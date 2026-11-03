"""Build a static, self-contained website. Never read vaults or runtime settings."""
import argparse
import concurrent.futures
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile

WEB = Path(__file__).resolve().parent
ROOT = WEB.parent
CORE = ('keys', 'jwk', 'material', 'compat_import', 'import_guard', 'pbes2',
        'ppk', 'openpgp', 'paircheck', 'conversion')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def browser_imports(data):
    # Pyodide ships PyCryptodome as Crypto, not pycryptodomex's Cryptodome.
    # A sys.modules alias loads extension bindings twice under different names.
    return data.replace(b'from Cryptodome.', b'from Crypto.').replace(b'import Cryptodome.', b'import Crypto.')


def fetch(item, allowed):
    target = WEB / '.vendor' / item['file']
    if target.name != item['file']:
        raise ValueError('Dependency filename must be a basename')
    if not target.exists():
        if item.get('build'):
            raise RuntimeError('Missing verified WASM wheel; run python web/build_wasm.py first')
        if not allowed:
            raise RuntimeError('Missing public dependency; use --fetch once: ' + item['name'])
        if not item['url'].startswith(('https://files.pythonhosted.org/', 'https://cdn.jsdelivr.net/pyodide/')):
            raise ValueError('Unexpected dependency host')
        with urllib.request.urlopen(item['url'], timeout=90) as response:
            data = response.read(32 * 1024 * 1024 + 1)
        if len(data) > 32 * 1024 * 1024 or digest(data) != item['sha256']:
            raise ValueError('Dependency digest mismatch')
        target.write_bytes(data)
    if digest(target.read_bytes()) != item['sha256']:
        raise ValueError('Cached dependency digest mismatch: ' + item['name'])
    return target


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fetch', action='store_true', help='Download pinned public build dependencies')
    args = parser.parse_args()
    locked = json.loads((WEB / 'dependencies.lock.json').read_text(encoding='utf-8'))
    runtime = WEB / 'node_modules/pyodide'
    if json.loads((runtime / 'package.json').read_text())['version'] != locked['pyodide']:
        raise ValueError('Run npm ci with the pinned lockfile first')
    (WEB / '.vendor').mkdir(exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        paths = list(pool.map(lambda item: fetch(item, args.fetch), locked['files']))
    out = WEB / 'dist'
    if out.exists():
        # Only remove this fixed generated directory; reject linked destinations.
        if out.is_symlink() or out.is_junction() or out.resolve() != WEB.resolve() / 'dist':
            raise ValueError('Unsafe build destination')
        shutil.rmtree(out)
    out.mkdir()
    assets = out / 'assets'
    assets.mkdir()
    for name in ('index.html', 'style.css', 'app.js', 'icon.svg'):
        shutil.copyfile(WEB / 'src' / name, out / name)
    npm = shutil.which('node')
    subprocess.run([npm, str(WEB / 'bundle.mjs')], cwd=WEB, check=True)
    py_lock = json.loads((runtime / 'pyodide-lock.json').read_text())
    py_lock['packages'] = {name: py_lock['packages'][name] for name in locked['wasm_packages']}
    for item in locked['files']:
        if item.get('build'):
            package = py_lock['packages'][item['name']]
            package.update(file_name=item['file'], version=item['version'], sha256=item['sha256'])
            package['tool'] = {'openssl_version': item['openssl']}
    (assets / 'pyodide-lock.json').write_text(json.dumps(py_lock), encoding='utf-8')
    for name in ('pyodide.asm.wasm', 'python_stdlib.zip'):
        shutil.copyfile(runtime / name, assets / name)
    licenses = out / 'licenses'
    licenses.mkdir()
    pure = io.BytesIO()
    with zipfile.ZipFile(pure, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('keyvault/__init__.py', '')
        for name in CORE:
            archive.writestr('keyvault/' + name + '.py', browser_imports((ROOT / 'keyvault' / (name + '.py')).read_bytes()))
        archive.writestr('keyvault/native_crypto.py', (WEB / 'src/native_crypto.py').read_bytes())
        archive.writestr('argon_adapter.py', (WEB / 'src/argon_adapter.py').read_bytes())
        for item, path in zip(locked['files'], paths):
            if item['name'] in locked['wasm_packages']:
                shutil.copyfile(path, assets / path.name)
            if path.name.endswith('.whl'):
                with zipfile.ZipFile(path) as wheel:
                    for name in wheel.namelist():
                        if item['name'] not in locked['wasm_packages'] and not name.endswith('/'):
                            if name.startswith('/') or '..' in Path(name).parts:
                                raise ValueError('Unsafe wheel member')
                            data = wheel.read(name)
                            if name.startswith('jks/') and name.endswith('.py'):
                                data = browser_imports(data)
                            archive.writestr(name, data)
                        if not name.endswith('/') and any(x in Path(name).name.lower() for x in ('license', 'copying', 'notice')):
                            (licenses / (item['name'] + '-' + Path(name).name)).write_bytes(wheel.read(name))
            else:
                with tarfile.open(path) as tar:
                    for entry in tar.getmembers():
                        if not entry.isfile():
                            continue
                        name = entry.name.split('/', 1)[-1]
                        if '..' in Path(name).parts:
                            raise ValueError('Unsafe source archive member')
                        if name.startswith('pgpy/') and name.endswith('.py'):
                            archive.writestr(name, tar.extractfile(entry).read())
                        if 'license' in Path(name).name.lower():
                            (licenses / ('PGPy-' + Path(name).name)).write_bytes(tar.extractfile(entry).read())
    (assets / 'python-code.zip').write_bytes(pure.getvalue())
    shutil.copyfile(WEB / 'src/kernel.py', assets / 'kernel.py')
    for package in ('@noble/curves', '@noble/hashes', 'node-forge'):
        source = WEB / 'node_modules' / package
        for path in source.glob('*LICENSE*'):
            shutil.copyfile(path, licenses / (package.replace('/', '-') + '-' + path.name))
    shutil.copyfile(ROOT / 'LICENSE', licenses / 'PROJECT-LICENSE.txt')
    for name in ('Pyodide-LICENSE.txt', 'CPython-LICENSE.txt', 'OpenSSL-LICENSE.txt'):
        shutil.copyfile(WEB / 'licenses' / name, licenses / name)
    shutil.copyfile(WEB / 'THIRD_PARTY.md', licenses / 'THIRD_PARTY.md')
    files = {p.relative_to(assets).as_posix(): {'sha256': digest(p.read_bytes()), 'bytes': p.stat().st_size}
             for p in sorted(assets.iterdir()) if p.is_file()}
    (out / 'assets.json').write_text(json.dumps({'files': files}, indent=2), encoding='utf-8')
    (out / '.nojekyll').write_text('')
    # Bind the whole output, not just runtime assets: extra nested files must fail
    # the deployment gate, including accidental key files in the license folder.
    deployed = {p.relative_to(out).as_posix(): {'sha256': digest(p.read_bytes()), 'bytes': p.stat().st_size}
                for p in sorted(out.rglob('*')) if p.is_file()}
    (out / 'deployment-manifest.json').write_text(json.dumps({'files': deployed}, indent=2), encoding='utf-8')
    print(json.dumps({'ok': True, 'files': len(files), 'asset_bytes': sum(v['bytes'] for v in files.values())}))


if __name__ == '__main__':
    main()
