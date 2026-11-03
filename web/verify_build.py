"""Verify the exact static deploy tree; do not publish runtime or test folders."""
import hashlib
import json
import re
import zipfile
from pathlib import Path

WEB = Path(__file__).resolve().parent


def verify(root=None):
    root = Path(root) if root is not None else WEB / 'dist'
    if root.is_symlink() or root.is_junction():
        raise ValueError('Linked deployment root')
    manifest = json.loads((root / 'assets.json').read_text(encoding='utf-8'))['files']
    top = {'.nojekyll', 'index.html', 'style.css', 'app.js', 'icon.svg', 'assets.json', 'assets', 'licenses', 'deployment-manifest.json'}
    if {p.name for p in root.iterdir()} != top:
        raise ValueError('Unexpected deployment content')
    if {p.name for p in (root / 'assets').iterdir()} != set(manifest):
        raise ValueError('Asset manifest differs from deployment')
    for path in root.rglob('*'):
        if path.is_symlink() or path.is_junction() or (path.is_file() and path.stat().st_nlink != 1):
            raise ValueError('Linked deployment content')
    deployed = json.loads((root / 'deployment-manifest.json').read_text(encoding='utf-8'))['files']
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    if actual != set(deployed) | {'deployment-manifest.json'}:
        raise ValueError('Unexpected nested deployment content')
    license_names = {
        '@noble-curves-LICENSE', '@noble-hashes-LICENSE', 'node-forge-LICENSE',
        'argon2-cffi-bindings-LICENSE', 'argon2-cffi-LICENSE', 'asn1crypto-LICENSE',
        'bcrypt-LICENSE', 'cffi-LICENSE', 'cryptography-LICENSE', 'cryptography-LICENSE.APACHE',
        'cryptography-LICENSE.BSD', 'javaobj-py3-LICENSE', 'PGPy-LICENSE', 'pyasn1-LICENSE.rst',
        'pyasn1-modules-LICENSE.txt', 'pycparser-LICENSE', 'pycryptodome-LICENSE.rst',
        'pyjks-LICENSE.txt', 'six-LICENSE', 'standard-imghdr-LICENSE',
        'Pyodide-LICENSE.txt', 'CPython-LICENSE.txt', 'PROJECT-LICENSE.txt', 'THIRD_PARTY.md', 'OpenSSL-LICENSE.txt',
    }
    if {p.name for p in (root / 'licenses').iterdir()} != license_names:
        raise ValueError('Unexpected license content')
    if {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_dir()} != {'assets', 'licenses'}:
        raise ValueError('Unexpected deployment directory')
    locked = json.loads((WEB / 'dependencies.lock.json').read_text(encoding='utf-8'))
    expected_assets = {'worker.js', 'kernel.py', 'python-code.zip', 'pyodide-lock.json', 'pyodide.asm.wasm', 'python_stdlib.zip'}
    expected_assets.update(item['file'] for item in locked['files'] if item['name'] in locked['wasm_packages'])
    if set(manifest) != expected_assets:
        raise ValueError('Unexpected runtime assets')
    runtime_lock = json.loads((root / 'assets/pyodide-lock.json').read_text(encoding='utf-8'))['packages']
    for item in locked['files']:
        if item['name'] not in locked['wasm_packages']:
            continue
        package = runtime_lock[item['name']]
        if (manifest[item['file']]['sha256'] != item['sha256'] or package['sha256'] != item['sha256']
                or package['file_name'] != item['file']):
            raise ValueError('Runtime differs from reviewed dependency lock')
        if item.get('build') and (package['version'] != item['version']
                or package['tool'].get('openssl_version') != item['openssl']):
            raise ValueError('Unexpected cryptographic runtime policy')
    for name, metadata in deployed.items():
        data = (root / name).read_bytes()
        if len(data) != metadata['bytes'] or hashlib.sha256(data).hexdigest() != metadata['sha256']:
            raise ValueError('Deployment digest mismatch')
    for name in ('index.html', 'style.css', 'app.js', 'icon.svg'):
        if (root / name).read_bytes() != (WEB / 'src' / name).read_bytes():
            raise ValueError('Deployment differs from reviewed source')
    if (root / 'assets/kernel.py').read_bytes() != (WEB / 'src/kernel.py').read_bytes():
        raise ValueError('Kernel differs from reviewed source')
    for name, metadata in manifest.items():
        if not re.fullmatch(r'[a-zA-Z0-9_.-]+', name):
            raise ValueError('Unsafe asset name')
        data = (root / 'assets' / name).read_bytes()
        if len(data) != metadata['bytes'] or hashlib.sha256(data).hexdigest() != metadata['sha256']:
            raise ValueError('Asset digest mismatch')
    with zipfile.ZipFile(root / 'assets/python-code.zip') as archive:
        names = archive.namelist()
        if archive.testzip() or any('/../' in '/' + n or n.startswith('/') for n in names):
            raise ValueError('Invalid Python asset archive')
        if any(n in names for n in ('keyvault/vault.py', 'keyvault/preferences.py', 'keyvault/token.py')):
            raise ValueError('Desktop persistence or native token code in website')
        if any(n.endswith(('.okv', '.pem', '.key', '.p12', '.jks')) for n in names):
            raise ValueError('Unexpected key material in website')
    app = (root / 'app.js').read_text(encoding='utf-8')
    if '__command' in app or '__worker' in app:
        raise ValueError('Browser test hooks must not ship')
    for name in ('Pyodide-LICENSE.txt', 'CPython-LICENSE.txt', 'PROJECT-LICENSE.txt', 'THIRD_PARTY.md'):
        if not (root / 'licenses' / name).is_file():
            raise ValueError('Missing distribution license')
    return {'ok': True, 'assets': len(manifest), 'bytes': sum(v['bytes'] for v in manifest.values())}


if __name__ == '__main__':
    print(json.dumps(verify()))
