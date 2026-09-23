"""EXPERIMENTAL macOS-only offline build. Must be validated on real Macs."""
import importlib.metadata as metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import sysconfig
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from build_portable import APP_FILES, PACKAGES, MODULES, copy_file, copy_tree, digest, checked
PYINSTALLER_VERSION = '6.16.0'


def command(arguments, *, cwd, env):
    result = subprocess.run([str(x) for x in arguments], cwd=cwd, env=env, capture_output=True,
                            text=True, encoding='utf-8', errors='replace', timeout=600)
    if result.returncode:
        raise RuntimeError('Local build/check failed:\n' + result.stdout[-12000:] + result.stderr[-12000:])
    return result.stdout


def main():
    if sys.platform != 'darwin':
        raise SystemExit('macOS build requires a real Mac; Windows cannot produce a verified .app. No downloads attempted.')
    if sys.version_info[:2] != (3, 12):
        raise SystemExit('Use a locally installed CPython 3.12 with Tk support.')
    architecture = platform.machine()
    if architecture not in ('arm64', 'x86_64'):
        raise SystemExit('Unsupported interpreter architecture: ' + architecture)
    site = Path(sysconfig.get_path('purelib')).resolve()
    installed = {dist.metadata['Name'].lower().replace('_', '-'): dist for dist in metadata.distributions(path=[str(site)])}
    required = dict(PACKAGES, pyinstaller=PYINSTALLER_VERSION)
    for name, version in required.items():
        if name not in installed or installed[name].version != version:
            raise SystemExit('Missing local dependency: ' + name + '==' + version + '; no downloads attempted.')
    for binary in ('/usr/bin/ditto', '/usr/bin/codesign'):
        if not Path(binary).is_file():
            raise SystemExit('Missing local macOS tool: ' + binary)
    (ROOT / 'build').mkdir(exist_ok=True)
    checked(ROOT / 'build')
    work = Path(tempfile.mkdtemp(prefix='macos-', dir=ROOT / 'build')).resolve()
    stage = work / 'source'
    for name in APP_FILES:
        copy_file(ROOT / name, stage / name)
    copy_file(ROOT / 'packaging/macos_runtime_hook.py', stage / 'macos_runtime_hook.py')
    copy_tree(Path(installed['pyjks'].locate_file('jks')), stage / 'vendor/jks', lambda p: p.suffix == '.py', {'__pycache__', 'tests'})
    jks_init = stage / 'vendor/jks/__init__.py'
    jks_init.write_text(jks_init.read_text(encoding='utf-8').replace('from .bks import *', '# BKS is intentionally not loaded'), encoding='utf-8')
    env = dict(os.environ)
    for name in ('PYTHONHOME', 'PYTHONPATH', 'PYTHONSTARTUP', 'TCL_LIBRARY', 'TK_LIBRARY',
                 'TCLLIBPATH', 'OPENSSL_CONF', 'OPENSSL_MODULES', 'OPENSSL_ENGINES'):
        env.pop(name, None)
    env['PYTHONNOUSERSITE'] = '1'
    env['PYINSTALLER_CONFIG_DIR'] = str(work / 'cache')
    probe = "import sys; sys.path.append(sys.argv[1]); import tkinter,cryptography,bcrypt,asn1crypto,cffi,pycparser; w=tkinter.Tk(); w.withdraw(); w.update(); w.destroy()"
    command([sys.executable, '-I', '-S', '-c', probe, site], cwd=work, env=env)
    driver = 'import sys; sys.path.insert(0,sys.argv.pop(1)); sys.path.append(sys.argv.pop(1)); from PyInstaller.__main__ import run; run()'
    arguments = [sys.executable, '-I', '-S', '-c', driver, stage / 'vendor', site, '--noconfirm', '--clean', '--windowed',
                 '--onedir', '--name', 'OfflineKeyVault', '--osx-bundle-identifier', 'local.offlinekeyvault',
                 '--target-architecture', architecture, '--distpath', work / 'dist',
                 '--workpath', work / 'analysis', '--specpath', work,
                 '--runtime-hook', stage / 'macos_runtime_hook.py', '--paths', stage, '--paths', stage / 'vendor',
                 '--hidden-import', '_cffi_backend']
    for package in PACKAGES:
        arguments.extend(['--collect-all', MODULES[package]])
    candidates = [Path('/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib'), Path('/usr/local/opt/openssl@3/lib/libcrypto.3.dylib'), Path(sys.base_prefix) / 'lib/libcrypto.3.dylib']
    crypto = next((p for p in candidates if p.is_file()), None)
    if crypto is None: raise SystemExit('A local OpenSSL 3 shared library is required; no downloads attempted.')
    arguments.extend(['--add-binary', str(crypto) + ':.'])
    arguments.append(stage / 'launch.py')
    print('Building from local dependencies for ' + architecture + '...', flush=True)
    command(arguments, cwd=stage, env=env)
    app = work / 'dist/OfflineKeyVault.app'
    if not app.is_dir():
        raise RuntimeError('PyInstaller did not create an app bundle')
    resources = app / 'Contents/Resources'
    resources.mkdir(exist_ok=True)
    for name in ('README.md', 'README.zh-CN.md', 'CONTRIBUTING.md', 'MACOS.md', 'COMPATIBILITY.md', 'SECURITY_RECOVERY.md', 'requirements.txt', 'LICENSE', 'SECURITY.md', 'THIRD_PARTY_NOTICES.md', 'RELEASING.md'):
        copy_file(ROOT / name, resources / name)
    for name, dist in installed.items():
        if name not in PACKAGES:
            continue
        for item in dist.files or ():
            if any('license' in part.lower() or part.lower().startswith('copying') for part in item.parts):
                if item.is_absolute() or '..' in item.parts:
                    raise RuntimeError('Unsafe dependency license path')
                source = Path(dist.locate_file(item))
                if source.is_file():
                    copy_file(source, resources / 'licenses' / name / Path(*item.parts))
    # Ad-hoc signing is entirely local; it is not Developer ID signing/notarization.
    command(['/usr/bin/codesign', '--force', '--deep', '--sign', '-', '--timestamp=none', app], cwd=work, env=env)
    command(['/usr/bin/codesign', '--verify', '--deep', '--strict', app], cwd=work, env=env)
    archive = work / ('offline-key-vault-macos-' + architecture + '-experimental.zip')
    command(['/usr/bin/ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', app, archive], cwd=work, env=env)
    relocated = work / '离线 解压验证'
    relocated.mkdir()
    command(['/usr/bin/ditto', '-x', '-k', archive, relocated], cwd=work, env=env)
    executable = relocated / 'OfflineKeyVault.app/Contents/MacOS/OfflineKeyVault'
    test_temp = work / 'diagnostic-temp'
    test_temp.mkdir()
    test_env = dict(env, PATH='/usr/bin:/bin', TMPDIR=str(test_temp), PYTHONHOME='/missing-python',
                    PYTHONPATH='/missing-modules', TCL_LIBRARY='/missing-tcl', TK_LIBRARY='/missing-tk',
                    TCLLIBPATH='/missing-tcl-packages', OPENSSL_CONF='/missing-openssl')
    output = command([executable, '--self-test'], cwd=work, env=test_env)
    reports = []
    for line in output.splitlines():
        try:
            report = json.loads(line)
        except ValueError:
            continue
        if isinstance(report, dict) and report.get('ok') is True and report.get('portable') is True:
            reports.append(report)
    if not reports:
        raise RuntimeError('Packaged self-test did not report success; artifact will not be published.')
    destination = ROOT / 'dist'
    destination.mkdir(exist_ok=True)
    checked(destination)
    target = destination / archive.name
    if target.is_symlink() or target.with_suffix('.zip.sha256').is_symlink():
        raise RuntimeError('Output cannot be a symbolic link')
    os.replace(archive, target)
    target.with_suffix('.zip.sha256').write_text(digest(target) + '  ' + target.name + '\n', encoding='ascii')
    (work / 'verification.json').write_text(json.dumps({'architecture': architecture, 'self_test': reports[-1],
        'status': 'experimental; macOS storage security qualification still required'}, indent=2), encoding='utf-8')
    print('Local build and relocated smoke test passed: ' + str(target))
    print('Experimental only: complete the macOS security checks in MACOS.md before using real keys.')


if __name__ == '__main__':
    main()
