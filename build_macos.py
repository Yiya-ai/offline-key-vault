"""Build and verify an offline standard macOS DMG on its native architecture."""
import argparse
import importlib.metadata as metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import sysconfig
import tempfile
import plistlib
import re

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from build_portable import APP_FILES, PACKAGES, MODULES, copy_file, copy_tree, digest, checked, copy_distribution_metadata
PYINSTALLER_VERSION = '6.16.0'


def command(arguments, *, cwd, env):
    result = subprocess.run([str(x) for x in arguments], cwd=cwd, env=env, capture_output=True,
                            text=True, encoding='utf-8', errors='replace', timeout=600)
    if result.returncode:
        raise RuntimeError('Local build/check failed:\n' + result.stdout[-12000:] + result.stderr[-12000:])
    return result.stdout


def audit_app(app, env):
    """Refuse private material, optional GPL modules and external native dependencies."""
    forbidden = {'.okv', '.okvr', '.key', '.pfx', '.p12', '.ppk', '.jks', '.log', '.sqlite'}
    private_key = re.compile(rb'-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----\s+[A-Za-z0-9+/=]{32,}')
    checked_files = 0
    for path in app.rglob('*'):
        if path.is_symlink():
            if not path.resolve().is_relative_to(app.resolve()):
                raise RuntimeError('Bundle contains an external symlink: ' + path.name)
            continue
        if not path.is_file(): continue
        relative = path.relative_to(app).as_posix()
        if ('pykcs11' in relative.lower() or '/SelfTest/' in relative
                or path.suffix.lower() in forbidden or path.name in ('direct_url.json', 'preferences.json')
                or path.name.startswith('.env')):
            raise RuntimeError('Disallowed bundle member: ' + relative)
        data = path.read_bytes()
        if private_key.search(data):
            raise RuntimeError('Private-key fixture found in bundle: ' + relative)
        if data[:4] in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe'):
            dependencies = command(['/usr/bin/otool', '-L', path], cwd=app.parent, env=env)
            for line in dependencies.splitlines()[1:]:
                dependency = line.strip().split(' (', 1)[0]
                if dependency.startswith('/') and not dependency.startswith(('/usr/lib/', '/System/Library/')):
                    raise RuntimeError('External native dependency in ' + relative)
        checked_files += 1
    return {'files_checked': checked_files, 'private_key_scan': True, 'native_dependencies_checked': True,
            'pykcs11_excluded': True}


def main():
    if sys.platform != 'darwin':
        raise SystemExit('macOS build requires a real Mac; Windows cannot produce a verified .app. No downloads attempted.')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-only', action='store_true')
    options = parser.parse_args()
    (ROOT / 'build').mkdir(exist_ok=True)
    support = ROOT / 'build/libokv_storage.dylib'
    subprocess.run(['/usr/bin/clang', '-dynamiclib', '-Wall', '-Wextra', '-Werror',
                    '-mmacosx-version-min=15.0', '-o', str(support), str(ROOT / 'packaging/macos_storage.c')], check=True)
    if options.prepare_only: return
    if sys.version_info[:2] != (3, 12):
        raise SystemExit('Use a locally installed CPython 3.12 with Tk support.')
    architecture = platform.machine()
    if architecture not in ('arm64', 'x86_64'):
        raise SystemExit('Unsupported interpreter architecture: ' + architecture)
    site = Path(sysconfig.get_path('purelib')).resolve()
    installed = {dist.metadata['Name'].lower().replace('_', '-'): dist for dist in metadata.distributions(path=[str(site)])}
    runtime_packages = {name: version for name, version in PACKAGES.items() if name != 'pykcs11'}
    required = dict(runtime_packages, pyinstaller=PYINSTALLER_VERSION)
    for name, version in required.items():
        if name not in installed or installed[name].version != version:
            raise SystemExit('Missing local dependency: ' + name + '==' + version + '; no downloads attempted.')
    for binary in ('/usr/bin/ditto', '/usr/bin/codesign', '/usr/bin/hdiutil'):
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
    probe = "import sys,json; sys.path.append(sys.argv[1]); import tkinter,cryptography,bcrypt,asn1crypto,cffi,pycparser; w=tkinter.Tk(); w.withdraw(); w.update(); print(json.dumps({'tcl':w.tk.eval('info library'),'tk':w.tk.eval('set tk_library'),'tcl_version':w.tk.eval('info patchlevel'),'tk_version':w.tk.eval('package require Tk')})); w.destroy()"
    tk_paths = json.loads(command([sys.executable, '-I', '-S', '-c', probe, site], cwd=work, env=env).strip())
    driver = 'import sys; sys.path.insert(0,sys.argv.pop(1)); sys.path.append(sys.argv.pop(1)); from PyInstaller.__main__ import run; run()'
    arguments = [sys.executable, '-I', '-S', '-c', driver, stage / 'vendor', site, '--noconfirm', '--clean', '--windowed',
                 '--onedir', '--name', 'OfflineKeyVault', '--osx-bundle-identifier', 'local.offlinekeyvault',
                 '--target-architecture', architecture, '--distpath', work / 'dist',
                 '--workpath', work / 'analysis', '--specpath', work,
                 '--runtime-hook', stage / 'macos_runtime_hook.py', '--paths', stage, '--paths', stage / 'vendor',
                 '--hidden-import', '_cffi_backend']
    arguments.extend(['--add-binary', str(support) + ':.', '--exclude-module', 'PyKCS11',
                      '--exclude-module', 'Cryptodome.SelfTest', '--exclude-module', 'pytest'])
    for package in runtime_packages:
        arguments.extend(['--collect-all', MODULES[package]])
    candidates = [Path('/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib'), Path('/usr/local/opt/openssl@3/lib/libcrypto.3.dylib'), Path(sys.base_prefix) / 'lib/libcrypto.3.dylib']
    crypto = next((p for p in candidates if p.is_file()), None)
    if crypto is None: raise SystemExit('A local OpenSSL 3 shared library is required; no downloads attempted.')
    crypto = crypto.resolve()  # Homebrew's opt entry is a version-selection symlink.
    arguments.extend(['--add-binary', str(crypto) + ':.'])
    legacy = crypto.parent / 'ossl-modules/legacy.dylib'
    if not legacy.is_file(): raise RuntimeError('Missing local OpenSSL legacy provider')
    arguments.extend(['--add-binary', str(legacy) + ':.'])
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
        if name not in runtime_packages and name != 'pyinstaller':
            continue
        copy_distribution_metadata(dist, resources / 'licenses' / name)
    python_license = next((p for p in (Path(sys.base_prefix) / 'LICENSE.txt',
                          Path(sys.base_prefix) / 'lib/python3.12/LICENSE.txt') if p.is_file()), None)
    if python_license is None: raise RuntimeError('Missing bundled Python license')
    copy_file(python_license, resources / 'licenses/Python-LICENSE.txt')
    for component in ('tcl', 'tk'):
        directory = tk_paths[component]
        script_dir = Path(directory).resolve()
        notice = next((p for folder in (script_dir, script_dir.parent, script_dir.parent.parent)
                       for name in ('license.terms', 'license', 'LICENSE', 'LICENSE.txt')
                       if (p := folder / name).is_file()), None)
        # The python.org 3.12.10 framework omits standalone Tcl/Tk notices.
        # These exact upstream 8.6.15 notices are retained in the source release.
        if notice is None and tk_paths[component + '_version'] == '8.6.15':
            notice = ROOT / 'packaging/licenses' / (component.capitalize() + '-LICENSE.txt')
        if notice is None: raise RuntimeError('Missing local ' + component + ' license for ' + tk_paths[component + '_version'])
        copy_file(notice, resources / 'licenses' / (component + '-LICENSE.txt'))
    # The native OpenSSL bridge is collected independently from cryptography.
    openssl_license = crypto.parent.parent / 'LICENSE.txt'
    if not openssl_license.is_file(): openssl_license = crypto.parent.parent / 'LICENSE'
    if not openssl_license.is_file(): raise RuntimeError('Missing bundled OpenSSL license')
    copy_file(openssl_license, resources / 'licenses/OpenSSL-LICENSE.txt')
    info_path = app / 'Contents/Info.plist'
    with info_path.open('rb') as stream: info = plistlib.load(stream)
    info.update(LSMinimumSystemVersion='15.0', CFBundleShortVersionString='0.2.1', CFBundleVersion='0.2.1')
    with info_path.open('wb') as stream: plistlib.dump(info, stream)
    audit = audit_app(app, env)
    # Ad-hoc signing is entirely local; it is not Developer ID signing/notarization.
    command(['/usr/bin/codesign', '--force', '--deep', '--sign', '-', '--timestamp=none', app], cwd=work, env=env)
    command(['/usr/bin/codesign', '--verify', '--deep', '--strict', app], cwd=work, env=env)
    archive = work / ('offline-key-vault-macos-' + architecture + '.zip')
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
    # Read-only DMG install flow: mount, copy the app to a clean directory, launch it.
    dmg_source = work / 'dmg-source'; dmg_source.mkdir()
    command(['/usr/bin/ditto', app, dmg_source / app.name], cwd=work, env=env)
    (dmg_source / 'Applications').symlink_to('/Applications', target_is_directory=True)
    (dmg_source / 'INSTALL.txt').write_text(
        'Drag OfflineKeyVault.app into Applications. macOS 15 or later.\n'
        'This build is ad-hoc signed, not Developer ID signed or notarized.\n'
        'Use macOS Privacy & Security to explicitly approve trusted software if requested; do not disable Gatekeeper.\n'
        'Standard build: no bundled PyKCS11; hardware token setup is optional and offline.\n', encoding='utf-8')
    dmg = work / ('offline-key-vault-macos-' + architecture + '.dmg')
    command(['/usr/bin/hdiutil', 'create', '-quiet', '-format', 'UDZO', '-volname', 'Offline Key Vault',
             '-srcfolder', dmg_source, dmg], cwd=work, env=env)
    mount = work / 'mounted'; mount.mkdir()
    command(['/usr/bin/hdiutil', 'attach', '-readonly', '-nobrowse', '-mountpoint', mount, dmg], cwd=work, env=env)
    try:
        installed_app = work / 'installed/OfflineKeyVault.app'
        command(['/usr/bin/ditto', mount / app.name, installed_app], cwd=work, env=env)
        command(['/usr/bin/codesign', '--verify', '--deep', '--strict', installed_app], cwd=work, env=env)
        output = command([installed_app / 'Contents/MacOS/OfflineKeyVault', '--self-test'], cwd=work, env=test_env)
        if not any(json.loads(line).get('ok') is True for line in output.splitlines() if line.startswith('{')):
            raise RuntimeError('DMG installed application self-test failed')
        command(['/usr/bin/open', '-W', '-n', installed_app, '--args', '--self-test'], cwd=work, env=test_env)
    finally:
        command(['/usr/bin/hdiutil', 'detach', mount], cwd=work, env=env)
    destination = ROOT / 'dist'
    destination.mkdir(exist_ok=True)
    checked(destination)
    target = destination / dmg.name
    if target.is_symlink() or target.with_suffix('.dmg.sha256').is_symlink():
        raise RuntimeError('Output cannot be a symbolic link')
    os.replace(dmg, target)
    target.with_suffix('.dmg.sha256').write_text(digest(target) + '  ' + target.name + '\n', encoding='ascii')
    report = {'architecture': architecture, 'self_test': reports[-1], 'dmg_install_tested': True,
              'codesign_verified': True, 'notarized': False, 'minimum_macos': '15.0',
              'profile': 'standard', 'sha256': digest(target), 'audit': audit, 'files': []}
    for path in sorted(app.rglob('*')):
        if path.is_file() and not path.is_symlink():
            report['files'].append({'path': path.relative_to(app).as_posix(), 'sha256': digest(path)})
    (destination / ('macos-verification-' + architecture + '.json')).write_text(json.dumps(report, indent=2), encoding='utf-8')
    print('Local build and relocated smoke test passed: ' + str(target))
    print('Ad-hoc signed only; no Developer ID signing or notarization.')


if __name__ == '__main__':
    main()
