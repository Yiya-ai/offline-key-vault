"""Build a Windows x64 portable package using installed files only. Never downloads."""
import hashlib
import argparse
import email
import importlib.metadata as metadata
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
PACKAGES = {'cryptography': '46.0.7', 'asn1crypto': '1.5.1', 'bcrypt': '5.0.0',
            'cffi': '2.0.0', 'pycparser': '3.0', 'pycryptodomex': '3.23.0', 'pyasn1': '0.6.3', 'pgpy': '0.6.0', 'pyjks': '20.0.0', 'argon2-cffi': '25.1.0', 'argon2-cffi-bindings': '26.1.0', 'pykcs11': '1.5.18', 'javaobj-py3': '0.6.1', 'pyasn1-modules': '0.4.2'}
MODULES = {name: name for name in PACKAGES}
MODULES.update({'pycryptodomex': 'Cryptodome', 'pyjks': 'jks', 'argon2-cffi': 'argon2', 'argon2-cffi-bindings': '_argon2_cffi_bindings', 'pykcs11': 'PyKCS11', 'javaobj-py3': 'javaobj', 'pyasn1-modules': 'pyasn1_modules'})
APP_FILES = ('launch.py', 'keyvault/__init__.py', 'keyvault/app.py', 'keyvault/offline.py',
             'keyvault/macos_storage.py', 'keyvault/branding.py',
             'keyvault/safeio.py', 'keyvault/vault.py', 'keyvault/keys.py', 'keyvault/jwk.py',
             'keyvault/pbes2.py', 'keyvault/import_guard.py', 'keyvault/localdialog.py',
             'keyvault/diagnostics.py', 'keyvault/compat_import.py', 'keyvault/material.py', 'keyvault/native_crypto.py', 'keyvault/openpgp.py', 'keyvault/ppk.py', 'keyvault/token.py', 'keyvault/token_ui.py', 'keyvault/protection.py', 'keyvault/security_ui.py', 'keyvault/preferences.py', 'keyvault/paircheck.py', 'keyvault/tool_ui.py', 'keyvault/widgets.py', 'keyvault/window_resize.py', 'keyvault/conversion.py', 'keyvault/content_ui.py')
SKIP = {'__pycache__', 'site-packages', 'test', 'tests', 'idlelib', 'ensurepip', 'venv', 'turtledemo'}


def checked(path):
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise RuntimeError('Build input/output cannot be a reparse point: ' + str(path))
    return path


def copy_file(source, dest):
    checked(source)
    if not source.is_file():
        raise RuntimeError('Missing build input: ' + str(source))
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, dest)


def copy_tree(source, dest, predicate=lambda p: True, skip=frozenset()):
    checked(source)
    for directory, directories, files in os.walk(source, followlinks=False):
        directory = Path(directory)
        checked(directory)
        directories[:] = [name for name in directories if name not in skip]
        for name in files:
            source_file = directory / name
            if predicate(source_file):
                copy_file(source_file, dest / source_file.relative_to(source))


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def publish_archive(source, target):
    """Atomically publish verified output; tolerate temporary Windows file locks."""
    source, target = Path(source), Path(target)
    for attempt in range(6):
        checked(source); checked(target.parent)
        if target.exists() or target.is_symlink(): checked(target)
        try:
            os.replace(source, target)
            return
        except OSError as error:
            if getattr(error, 'winerror', None) not in (5, 32, 33) or attempt == 5 or not source.exists():
                raise
            time.sleep(0.1 * (2 ** attempt))


def verify_executable_icon(path):
    """Ask Windows to extract the embedded icon, without Explorer's fallback."""
    import ctypes
    from ctypes import wintypes
    extract = ctypes.WinDLL('shell32', use_last_error=True).ExtractIconExW
    extract.argtypes = (wintypes.LPCWSTR, ctypes.c_int, ctypes.POINTER(wintypes.HANDLE),
                        ctypes.POINTER(wintypes.HANDLE), wintypes.UINT)
    extract.restype = wintypes.UINT
    destroy = ctypes.WinDLL('user32', use_last_error=True).DestroyIcon
    destroy.argtypes = (wintypes.HANDLE,)
    large, small = wintypes.HANDLE(), wintypes.HANDLE()
    try:
        if extract(str(path), 0, ctypes.byref(large), ctypes.byref(small), 1) in (0, 0xffffffff) or not large or not small:
            raise RuntimeError('Executable is missing its application icon')
    finally:
        if large: destroy(large)
        if small: destroy(small)


def copy_distribution_metadata(dist, destination):
    """Retain notices even when an offline vendor installation has no RECORD."""
    normalize = lambda value: value.lower().replace('_', '-')
    expected = normalize(dist.metadata['Name'])
    matches = []
    for candidate in Path(dist.locate_file('')).glob('*.dist-info'):
        metadata_file = checked(candidate / 'METADATA')
        info = email.message_from_bytes(metadata_file.read_bytes())
        if normalize(info.get('Name', '')) == expected and info.get('Version') == dist.version:
            matches.append(candidate)
    if len(matches) != 1:
        raise RuntimeError('Expected unique dependency metadata for ' + expected)
    source = matches[0]
    notices = []
    def include(path):
        parts = path.relative_to(source).parts
        is_notice = any('license' in part.lower() or 'copying' in part.lower() or 'notice' in part.lower() for part in parts)
        if is_notice: notices.append(path)
        return is_notice or path.name in ('METADATA', 'WHEEL')
    copy_tree(source, destination / source.name, include)
    if not notices:
        raise RuntimeError('Missing dependency license files: ' + expected)


def clean_environment(temp):
    env = dict(os.environ)
    # Deliberately hostile values demonstrate that the launcher isolates them.
    env.update(PYTHONHOME='Z:\\missing-python', PYTHONPATH='Z:\\missing-modules',
               TCL_LIBRARY='Z:\\missing-tcl', TK_LIBRARY='Z:\\missing-tk',
               TCLLIBPATH='Z:\\missing-tcl-packages', OPENSSL_CONF='Z:\\missing-openssl',
               PATH=str(Path(os.environ['SystemRoot']) / 'System32'),
               TEMP=str(temp), TMP=str(temp))
    return env


def run_checked(arguments, **kwargs):
    for attempt in range(6):
        try:
            result = subprocess.run([str(x) for x in arguments], capture_output=True, text=True,
                                    encoding='utf-8', errors='replace', timeout=180, **kwargs)
            break
        except OSError as error:
            # A sharing violation means CreateProcess did not start the child.
            # Retry only transient file locks; permissions/integrity errors remain fatal.
            if getattr(error, 'winerror', None) not in (32, 33) or attempt == 5:
                raise
            time.sleep(0.05 * (2 ** attempt))
    if result.returncode:
        raise RuntimeError('Local build check failed (exit ' + str(result.returncode) + '):\n' + result.stdout + result.stderr)
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--with-pkcs11', action='store_true', help='Local-only bundle with optional GPL PyKCS11 dependency; not the public standard installer')
    options = parser.parse_args()
    runtime_packages = {name: version for name, version in PACKAGES.items() if name != 'pykcs11' or options.with_pkcs11}
    if os.name != 'nt' or sys.version_info[:2] != (3, 12) or platform.machine().lower() not in ('amd64', 'x86_64') or sys.maxsize < 2**32:
        raise SystemExit('Build requires locally installed Windows x64 CPython 3.12 with Tk.')
    checked(ROOT)
    base = checked(Path(sys.base_prefix))
    site = Path(sysconfig.get_path('purelib'))
    installed = {dist.metadata['Name'].lower().replace('_', '-'): dist for dist in metadata.distributions(path=[str(site), str(ROOT / 'vendor')])}
    for name, version in runtime_packages.items():
        if name not in installed or installed[name].version != version:
            raise SystemExit('Missing local dependency: ' + name + '==' + version + '; no downloads attempted.')
    compiler = Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    checked(compiler)
    for directory in (ROOT / 'build', ROOT / 'dist'):
        directory.mkdir(exist_ok=True)
        checked(directory)
    work = Path(tempfile.mkdtemp(prefix='portable-', dir=ROOT / 'build'))
    bundle = work / 'OfflineKeyVault'
    runtime = bundle / 'runtime'
    for source in APP_FILES:
        copy_file(ROOT / source, bundle / 'app' / source)
    for name in ('README.md', 'README.zh-CN.md', 'CONTRIBUTING.md', 'MACOS.md', 'COMPATIBILITY.md', 'SECURITY_RECOVERY.md', 'requirements.txt', 'LICENSE', 'SECURITY.md', 'THIRD_PARTY_NOTICES.md', 'RELEASING.md'):
        copy_file(ROOT / name, bundle / name)
    for name in ('python.exe', 'pythonw.exe', 'python3.dll', 'python312.dll', 'vcruntime140.dll', 'vcruntime140_1.dll'):
        copy_file(base / name, runtime / name)
    copy_file(base / 'LICENSE.txt', bundle / 'licenses/Python-LICENSE.txt')
    copy_file(ROOT / 'packaging/licenses/Tcl-LICENSE.txt', bundle / 'licenses/Tcl-LICENSE.txt')
    copy_tree(base / 'Lib', runtime / 'Lib', lambda p: p.suffix == '.py', SKIP)
    copy_tree(base / 'DLLs', runtime / 'DLLs',
              lambda p: p.suffix in ('.dll', '.pyd') and not p.name.startswith(('_test', '_ctypes_test')))
    for name in ('tcl8', 'tcl8.6', 'tk8.6'):
        copy_tree(base / 'tcl' / name, runtime / 'tcl' / name)
    for name in runtime_packages:
        dist = installed[name]
        package_site = Path(dist.locate_file(''))
        module = MODULES[name]
        copy_tree(package_site / module, runtime / 'Lib/site-packages' / module,
                  lambda p: p.suffix in ('.py', '.pyd', '.dll') or p.name == 'py.typed', {'__pycache__', 'tests', 'SelfTest'})
        copy_distribution_metadata(dist, runtime / 'Lib/site-packages')
    jks_init = runtime / 'Lib/site-packages/jks/__init__.py'
    jks_init.write_text(jks_init.read_text(encoding='utf-8').replace('from .bks import *', '# BKS is intentionally not loaded'), encoding='utf-8')
    native = list(Path(installed['cffi'].locate_file('')).glob('_cffi_backend*.pyd'))
    if len(native) != 1:
        raise RuntimeError('Expected exactly one local cffi native backend')
    copy_file(native[0], runtime / 'Lib/site-packages' / native[0].name)
    (runtime / 'python312._pth').write_text('.\nLib\nDLLs\nLib\\site-packages\n', encoding='ascii')
    launcher = bundle / 'OfflineKeyVault.exe'
    for name, arguments in (('launch.cmd', ''), ('self-test.cmd', '--self-test'), ('verify.cmd', '--verify')):
        body = '@echo off\r\nsetlocal\r\ncd /d "%~dp0"\r\nstart "" /wait "%~dp0OfflineKeyVault.exe" ' + arguments + '\r\n'
        body += 'set "result=%errorlevel%"\r\n'
        if arguments:
            body += 'if "%result%"=="0" (echo Offline check passed.) else (echo Offline check FAILED.)\r\npause\r\n'
        body += 'exit /b %result%\r\n'
        (bundle / name).write_bytes(body.encode('ascii'))
    (bundle / 'START-HERE.txt').write_text(
        '离线密钥柜 / Windows 10、11 x64 便携版\n\n'
        '1. 将 ZIP 完整解压到可信的本地目录（请勿在 ZIP 内启动）。\n'
        '2. 双击 OfflineKeyVault.exe 或 launch.cmd，即可使用。无需安装 Python、pip 或依赖，无需管理员权限。\n'
        '3. 自行选择非云同步目录保存加密密钥库；程序不会自动写入用户密钥到安装目录。\n'
        '4. self-test.cmd 执行离线功能自检，只使用临时合成密钥；verify.cmd 检查包内文件摘要。\n'
        '5. 升级时解压到新目录，再打开已有 .okv；删除程序目录前确认其中没有自行存放的密钥库或导出文件。\n\n'
        '内置 CPython、Tk 和密码库；没有在线安装、更新、上传或遥测。\n'
        '启动器需要 Windows 自带的 .NET Framework 4.x。没有数字签名；摘要检测损坏，不证明发布者身份。\n'
        'Windows x64 本机验证完成；未在干净的 Windows 10/11 虚拟机上逐一测试。\n'
        '第三方许可证随包保存于 licenses、runtime/tcl 和各依赖 dist-info 目录。\n'
        '严格物理离线需求请在断网设备运行；详情及格式限制见 README.md。\n', encoding='utf-8-sig')
    build_info = {'platform': 'windows-x64', 'python': platform.python_version(), 'packages': runtime_packages,
                  'launcher_source_sha256': digest(ROOT / 'packaging/Launcher.cs'),
                  'uninstaller_sources': {name: digest(ROOT / name) for name in ('packaging/Installer.cs', 'packaging/Upgrade.cs', 'packaging/Uninstall.cs')},
                  'profile': 'local-pkcs11' if options.with_pkcs11 else 'standard',
                  'build': 'local-files-only', 'source_files': list(APP_FILES)}
    (bundle / 'build-info.json').write_text(json.dumps(build_info, indent=2) + '\n', encoding='utf-8')
    files = sorted(p for p in bundle.rglob('*') if p.is_file())
    manifest = bundle / 'manifest.sha256'
    manifest.write_text(''.join(digest(p) + '  ' + p.relative_to(bundle).as_posix() + '\n' for p in files), encoding='utf-8', newline='\n')
    from keyvault.branding import write_ico
    icon = work / 'OfflineKeyVault.ico'
    write_ico(icon)
    uninstaller_source = work / 'Uninstall.cs'
    uninstall_template = (ROOT / 'packaging/Uninstall.cs').read_text(encoding='utf-8')
    if uninstall_template.count('__PROGRAM_MANIFEST_SHA256__') != 1:
        raise RuntimeError('Uninstaller manifest binding template is invalid')
    uninstaller_source.write_text(uninstall_template.replace('__PROGRAM_MANIFEST_SHA256__', digest(manifest)), encoding='utf-8')
    uninstaller = bundle / 'Uninstall.exe'
    run_checked([compiler, '/nologo', '/target:winexe', '/main:UninstallEntry', '/platform:x64', '/optimize+',
                 '/win32icon:' + str(icon), '/r:System.Windows.Forms.dll', '/r:System.Drawing.dll', '/r:System.IO.Compression.dll',
                 '/out:' + str(uninstaller), ROOT / 'packaging/Installer.cs', ROOT / 'packaging/Upgrade.cs', uninstaller_source])
    verify_executable_icon(uninstaller)
    files.append(uninstaller)
    manifest.write_text(manifest.read_text(encoding='utf-8') + digest(uninstaller) + '  Uninstall.exe\n', encoding='utf-8', newline='\n')
    launcher_source = work / 'Launcher.cs'
    template = (ROOT / 'packaging/Launcher.cs').read_text(encoding='utf-8')
    if template.count('__MANIFEST_SHA256__') != 1:
        raise RuntimeError('Launcher manifest binding template is invalid')
    launcher_source.write_text(template.replace('__MANIFEST_SHA256__', digest(manifest)), encoding='utf-8')
    run_checked([compiler, '/nologo', '/target:winexe', '/platform:x64', '/optimize+', '/win32icon:' + str(icon),
                 '/r:System.Windows.Forms.dll', '/out:' + str(launcher), launcher_source])
    verify_executable_icon(launcher)
    temporary_zip = work / ('offline-key-vault-windows-x64-local-pkcs11.zip' if options.with_pkcs11 else 'offline-key-vault-windows-x64.zip')
    with zipfile.ZipFile(temporary_zip, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(p for p in bundle.rglob('*') if p.is_file()):
            archive.write(path, 'OfflineKeyVault/' + path.relative_to(bundle).as_posix())
    # Test the actual archive after extraction, not the assembly directory.
    relocated = work / '离线 解压验证'
    relocated.mkdir()
    with zipfile.ZipFile(temporary_zip) as archive:
        for member in archive.infolist():
            target = (relocated / member.filename).resolve()
            if not target.is_relative_to(relocated.resolve()):
                raise RuntimeError('Unsafe archive path')
        archive.extractall(relocated)
    extracted = relocated / 'OfflineKeyVault'
    temporary = work / 'diagnostic-temp'
    temporary.mkdir()
    env = clean_environment(temporary)
    print('Verifying relocated package...', flush=True)
    print(run_checked([extracted / 'OfflineKeyVault.exe', '--verify'], cwd=work, env=env), flush=True)
    print(run_checked([extracted / 'OfflineKeyVault.exe', '--self-test'], cwd=work, env=env), flush=True)
    # Integrity gate must reject both changed and missing files before Python runs.
    sample = extracted / 'app/keyvault/keys.py'
    original = sample.read_bytes()
    sample.write_bytes(original + b'\n# corruption test\n')
    failed = subprocess.run([str(extracted / 'OfflineKeyVault.exe'), '--verify'], cwd=work, env=env, capture_output=True, timeout=30)
    if failed.returncode == 0:
        raise RuntimeError('Integrity gate accepted corrupted package')
    sample.unlink()
    failed = subprocess.run([str(extracted / 'OfflineKeyVault.exe'), '--verify'], cwd=work, env=env, capture_output=True, timeout=30)
    if failed.returncode == 0:
        raise RuntimeError('Integrity gate accepted incomplete package')
    sample.write_bytes(original)
    manifest_path = extracted / 'manifest.sha256'
    original_manifest = manifest_path.read_bytes()
    sample.write_bytes(original + b'\n# synthetic manifest rewrite test\n')
    manifest_path.write_bytes(original_manifest.replace(hashlib.sha256(original).hexdigest().encode(), digest(sample).encode()))
    failed = subprocess.run([str(extracted / 'OfflineKeyVault.exe'), '--verify'], cwd=work, env=env, capture_output=True, timeout=30)
    if failed.returncode == 0:
        raise RuntimeError('Integrity gate accepted rewritten manifest')
    sample.write_bytes(original)
    manifest_path.write_bytes(original_manifest)
    extra = extracted / 'app/unlisted.py'
    extra.write_bytes(b'# synthetic unexpected module\n')
    failed = subprocess.run([str(extracted / 'OfflineKeyVault.exe'), '--verify'], cwd=work, env=env, capture_output=True, timeout=30)
    if failed.returncode == 0:
        raise RuntimeError('Integrity gate accepted unlisted module')
    extra.unlink()
    # User vaults outside program trees remain usable; executable injections do not.
    user_data = extracted / 'vaults'
    user_data.mkdir()
    (user_data / 'synthetic.okv').write_bytes(b'synthetic vault placeholder')
    (extracted / '.offline-key-vault-preferences.json').write_bytes(b'{}')
    run_checked([extracted / 'OfflineKeyVault.exe', '--verify'], cwd=work, env=env)
    for extra in (extracted / 'injected.dll', extracted / 'runtime/extra.json'):
        extra.write_bytes(b'synthetic unexpected content')
        failed = subprocess.run([str(extracted / 'OfflineKeyVault.exe'), '--verify'], cwd=work, env=env, capture_output=True, timeout=30)
        if failed.returncode == 0:
            raise RuntimeError('Integrity gate accepted unexpected executable/runtime content')
        extra.unlink()
    marker = extracted / '.offline-key-vault-upgrade'
    marker.write_bytes(b'synthetic upgrade in progress')
    failed = subprocess.run([str(extracted / 'OfflineKeyVault.exe'), '--self-test'], cwd=work, env=env, capture_output=True, timeout=30)
    if failed.returncode == 0:
        raise RuntimeError('Application launched during an incomplete upgrade')
    marker.unlink()
    run_checked([extracted / 'OfflineKeyVault.exe', '--verify'], cwd=work, env=env)
    # Only publish an archive after all checks pass. No generated vaults enter it.
    output = ROOT / 'dist' / temporary_zip.name
    if output.exists():
        checked(output)
    publish_archive(temporary_zip, output)
    checksum = output.with_suffix(output.suffix + '.sha256')
    if checksum.exists():
        checked(checksum)
    checksum.write_text(digest(output) + '  ' + output.name + '\n', encoding='ascii')
    report = {'ok': True, 'relocated_path_tested': True, 'host_python_removed_from_path': True,
              'external_environment_ignored': True, 'tamper_rejected': True, 'missing_file_rejected': True,
              'manifest_rewrite_rejected': True, 'unlisted_module_rejected': True,
              'user_data_allowed': True, 'runtime_injection_rejected': True, 'incomplete_upgrade_blocked': True,
              'archive_files': len(files) + 2, 'archive_bytes': output.stat().st_size, 'sha256': digest(output)}
    (work / 'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report), flush=True)
    print('Package: ' + str(output), flush=True)


if __name__ == '__main__':
    main()
