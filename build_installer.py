"""Build and test an offline Windows installer from the verified portable ZIP."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import zipfile
from build_portable import checked, digest, run_checked, verify_executable_icon

ROOT = Path(__file__).resolve().parent


def publish_artifact(output, directory):
    """Keep an older installer usable when Windows still has its image open."""
    target = directory / output.name
    if target.exists(): checked(target)
    try:
        os.replace(output, target)
    except PermissionError:
        target = directory / ('offline-key-vault-setup-' + digest(output)[:12] + '.exe')
        if target.exists():
            checked(target)
            if digest(target) != digest(output):
                raise RuntimeError('Versioned installer output is occupied by another file')
        else:
            os.replace(output, target)
    return target


def main():
    if os.name != 'nt': raise SystemExit('Windows installer requires Windows.')
    archive = checked(ROOT / 'dist/offline-key-vault-windows-x64.zip')
    checksum = checked(archive.with_suffix('.zip.sha256')).read_text(encoding='ascii').split()[0]
    if digest(archive) != checksum: raise SystemExit('Portable ZIP checksum mismatch.')
    # Reject stale bundles so installer always contains the current application.
    from build_portable import APP_FILES
    with zipfile.ZipFile(archive) as z:
        info = json.loads(z.read('OfflineKeyVault/build-info.json'))
        if info.get('launcher_source_sha256') != digest(ROOT / 'packaging/Launcher.cs'):
            raise SystemExit('Rebuild the portable ZIP: launcher source changed.')
        if info.get('profile') != 'standard' or 'pykcs11' in info.get('packages', {}):
            raise SystemExit('Public installer requires a freshly verified standard portable build without PyKCS11.')
        if any('pykcs11' in name.lower() for name in z.namelist()):
            raise SystemExit('Unexpected PyKCS11 files in standard installer payload.')
        for name in APP_FILES:
            if z.read('OfflineKeyVault/app/' + name) != (ROOT / name).read_bytes():
                raise SystemExit('Rebuild the portable ZIP before building the installer.')
        for name in ('README.md', 'README.zh-CN.md', 'RELEASING.md'):
            if z.read('OfflineKeyVault/' + name) != (ROOT / name).read_bytes():
                raise SystemExit('Rebuild the portable ZIP: packaged documentation changed.')
    checked(ROOT / 'build'); checked(ROOT / 'dist')
    work = Path(tempfile.mkdtemp(prefix='installer-', dir=ROOT / 'build'))
    output = work / 'offline-key-vault-setup.exe'
    compiler = checked(Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe')
    print('Compiling offline installer...', flush=True)
    from keyvault.branding import write_ico
    icon = work / 'OfflineKeyVault.ico'
    write_ico(icon)
    run_checked([compiler, '/nologo', '/target:winexe', '/platform:x64', '/optimize+', '/win32icon:' + str(icon),
                 '/r:System.Windows.Forms.dll', '/r:System.Drawing.dll', '/r:System.IO.Compression.dll',
                 '/resource:' + str(archive) + ',payload.zip', '/out:' + str(output), ROOT / 'packaging/Installer.cs', ROOT / 'packaging/Upgrade.cs'])
    verify_executable_icon(output)
    installed = work / '安装 验证'
    print('Testing actual install, in-place upgrade, data preservation and shortcut updates...', flush=True)
    run_checked([output, '--test-install', installed], cwd=work)
    refusal = subprocess.run([str(output), '--test-install', str(installed)], cwd=work, capture_output=True, timeout=30)
    if refusal.returncode == 0:
        raise RuntimeError('Test mode accepted an existing installation')
    verify_executable_icon(installed / 'OfflineKeyVault.exe')
    if not (work / 'shortcut-test/OfflineKeyVault-Test.lnk').is_file():
        raise RuntimeError('Shortcut verification failed')
    target = publish_artifact(output, ROOT / 'dist')
    sidecar = target.with_suffix('.exe.sha256')
    if sidecar.exists(): checked(sidecar)
    sidecar.write_text(digest(target) + '  ' + target.name + '\n', encoding='ascii')
    report = {'ok': True, 'install_verified': True, 'shortcut_target_verified': True,
              'embedded_icons_verified': True, 'shortcut_icon_verified': True,
              'in_place_upgrade_verified': True, 'user_data_preserved': True, 'shortcut_update_verified': True,
              'test_mode_existing_refused': True,
              'unrelated_folder_preserved': True, 'real_desktop_untouched': True,
              'sources': {name: digest(ROOT / name) for name in ('packaging/Installer.cs', 'packaging/Upgrade.cs')},
              'artifact': target.name, 'sha256': digest(target)}
    (work / 'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report), flush=True)
    print('Installer: ' + str(target), flush=True)


if __name__ == '__main__': main()
