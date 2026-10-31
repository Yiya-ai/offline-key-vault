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
from build_portable import checked, digest, run_checked

ROOT = Path(__file__).resolve().parent


def main():
    if os.name != 'nt': raise SystemExit('Windows installer requires Windows.')
    archive = checked(ROOT / 'dist/offline-key-vault-windows-x64.zip')
    checksum = checked(archive.with_suffix('.zip.sha256')).read_text(encoding='ascii').split()[0]
    if digest(archive) != checksum: raise SystemExit('Portable ZIP checksum mismatch.')
    # Reject stale bundles so installer always contains the current application.
    from build_portable import APP_FILES
    with zipfile.ZipFile(archive) as z:
        for name in APP_FILES:
            if z.read('OfflineKeyVault/app/' + name) != (ROOT / name).read_bytes():
                raise SystemExit('Rebuild the portable ZIP before building the installer.')
    checked(ROOT / 'build'); checked(ROOT / 'dist')
    work = Path(tempfile.mkdtemp(prefix='installer-', dir=ROOT / 'build'))
    output = work / 'offline-key-vault-setup.exe'
    compiler = checked(Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe')
    print('Compiling offline installer...', flush=True)
    run_checked([compiler, '/nologo', '/target:winexe', '/platform:x64', '/optimize+',
                 '/r:System.Windows.Forms.dll', '/r:System.Drawing.dll', '/r:System.IO.Compression.dll',
                 '/resource:' + str(archive) + ',payload.zip', '/out:' + str(output), ROOT / 'packaging/Installer.cs'])
    installed = work / '安装 验证'
    print('Testing actual install, shortcut target, runtime and overwrite refusal...', flush=True)
    run_checked([output, '--test-install', installed], cwd=work)
    if not (installed / 'shortcut-test/OfflineKeyVault-Test.lnk').is_file():
        raise RuntimeError('Shortcut verification failed')
    target = ROOT / 'dist' / output.name
    if target.exists(): checked(target)
    os.replace(output, target)
    sidecar = target.with_suffix('.exe.sha256')
    if sidecar.exists(): checked(sidecar)
    sidecar.write_text(digest(target) + '  ' + target.name + '\n', encoding='ascii')
    report = {'ok': True, 'install_verified': True, 'shortcut_target_verified': True,
              'overwrite_rejected': True, 'real_desktop_untouched': True, 'sha256': digest(target)}
    (work / 'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report), flush=True)
    print('Installer: ' + str(target), flush=True)


if __name__ == '__main__': main()
