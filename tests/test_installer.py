"""Exercise the compiled installer with temporary ACLs on synthetic directories."""
import os
from pathlib import Path
import subprocess
import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows installer')
HARNESS = r'''
using System;
using System.IO;
using System.Reflection;
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
public static class InstallerIOTests {
    static void Restore(string folder,string descriptor) {
        var security=new DirectorySecurity();
        security.SetSecurityDescriptorSddlForm(descriptor,AccessControlSections.Access);
        Directory.SetAccessControl(folder,security);
    }
    static FileStream Open(string path) {
        try { return (FileStream)typeof(Installer).GetMethod("OpenNewOutput",BindingFlags.NonPublic|BindingFlags.Static).Invoke(null,new object[]{path}); }
        catch(TargetInvocationException error) { throw error.InnerException; }
    }
    public static string Run(string mode,string folder) {
        string path=Path.Combine(folder,"synthetic-runtime.dll");
        if(mode=="existing") {
            File.WriteAllText(path,"preserve existing content");
            try { using(var stream=Open(path)) {} throw new Exception("Overwrite accepted"); }
            catch(IOException) {}
            if(File.ReadAllText(path)!="preserve existing content")throw new Exception("Existing file changed");
            return "passed";
        }
        if(mode=="normal") {
            using(var stream=Open(path))stream.WriteByte(42);
            if(File.ReadAllBytes(path)[0]!=42)throw new Exception("Wrong output");
            return "passed";
        }
        var original=Directory.GetAccessControl(folder).GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        var denied=Directory.GetAccessControl(folder);
        denied.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User,FileSystemRights.CreateFiles,AccessControlType.Deny));
        Directory.SetAccessControl(folder,denied);
        try {
            bool fixtureDenied=false;
            try { using(var stream=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)){} }
            catch(UnauthorizedAccessException){fixtureDenied=true;}
            if(!fixtureDenied)throw new Exception("ACL fixture did not deny creation");
            var clock=Stopwatch.StartNew();
            if(mode=="transient") {
                using(var timer=new System.Threading.Timer(state=>Restore(folder,original),null,450,System.Threading.Timeout.Infinite)) {
                    using(var stream=Open(path))stream.WriteByte(42);
                }
                if(clock.ElapsedMilliseconds<400 || clock.ElapsedMilliseconds>6000)throw new Exception("Retry timing invalid");
                if(File.ReadAllBytes(path)[0]!=42)throw new Exception("Wrong recovered output");
            } else if(mode=="persistent") {
                bool refused=false;
                try { using(var stream=Open(path)) {} }
                catch(UnauthorizedAccessException) { refused=true; }
                if(!refused || clock.ElapsedMilliseconds>6000)throw new Exception("Persistent denial did not fail safely");
            } else throw new Exception("Unknown case");
        } finally { Restore(folder,original); }
        if(mode=="persistent" && File.Exists(path))throw new Exception("Partial output left behind");
        return "passed";
    }
}
'''


@pytest.fixture(scope='module')
def compiled_installer(tmp_path_factory):
    work = tmp_path_factory.mktemp('compiled-installer-io')
    harness = work / 'Harness.cs'; harness.write_text(HARNESS, encoding='utf-8')
    dll = work / 'InstallerTests.dll'
    compiler = Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    subprocess.run([str(compiler), '/nologo', '/target:library',
                    '/r:System.Windows.Forms.dll', '/r:System.Drawing.dll', '/r:System.IO.Compression.dll',
                    '/out:' + str(dll), str(ROOT / 'packaging/Installer.cs'), str(ROOT / 'packaging/Upgrade.cs'), str(harness)], check=True, capture_output=True)
    script = work / 'Run.ps1'
    script.write_text("param($Assembly,$Mode,$Folder)\n$ErrorActionPreference='Stop'\nAdd-Type -Path $Assembly\n[InstallerIOTests]::Run($Mode,$Folder)\n", encoding='utf-8')
    return dll, script


@pytest.mark.parametrize('mode', ['normal', 'transient', 'persistent', 'existing'])
def test_installer_output_creation(compiled_installer, tmp_path, mode):
    dll, script = compiled_installer
    result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(script), str(dll), mode,
                             str(tmp_path)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'passed'


def test_locked_previous_installer_is_kept_and_new_artifact_is_published(tmp_path):
    from build_installer import publish_artifact
    work = tmp_path / 'build'
    dist = tmp_path / 'dist'
    work.mkdir()
    dist.mkdir()
    output = work / 'offline-key-vault-setup.exe'
    target = dist / output.name
    output.write_bytes(b'synthetic new installer')
    target.write_bytes(b'synthetic previous installer')
    with target.open('rb'):
        published = publish_artifact(output, dist)
    assert published != target
    assert published.read_bytes() == b'synthetic new installer'
    assert target.read_bytes() == b'synthetic previous installer'
