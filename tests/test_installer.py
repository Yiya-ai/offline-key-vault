"""Exercise the compiled installer with temporary ACLs on synthetic directories."""
import os
from pathlib import Path
import subprocess
import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows installer')


@pytest.mark.parametrize('mode', ['transient', 'persistent', 'nontransient'])
def test_verified_archive_publication_preserves_old_output_on_failure(tmp_path, monkeypatch, mode):
    import build_portable
    source, target = tmp_path / 'new.zip', tmp_path / 'published.zip'
    source.write_bytes(b'new verified artifact')
    target.write_bytes(b'previous artifact')
    replace = os.replace
    calls = []
    def locked_replace(first, second):
        calls.append(1)
        if mode == 'transient' and len(calls) == 3:
            return replace(first, second)
        error = PermissionError('synthetic sharing error')
        error.winerror = 87 if mode == 'nontransient' else 5
        raise error
    monkeypatch.setattr(build_portable.os, 'replace', locked_replace)
    monkeypatch.setattr(build_portable.time, 'sleep', lambda _: None)
    if mode == 'transient':
        build_portable.publish_archive(source, target)
        assert target.read_bytes() == b'new verified artifact' and not source.exists()
        assert len(calls) == 3
    else:
        with pytest.raises(PermissionError):
            build_portable.publish_archive(source, target)
        assert target.read_bytes() == b'previous artifact' and source.read_bytes() == b'new verified artifact'
        assert len(calls) == (1 if mode == 'nontransient' else 6)

HARNESS = r'''
using System;
using System.IO;
using System.Reflection;
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Windows.Forms;
using System.Drawing;
public static class InstallerIOTests {
    static void Check(bool value,string message) {if(!value)throw new Exception(message);}
    static void CheckBounds(Control parent) {
        foreach(Control child in parent.Controls) {
            if(!child.Visible)continue;
            Check(child.Left>=0&&child.Top>=0&&child.Right<=parent.ClientSize.Width+1&&child.Bottom<=parent.ClientSize.Height+1,"Clipped: "+child.GetType().Name+" "+child.Text);
            var label=child as Label;
            if(label!=null)Check(label.Height>=label.PreferredHeight,"Label height clipped: "+label.Text);
            CheckBounds(child);
        }
    }
    static string TestUI(string mode,string folder) {
        Application.EnableVisualStyles();
        if(mode=="path-editor") {
            using(var model=new TextBox {Text=Path.Combine(Path.GetPathRoot(folder),"Apps","OfflineKeyVault")})
            using(var editor=new Installer.LocationEditor(model,new Button())) {
                string root=Path.GetPathRoot(folder);
                Check((string)editor.Drive.SelectedItem==root,"Initial drive mismatch");
                Check(editor.Folder.Text==@"Apps\OfflineKeyVault","Initial folder mismatch");
                editor.Folder.Text=@"Tools\Vault";Check(model.Text==root+@"Tools\Vault","Typing did not update model");
                foreach(string bad in new[]{@"\escape",@"C:relative",@"\\server\share",@"\\?\C:\device"}) {
                    editor.Folder.Text=bad;Check(model.Text==String.Empty,"Unsafe path silently rewritten");
                    try {typeof(Installer).GetMethod("CheckLocal",BindingFlags.NonPublic|BindingFlags.Static).Invoke(null,new object[]{bad,false});throw new Exception("Unsafe absolute path accepted");}
                    catch(TargetInvocationException error) {Check(error.InnerException is IOException,"Unexpected path failure");}
                }
                editor.Folder.Text=root+@"Paste\Vault";
                Check(editor.Folder.Text==@"Paste\Vault"&&model.Text==root+@"Paste\Vault","Full paste did not split");
                editor.Folder.Text=model.Text;Check(editor.Folder.Text==@"Paste\Vault","Same path paste did not split");
                if(editor.Drive.Items.Count>1) {
                    int next=(editor.Drive.SelectedIndex+1)%editor.Drive.Items.Count;
                    editor.Drive.SelectedIndex=next;
                    Check(model.Text==(string)editor.Drive.SelectedItem+@"Paste\Vault","Drive change lost folder");
                }
                model.Text=root+@"Browse\Vault";Check(editor.Folder.Text==@"Browse\Vault","Browse did not sync");
                model.Enabled=false;Check(!editor.Enabled,"Editor stayed enabled during install");
                string start=(string)typeof(Installer).GetMethod("BrowseStart",BindingFlags.NonPublic|BindingFlags.Static).Invoke(null,new object[]{Path.Combine(folder,"new","install")});
                Check(start==folder,"New installation browser did not start in existing parent");
            }
            return "passed";
        }
        using(var owner=new Form())
        using(var form=(Form)typeof(Installer).GetMethod(mode=="layout-picker"?"CreateFolderPicker":"CreateWizard",BindingFlags.NonPublic|BindingFlags.Static).Invoke(null,mode=="layout-picker"?new object[]{owner,folder,new Action<string>(value=>{})}:null)) {
            if(mode=="layout-large")form.Font=new Font("Microsoft YaHei UI",14);
            form.Show();Application.DoEvents();form.PerformLayout();Application.DoEvents();
            CheckBounds(form);
            Check(form.ClientSize.Height<700,"Excessive empty height");
            foreach(Control control in form.Controls) {
                var panel=control as Panel;
                if(panel!=null)Check(!panel.VerticalScroll.Visible&&!panel.HorizontalScroll.Visible,"Unnecessary scrollbar");
            }
            using(var bitmap=new Bitmap(form.Width,form.Height)) {form.DrawToBitmap(bitmap,new Rectangle(Point.Empty,bitmap.Size));bitmap.Save(Path.Combine(folder,"installer-layout.png"));}
            if(mode=="layout-picker") {
                var field=(TextBox)form.Controls.Find("InstallFolder",true)[0];
                var choose=(Button)form.Controls.Find("ChooseDirectory",true)[0];
                Check(choose.Enabled,"Existing folder not selectable");
                field.Text=@"missing-child\invalid";Application.DoEvents();
                Check(!choose.Enabled,"Stale folder can still be confirmed");
                field.Text=folder;
                var until=DateTime.UtcNow.AddMilliseconds(600);
                while(DateTime.UtcNow<until){Application.DoEvents();System.Threading.Thread.Sleep(10);}
                Check(choose.Enabled,"Live directory refresh did not run");
            }
            form.Close();
        }
        return "passed";
    }
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
        if(mode=="path-editor"||mode.StartsWith("layout-"))return TestUI(mode,folder);
        if(mode.StartsWith("process-")) {
            int attempts=0;bool refused=false;
            try {Installer.StartChecked(()=>{attempts++;if(mode=="process-sharing"&&attempts==3)return null;throw new System.ComponentModel.Win32Exception(mode=="process-permission"?5:attempts==1?32:33);});}
            catch(System.ComponentModel.Win32Exception){refused=true;}
            Check(attempts==(mode=="process-sharing"?3:mode=="process-permission"?1:6),"Unexpected process-start retry count");
            Check(refused==(mode!="process-sharing"),"Unexpected process-start outcome");return "passed";
        }
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
                    '/out:' + str(dll), str(ROOT / 'packaging/Installer.cs'), str(ROOT / 'packaging/Upgrade.cs'), str(ROOT / 'packaging/Uninstall.cs'), str(harness)], check=True, capture_output=True)
    script = work / 'Run.ps1'
    script.write_text("param($Assembly,$Mode,$Folder)\n$ErrorActionPreference='Stop'\nAdd-Type -Path $Assembly\n[InstallerIOTests]::Run($Mode,$Folder)\n", encoding='utf-8')
    return dll, script


@pytest.mark.parametrize('mode', ['normal', 'transient', 'persistent', 'existing', 'path-editor', 'layout-normal', 'layout-large', 'layout-picker', 'process-sharing', 'process-persistent', 'process-permission'])
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
