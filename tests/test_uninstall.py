"""Uninstall only synthetic files and isolated current-user registration keys."""
import os
from pathlib import Path
import subprocess
import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows uninstaller')

HARNESS = r'''
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.Win32;
internal static partial class Installer {
    static void AssertUninstall(bool value) {if(!value)throw new Exception("Synthetic uninstall assertion failed");}
    public static string UninstallTest(string mode,string folder) {
        string installed=Path.Combine(folder,"installed"), links=Path.Combine(folder,"links");
        string registry=@"Software\OfflineKeyVaultTests\"+Guid.NewGuid().ToString("N");
        Directory.CreateDirectory(installed);Directory.CreateDirectory(links);
        var manifest=new StringBuilder();
        foreach(string relative in new[]{"app/launch.py","runtime/python.exe","runtime/pythonw.exe","runtime/python312._pth","build-info.json","README.md"}) {
            string path=Path.Combine(installed,relative);Directory.CreateDirectory(Path.GetDirectoryName(path));
            File.WriteAllText(path,"synthetic program "+relative);manifest.Append(FileDigest(path)+"  "+relative+"\n");
        }
        string expected=TextDigest(manifest.ToString());
        File.WriteAllText(Path.Combine(installed,"OfflineKeyVault.exe"),"synthetic launcher");
        File.WriteAllText(Path.Combine(installed,"Uninstall.exe"),"synthetic uninstaller");
        string self=FileDigest(Path.Combine(installed,"Uninstall.exe"));
        manifest.Append(self+"  Uninstall.exe\n");
        File.WriteAllText(Path.Combine(installed,"manifest.sha256"),manifest.ToString(),new UTF8Encoding(false));
        FileStream blocked=null;
        try {
            RegisterInstallation(installed,registry);
            using(var key=Registry.CurrentUser.OpenSubKey(registry+"\\"+RegistrationName(installed))) {
                AssertUninstall((string)key.GetValue("UninstallString")==UninstallCommand(installed));
                AssertUninstall((string)key.GetValue("DisplayIcon")==Path.Combine(installed,"OfflineKeyVault.exe")+",0");
                AssertUninstall((string)key.GetValue("DisplayVersion")==ProductVersion);
            }
            // Repair / repeated upgrade updates the same key rather than duplicating it.
            RegisterInstallation(installed,registry);
            using(var key=Registry.CurrentUser.OpenSubKey(registry))AssertUninstall(key.GetSubKeyNames().Length==1);
            Shortcut(links,installed,"Synthetic matching shortcut");
            string other=Path.Combine(folder,"other");Directory.CreateDirectory(other);
            Shortcut(links,other,"Synthetic unrelated shortcut");
            var data=new Dictionary<string,string>();
            foreach(string relative in new[]{"vaults/personal.okv","recovery/private.okvr","keys/private.key",".offline-key-vault-preferences.json","app/personal.okv","runtime/personal.key"}) {
                string path=Path.Combine(installed,relative);Directory.CreateDirectory(Path.GetDirectoryName(path));
                File.WriteAllText(path,"synthetic user data "+relative);data[path]=FileDigest(path);
            }
            string preserved=Path.Combine(installed,"README.md");
            DataApproval approved=null;string selected=Path.Combine(installed,"vaults/personal.okv");
            if(mode=="delete-selected"||mode.StartsWith("data-")) {
                File.WriteAllText(selected,"{\"format\":\"OKV2\",\"fixture\":\"synthetic\"}");
                approved=ApproveDataDeletion(new[]{InspectData(selected)},"删除");
                if(mode=="data-changed")File.AppendAllText(selected," ");
                if(mode=="data-locked")blocked=new FileStream(selected+".lock",FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.ReadWrite);
                data[selected]=FileDigest(selected);
            }
            if(mode=="modified") {File.AppendAllText(preserved," user notes");data[preserved]=FileDigest(preserved);}
            if(mode=="missing")File.Delete(Path.Combine(installed,"app","launch.py"));
            if(mode=="manifest")File.AppendAllText(Path.Combine(installed,"manifest.sha256"),"invalid\n");
            if(mode=="receipt")File.WriteAllText(Path.Combine(installed,InstallReceipt),"invalid receipt");
            if(mode=="binding")expected=new string('0',64);
            if(mode=="self")self=new string('0',64);
            if(mode=="journal")File.WriteAllText(Path.Combine(installed,UpgradeJournal),"unfinished");
            if(mode=="locked")blocked=new FileStream(Path.Combine(installed,"README.md"),FileMode.Open,FileAccess.Read,FileShare.Read);
            if(mode=="metadata-locked")blocked=new FileStream(Path.Combine(installed,"manifest.sha256"),FileMode.Open,FileAccess.Read,FileShare.Read);
            if(mode=="registration-other")using(var key=Registry.CurrentUser.OpenSubKey(registry+"\\"+RegistrationName(installed),true))key.SetValue("InstallLocation",other);
            string runtime=Path.Combine(installed,"runtime"),outside=Path.Combine(folder,"outside-runtime");
            if(mode=="junction") {
                AssertUninstall(Path.GetFullPath(runtime).StartsWith(Path.GetFullPath(folder)+Path.DirectorySeparatorChar)&&Path.GetFullPath(outside).StartsWith(Path.GetFullPath(folder)+Path.DirectorySeparatorChar));
                Directory.Move(runtime,outside);
                using(var process=Process.Start(new ProcessStartInfo("powershell.exe","-NoProfile -File \""+Path.Combine(folder,"Junction.ps1")+"\" \""+runtime+"\" \""+outside+"\""){UseShellExecute=false,CreateNoWindow=true})) {process.WaitForExit();AssertUninstall(process.ExitCode==0);}
            }
            bool rejected=false;
            try {
                if(approved==null)RemoveInstallation(installed,expected,self,registry,new[]{links});
                else RemoveInstallationWithData(installed,expected,self,registry,new[]{links},approved);
            }catch(IOException){rejected=true;}
            if(mode=="junction") {AssertUninstall((File.GetAttributes(runtime)&FileAttributes.ReparsePoint)!=0);Directory.Delete(runtime,false);Directory.Move(outside,runtime);}
            bool shouldReject=Array.IndexOf(new[]{"manifest","receipt","binding","self","journal","locked","metadata-locked","junction","data-changed","data-locked"},mode)>=0;
            AssertUninstall(rejected==shouldReject);
            foreach(var pair in data) {
                if(mode=="delete-selected"&&pair.Key==selected)AssertUninstall(!File.Exists(selected));
                else AssertUninstall(FileDigest(pair.Key)==pair.Value);
            }
            AssertUninstall(File.Exists(Path.Combine(links,"Synthetic unrelated shortcut.lnk")));
            AssertUninstall(File.Exists(Path.Combine(installed,"Uninstall.exe"))==shouldReject);
            AssertUninstall(File.Exists(Path.Combine(links,"Synthetic matching shortcut.lnk"))==shouldReject);
            if(shouldReject)AssertUninstall(File.Exists(Path.Combine(installed,"runtime","python.exe")));
            else AssertUninstall(!File.Exists(Path.Combine(installed,"runtime","python.exe")));
            using(var key=Registry.CurrentUser.OpenSubKey(registry+"\\"+RegistrationName(installed)))AssertUninstall((key!=null)==(shouldReject||mode=="registration-other"));
            return "passed";
        } finally {
            if(blocked!=null)blocked.Dispose();
            // This unique test namespace never contains a real installed-app key.
            Registry.CurrentUser.DeleteSubKeyTree(registry,false);
        }
    }
}
public static class UninstallBridge {public static string Run(string mode,string folder){return Installer.UninstallTest(mode,folder);}}
'''


@pytest.fixture(scope='module')
def compiled(tmp_path_factory):
    work = tmp_path_factory.mktemp('uninstaller')
    harness = work / 'Harness.cs'
    harness.write_text(HARNESS, encoding='utf-8')
    dll = work / 'Tests.dll'
    compiler = Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    result = subprocess.run([str(compiler), '/nologo', '/target:library', '/r:System.Windows.Forms.dll', '/r:System.Web.Extensions.dll',
                             '/r:System.Drawing.dll', '/r:System.IO.Compression.dll', '/out:' + str(dll),
                             *(str(ROOT / 'packaging' / name) for name in ('Installer.cs', 'Upgrade.cs', 'Uninstall.cs', 'UninstallData.cs')),
                             str(harness)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    script = work / 'Run.ps1'
    script.write_text("param($Assembly,$Mode,$Folder)\n$ErrorActionPreference='Stop'\nAdd-Type -Path $Assembly\n[UninstallBridge]::Run($Mode,$Folder)\n", encoding='utf-8')
    return dll, script


@pytest.mark.parametrize('mode', ['success', 'modified', 'missing', 'manifest', 'receipt', 'binding', 'self', 'journal', 'locked', 'metadata-locked', 'registration-other', 'junction', 'delete-selected', 'data-changed', 'data-locked'])
def test_uninstall_preserves_personal_data_and_unrelated_registration(compiled, tmp_path, mode):
    dll, script = compiled
    if mode == 'junction':
        (tmp_path / 'Junction.ps1').write_text("param($Link,$Target)\n$ErrorActionPreference='Stop'\nNew-Item -ItemType Junction -Path $Link -Target $Target | Out-Null\n", encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(script), str(dll), mode, str(tmp_path)],
                            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'passed'
