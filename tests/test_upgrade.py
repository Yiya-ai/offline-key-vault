"""Compiled Windows upgrade transactions on disposable synthetic installations."""
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows upgrade transactions')
HARNESS = r'''
using System;
using System.IO;
using System.Text;
using System.Reflection;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
internal static partial class Installer {
    static void Fixture(string folder,string version) {
        Directory.CreateDirectory(folder);var manifest=new StringBuilder();
        foreach(string name in new[]{"app/launch.py","runtime/python.exe","runtime/pythonw.exe","runtime/python312._pth","runtime/Lib/legacy.py","build-info.json",version=="old"?"SECURITY.md":"CONTRIBUTING.md"}) {
            string path=Path.Combine(folder,name);Directory.CreateDirectory(Path.GetDirectoryName(path));
            File.WriteAllText(path,version+" "+name);manifest.Append(FileDigest(path)+"  "+name+"\n");
        }
        File.WriteAllText(Path.Combine(folder,"OfflineKeyVault.exe"),version);
        File.WriteAllText(Path.Combine(folder,"manifest.sha256"),manifest.ToString());
    }
    static void Assert(bool value) {if(!value)throw new Exception("Synthetic upgrade assertion failed");}
    public static string Test(string mode,string folder) {
        string dest=Path.Combine(folder,"installed"),stage=Path.Combine(folder,"staged");
        if(mode.StartsWith("test-mode-")) {
            string existing=mode=="test-mode-existing"?dest:Path.Combine(folder,mode=="test-mode-shortcut"?"shortcut-test":"unrelated-folder");
            Directory.CreateDirectory(existing);string sentinel=Path.Combine(existing,"keep.txt");File.WriteAllText(sentinel,"preserve user data");
            Assert(Main(new[]{"--test-install",dest})!=0);
            Assert(File.ReadAllText(sentinel)=="preserve user data");
            Assert(Directory.GetDirectories(folder,".offline-key-vault-install-*").Length==0);return "passed";
        }
        if(mode=="shortcut-update"||mode=="shortcut-unrelated") {
            Directory.CreateDirectory(dest);Directory.CreateDirectory(stage);
            string links=Path.Combine(folder,"shortcuts"),owner=mode=="shortcut-update"?dest:stage;
            Shortcut(links,owner,"Synthetic renamed shortcut");
            string link=Path.Combine(links,"Synthetic renamed shortcut.lnk");
            var issues=new List<string>();UpdateExistingShortcuts(links,dest,issues);Assert(issues.Count==0);
            bool refused=false;try{Shortcut(links,dest,"Synthetic renamed shortcut");}catch(IOException){refused=true;}
            Assert(refused==(mode=="shortcut-unrelated"));
            Assert(ReadShortcutTarget(link)==Path.Combine(owner,"OfflineKeyVault.exe"));return "passed";
        }
        if(mode=="recover") {RecoverUpgrade(dest);Assert(File.ReadAllText(Path.Combine(dest,"OfflineKeyVault.exe"))=="old");Assert(File.Exists(Path.Combine(dest,"SECURITY.md")));Assert(!File.Exists(Path.Combine(dest,"CONTRIBUTING.md")));Assert(File.ReadAllText(Path.Combine(dest,"vaults","sample.okv"))=="synthetic vault bytes");return "passed";}
        if(mode=="guard-running" || mode=="guard-launch") {
            Directory.CreateDirectory(dest);File.Copy(Path.Combine(folder,"Sleeper.exe"),Path.Combine(dest,"OfflineKeyVault.exe"));
            if(mode=="guard-running") {
                using(var p=Process.Start(new ProcessStartInfo(Path.Combine(dest,"OfflineKeyVault.exe")){UseShellExecute=false,CreateNoWindow=true})) {
                    try {System.Threading.Thread.Sleep(250);bool denied=false;try{var g=GuardApplications(dest);foreach(var f in g)f.Dispose();}catch(IOException){denied=true;}Assert(denied);}
                    finally {if(!p.HasExited)p.Kill();p.WaitForExit();}
                }
            } else {
                var guards=GuardApplications(dest);bool denied=false;
                try {try{using(var p=Process.Start(new ProcessStartInfo(Path.Combine(dest,"OfflineKeyVault.exe")){UseShellExecute=false,CreateNoWindow=true})){p.Kill();p.WaitForExit();}}catch(System.ComponentModel.Win32Exception){denied=true;}Assert(denied);}
                finally {foreach(var g in guards)g.Dispose();}
            }
            return "passed";
        }
        Fixture(dest,"old");Fixture(stage,"new");
        Directory.CreateDirectory(Path.Combine(dest,"vaults"));File.WriteAllText(Path.Combine(dest,"vaults","sample.okv"),"synthetic vault bytes");
        File.WriteAllText(Path.Combine(dest,".offline-key-vault-preferences.json"),"synthetic preferences");
        string cache=null,cacheHash=null;
        if(mode.StartsWith("cache-")) {
            string relative=mode=="cache-outside"?"app/__pycache__/launch.cpython-312.pyc":mode=="cache-orphan"?"runtime/Lib/__pycache__/unknown.cpython-312.pyc":mode=="cache-optimized"?"runtime/Lib/__pycache__/legacy.cpython-312.opt-1.pyc":"runtime/Lib/__pycache__/legacy.cpython-312.pyc";
            cache=Path.Combine(mode=="cache-stage"?stage:dest,relative);Directory.CreateDirectory(Path.GetDirectoryName(cache));
            using(var writer=new BinaryWriter(File.Create(cache))) {writer.Write(mode=="cache-header"?0u:0x0a0d0dcbu);writer.Write(mode=="cache-flags"?2u:0u);writer.Write(0UL);writer.Write(42);}
            if(mode=="cache-large")using(var file=File.OpenWrite(cache))file.SetLength(16*1024*1024+1);
            cacheHash=FileDigest(cache);
        }
        if(mode=="journal-invalid") {
            File.WriteAllText(Path.Combine(dest,UpgradeJournal),"OKV-UPGRADE1\n"+Guid.NewGuid().ToString("N")+"\n11 ../vaults\n");
            bool denied=false;try{RecoverUpgrade(dest);}catch(IOException){denied=true;}Assert(denied);
            Assert(File.ReadAllText(Path.Combine(dest,"vaults","sample.okv"))=="synthetic vault bytes");
            Assert(File.ReadAllText(Path.Combine(dest,"OfflineKeyVault.exe"))=="old");return "passed";
        }
        if(mode=="tampered")File.AppendAllText(Path.Combine(dest,"app","launch.py"),"changed");
        if(mode=="extra")File.WriteAllText(Path.Combine(dest,"runtime","private.okv"),"retain this file");
        if(mode=="collision")File.WriteAllText(Path.Combine(dest,"CONTRIBUTING.md"),"user document");
        if(mode=="traversal")File.AppendAllText(Path.Combine(dest,"manifest.sha256"),new string('0',64)+"  ../outside.txt\n");
        FileStream blocked=null;System.Threading.Timer unlock=null;
        if(mode=="transient-rename"||mode=="blocked-rename") {
            blocked=new FileStream(Path.Combine(dest,"app","launch.py"),FileMode.Open,FileAccess.Read,FileShare.Read);
            if(mode=="transient-rename")unlock=new System.Threading.Timer(state=>blocked.Dispose(),null,450,System.Threading.Timeout.Infinite);
        }
        var clock=Stopwatch.StartNew();
        bool failed=false;
        try {
            ApplyUpgrade(dest,stage,p=>{Assert(File.ReadAllText(Path.Combine(p,"OfflineKeyVault.exe"))=="new");if(mode=="verify-fail"||mode=="cache-rollback")throw new IOException("synthetic validation failure");},n=>{
                if(mode=="move-fail"&&n==3)throw new IOException("synthetic rename failure");
                if(mode.StartsWith("crash-")&&n==Int32.Parse(mode.Substring(6)))Environment.Exit(73);
            });
        } catch(IOException){failed=true;}
        finally {if(unlock!=null)unlock.Dispose();if(blocked!=null)blocked.Dispose();}
        if(mode=="transient-rename")Assert(clock.ElapsedMilliseconds>=400);
        if(mode=="blocked-rename")Assert(clock.ElapsedMilliseconds<8000);
        Assert(failed==(mode!="success"&&mode!="transient-rename"&&mode!="cache-old"&&mode!="cache-optimized"));
        if(cache!=null) {
            if(failed)Assert(FileDigest(cache)==cacheHash);
            else {
                Assert(Directory.GetFiles(Path.Combine(dest,"runtime"),"*.pyc",SearchOption.AllDirectories).Length==0);
                var backups=Directory.GetDirectories(folder,".offline-key-vault-upgrade-*");Assert(backups.Length==1);
                var caches=Directory.GetFiles(Path.Combine(backups[0],"old","runtime"),"*.pyc",SearchOption.AllDirectories);
                Assert(caches.Length==1&&FileDigest(caches[0])==cacheHash);
            }
        }
        Assert(File.ReadAllText(Path.Combine(dest,"OfflineKeyVault.exe"))==(failed?"old":"new"));
        Assert(!File.Exists(Path.Combine(dest,UpgradeJournal)));
        Assert(File.ReadAllText(Path.Combine(dest,"vaults","sample.okv"))=="synthetic vault bytes");
        Assert(File.ReadAllText(Path.Combine(dest,".offline-key-vault-preferences.json"))=="synthetic preferences");
        if(mode=="collision")Assert(File.ReadAllText(Path.Combine(dest,"CONTRIBUTING.md"))=="user document");
        if(mode=="extra")Assert(File.ReadAllText(Path.Combine(dest,"runtime","private.okv"))=="retain this file");
        foreach(string transaction in Directory.GetDirectories(folder,".offline-key-vault-upgrade-*"))Assert(Directory.GetFiles(transaction,"*.okv",SearchOption.AllDirectories).Length==0);
        return "passed";
    }
}
public static class UpgradeTestBridge {public static string Run(string mode,string folder){return Installer.Test(mode,folder);}}
'''


@pytest.fixture(scope='module')
def compiled(tmp_path_factory):
    work = tmp_path_factory.mktemp('compiled-upgrade')
    harness = work / 'Harness.cs'
    harness.write_text(HARNESS, encoding='utf-8')
    compiler = Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    dll = work / 'UpgradeTests.dll'
    result = subprocess.run([str(compiler), '/nologo', '/target:library',
                             '/r:System.Windows.Forms.dll', '/r:System.Drawing.dll', '/r:System.IO.Compression.dll',
                             '/out:' + str(dll), str(ROOT / 'packaging/Installer.cs'),
                             str(ROOT / 'packaging/Upgrade.cs'), str(ROOT / 'packaging/Uninstall.cs'), str(harness)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    sleeper = work / 'Sleeper.cs'
    sleeper.write_text('class Sleeper {static void Main(){System.Threading.Thread.Sleep(60000);}}', encoding='utf-8')
    subprocess.run([str(compiler), '/nologo', '/target:winexe', '/out:' + str(work / 'Sleeper.exe'), str(sleeper)], check=True, capture_output=True)
    script = work / 'Run.ps1'
    script.write_text("param($Assembly,$Mode,$Folder)\n$ErrorActionPreference='Stop'\nAdd-Type -Path $Assembly\n[UpgradeTestBridge]::Run($Mode,$Folder)\n", encoding='utf-8')
    return dll, script, work / 'Sleeper.exe'


def invoke(compiled, mode, folder):
    dll, script, _ = compiled
    return subprocess.run(['powershell.exe', '-NoProfile', '-File', str(script), str(dll), mode,
                           str(folder)], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)


@pytest.mark.parametrize('mode', ['success', 'verify-fail', 'move-fail', 'transient-rename', 'blocked-rename', 'tampered', 'extra', 'collision', 'traversal', 'journal-invalid', 'guard-running', 'guard-launch', 'shortcut-update', 'shortcut-unrelated', 'test-mode-existing', 'test-mode-shortcut', 'test-mode-unrelated', 'cache-old', 'cache-optimized', 'cache-rollback', 'cache-stage', 'cache-orphan', 'cache-header', 'cache-flags', 'cache-outside', 'cache-large'])
def test_upgrade_transaction(compiled, tmp_path, mode):
    if mode.startswith('guard-'):
        import shutil
        shutil.copyfile(compiled[2], tmp_path / 'Sleeper.exe')
    result = invoke(compiled, mode, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'passed'


@pytest.mark.parametrize('moves', [1, 2, 3, 4, 7, 10, 12])
def test_abrupt_process_exit_recovers_without_touching_data(compiled, tmp_path, moves):
    crash = invoke(compiled, 'crash-' + str(moves), tmp_path)
    assert crash.returncode == 73, crash.stdout + crash.stderr
    recovered = invoke(compiled, 'recover', tmp_path)
    assert recovered.returncode == 0, recovered.stdout + recovered.stderr


def test_upgrade_rejects_junction_in_program_tree(compiled, tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    sentinel = outside / 'keep.txt'
    sentinel.write_bytes(b'untouched outside data')
    app = tmp_path / 'installed/app'
    app.mkdir(parents=True)
    script = tmp_path / 'Junction.ps1'
    script.write_text("param($Link,$Target)\n$ErrorActionPreference='Stop'\nNew-Item -ItemType Junction -Path $Link -Target $Target | Out-Null\n", encoding='utf-8')
    subprocess.run(['powershell.exe', '-NoProfile', '-File', str(script), str(app / 'redirect'), str(outside)], check=True, capture_output=True)
    result = invoke(compiled, 'junction', tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert sentinel.read_bytes() == b'untouched outside data'
