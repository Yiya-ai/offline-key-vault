using System;
using System.IO;
using System.Text;
using System.Reflection;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Windows.Forms;
using Microsoft.Win32;

internal static partial class Installer {
    internal const string ProductVersion="0.2.6";
    const string ProgramManifestHash="__PROGRAM_MANIFEST_SHA256__";
    const string InstallReceipt=".offline-key-vault-install.txt";
    internal const string UninstallRegistry=@"Software\Microsoft\Windows\CurrentVersion\Uninstall";
    static string TextDigest(string text) {
        using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(text))).Replace("-","").ToLowerInvariant();
    }
    static string RegistrationName(string folder) {return "OfflineKeyVault-"+TextDigest(CheckLocal(folder).ToUpperInvariant()).Substring(0,24);}
    static bool DigestText(string value) {return value.Length==64&&Array.TrueForAll(value.ToCharArray(),c=>(c>='0'&&c<='9')||(c>='a'&&c<='f'));}
    static string UninstallCommand(string folder) {return "\""+Path.Combine(folder,"Uninstall.exe")+"\"";}
    static void RegisterInstallation(string folder,string registryRoot=UninstallRegistry) {
        folder=CheckLocal(folder);
        string receipt=Path.Combine(folder,InstallReceipt);Plain(receipt);
        if(File.Exists(receipt)) {
            var previous=ReadReceipt(folder);
            if(!String.Equals(previous[1],folder,StringComparison.OrdinalIgnoreCase))throw new IOException("安装登记文件不属于此目录，未覆盖。");
        }
        string content="OKV-INSTALL1\n"+folder+"\n"+FileDigest(Path.Combine(folder,"OfflineKeyVault.exe"))+"\n"+FileDigest(Path.Combine(folder,"Uninstall.exe"))+"\n"+FileDigest(Path.Combine(folder,"manifest.sha256"))+"\n";
        string temporary=Path.Combine(folder,".okv-registration-"+Guid.NewGuid().ToString("N")+".tmp");
        using(var stream=OpenNewOutput(temporary)) {byte[] bytes=Encoding.UTF8.GetBytes(content);stream.Write(bytes,0,bytes.Length);stream.Flush(true);}
        if(File.Exists(receipt))File.Replace(temporary,receipt,null);else File.Move(temporary,receipt);
        using(var key=Registry.CurrentUser.CreateSubKey(registryRoot+"\\"+RegistrationName(folder))) {
            string old=key.GetValue("InstallLocation") as string;
            if(old!=null&&!String.Equals(old,folder,StringComparison.OrdinalIgnoreCase))throw new IOException("卸载登记名称已被其他安装占用。");
            key.SetValue("DisplayName","离线密钥柜 / Offline Key Vault");key.SetValue("DisplayVersion",ProductVersion);
            key.SetValue("Publisher","Offline Key Vault contributors");key.SetValue("InstallLocation",folder);
            key.SetValue("DisplayIcon",Path.Combine(folder,"OfflineKeyVault.exe")+",0");
            key.SetValue("UninstallString",UninstallCommand(folder));
            key.SetValue("NoModify",1,RegistryValueKind.DWord);key.SetValue("NoRepair",1,RegistryValueKind.DWord);
        }
    }
    static string[] ReadReceipt(string folder) {
        string path=Path.Combine(folder,InstallReceipt);Plain(path);
        if(!File.Exists(path)||new FileInfo(path).Length>8192)throw new IOException("缺少有效的安装登记，请先用新版安装器在原目录升级一次。");
        string[] lines=File.ReadAllLines(path,new UTF8Encoding(false,true));
        if(lines.Length!=5||lines[0]!="OKV-INSTALL1"||!String.Equals(lines[1],folder,StringComparison.OrdinalIgnoreCase)||!DigestText(lines[2])||!DigestText(lines[3])||!DigestText(lines[4]))throw new IOException("安装登记无效，未移除文件。");
        return lines;
    }
    static Dictionary<string,string> RemovalPlan(string folder,string expectedManifest,string expectedUninstaller) {
        string[] receipt=ReadReceipt(folder);
        string manifest=Path.Combine(folder,"manifest.sha256");Plain(manifest);
        if(new FileInfo(manifest).Length>4*1024*1024||FileDigest(manifest)!=receipt[4])throw new IOException("安装清单已改变，未移除文件。");
        var files=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);var body=new StringBuilder();
        foreach(string line in File.ReadAllLines(manifest,new UTF8Encoding(false,true))) {
            if(line.Length<67||line.Substring(64,2)!="  "||!DigestText(line.Substring(0,64)))throw new IOException("卸载清单无效。");
            string name=line.Substring(66);
            if(!ComponentNames.Contains(name.Split('/')[0])||name.IndexOfAny(new[]{'\\',':'})>=0||Array.Exists(name.Split('/'),p=>p.Length==0||p=="."||p=="..")||files.ContainsKey(name))throw new IOException("卸载清单路径无效。");
            files.Add(name,line.Substring(0,64));
            if(name!="Uninstall.exe")body.Append(line+"\n");
        }
        if(!DigestText(expectedManifest)||TextDigest(body.ToString())!=expectedManifest||!files.ContainsKey("Uninstall.exe")||files["Uninstall.exe"]!=expectedUninstaller||receipt[3]!=expectedUninstaller)throw new IOException("卸载器与安装清单不匹配，未移除文件。");
        files.Add("OfflineKeyVault.exe",receipt[2]);
        return files;
    }
    static void RemoveRegistration(string folder,string registryRoot) {
        string name=RegistrationName(folder);
        using(var parent=Registry.CurrentUser.OpenSubKey(registryRoot,true)) {
            if(parent==null)return;
            using(var key=parent.OpenSubKey(name)) {
                if(key==null||!String.Equals(key.GetValue("InstallLocation") as string,folder,StringComparison.OrdinalIgnoreCase)||!String.Equals(key.GetValue("UninstallString") as string,UninstallCommand(folder),StringComparison.OrdinalIgnoreCase))return;
            }
            parent.DeleteSubKey(name,false);
        }
    }
    static void RemoveShortcuts(string folder,string installed,List<string> notes) {
        if(!Directory.Exists(folder))return;
        CheckLocal(folder);
        foreach(string path in Directory.GetFiles(folder,"*.lnk")) {
            try {
                Plain(path);
                if(String.Equals(ReadShortcutTarget(path),Path.Combine(installed,"OfflineKeyVault.exe"),StringComparison.OrdinalIgnoreCase))File.Delete(path);
            } catch {notes.Add("部分快捷方式未能移除，可稍后手动移除。");}
        }
    }
    // Delete individual, hash-matching program files only. Never recursively
    // delete the installation directory or follow user data/default-path settings.
    internal static List<string> RemoveInstallation(string folder,string expectedManifest,string selfHash,string registryRoot,string[] shortcutFolders) {
        return RemoveInstallationWithData(folder,expectedManifest,selfHash,registryRoot,shortcutFolders,null);
    }
    internal static List<string> RemoveInstallationWithData(string folder,string expectedManifest,string selfHash,string registryRoot,string[] shortcutFolders,DataApproval approval) {
        folder=CheckLocal(folder);
        DataBatch data=null;
        var notes=new List<string>();var handles=new List<FileStream>();
        var directories=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var gate=InstallationGate(folder);var pins=new List<Microsoft.Win32.SafeHandles.SafeFileHandle>();
        try {
            pins=Pin(folder);
            if(File.Exists(Path.Combine(folder,UpgradeJournal)))throw new IOException("存在未完成的升级，请先重新运行安装器恢复，再卸载。");
            var plan=RemovalPlan(folder,expectedManifest,selfHash);
            handles.AddRange(GuardApplications(folder));
            foreach(string metadata in new[]{"manifest.sha256",InstallReceipt})handles.Add(new FileStream(Path.Combine(folder,metadata),FileMode.Open,FileAccess.ReadWrite,FileShare.Read|FileShare.Delete));
            var remove=new List<string>();
            foreach(var entry in plan) {
                string path=Path.GetFullPath(Path.Combine(folder,entry.Key.Replace('/',Path.DirectorySeparatorChar)));
                if(!path.StartsWith(folder+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("卸载路径越界。");
                Plain(path);
                if(!File.Exists(path)){if(Directory.Exists(path))notes.Add("保留了与程序文件同名的目录。");continue;}
                var existing=handles.Find(h=>String.Equals(h.Name,path,StringComparison.OrdinalIgnoreCase));
                string actual;
                if(existing==null)actual=FileDigest(path);
                else using(var hash=SHA256.Create()){existing.Position=0;actual=BitConverter.ToString(hash.ComputeHash(existing)).Replace("-","").ToLowerInvariant();}
                if(actual!=entry.Value){notes.Add("保留了已修改的程序文件。");continue;}
                // Preflight all locks before deleting anything; keep handles to
                // prevent writes while permitting deletion by this process.
                if(existing==null)handles.Add(new FileStream(path,FileMode.Open,FileAccess.ReadWrite,FileShare.Read|FileShare.Delete));
                remove.Add(path);
                for(string parent=Path.GetDirectoryName(path);parent!=folder;parent=Path.GetDirectoryName(parent))directories.Add(parent);
            }
            string uninstaller=Path.Combine(folder,"Uninstall.exe");
            if(!remove.Contains(uninstaller))throw new IOException("卸载程序已被修改，请先修复安装。");
            // Review and lock every selected data file before touching the app.
            // Default preservation never discovers or opens personal data.
            if(approval!=null)data=new DataBatch(approval);
            // Keep the entry point, manifest and receipt available until the
            // program-file pass succeeds, so a partial failure can be retried.
            remove.Remove(uninstaller);
            foreach(string path in remove){Plain(path);File.Delete(path);}
            if(data!=null)data.DeleteConfirmed();
            foreach(string shortcuts in shortcutFolders)RemoveShortcuts(shortcuts,folder,notes);
            RemoveRegistration(folder,registryRoot);
            Plain(uninstaller);File.Delete(uninstaller);
            Plain(Path.Combine(folder,"manifest.sha256"));File.Delete(Path.Combine(folder,"manifest.sha256"));
            Plain(Path.Combine(folder,InstallReceipt));File.Delete(Path.Combine(folder,InstallReceipt));
        } finally {
            if(data!=null)data.Dispose();
            foreach(var handle in handles)handle.Dispose();foreach(var pin in pins)pin.Dispose();gate.ReleaseMutex();gate.Dispose();
        }
        var ordered=new List<string>(directories);ordered.Sort((a,b)=>b.Length.CompareTo(a.Length));ordered.Add(folder);
        foreach(string directory in ordered) {
            // Delete only empty known program directories. Extra files, vaults,
            // preferences, recovery material and previous backups stay untouched.
            try {Plain(directory);Directory.Delete(directory,false);}catch(IOException){}catch(UnauthorizedAccessException){}
        }
        return notes;
    }
    internal static int RunUninstaller(string[] args) {
        Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
        try {
            string current=Assembly.GetExecutingAssembly().Location;
            if(args.Length==0) {
                string folder=CheckLocal(Path.GetDirectoryName(current));ReadReceipt(folder);
                string temporary=CheckLocal(Path.Combine(Path.GetTempPath(),"OfflineKeyVault-Uninstall-"+Guid.NewGuid().ToString("N")));
                Directory.CreateDirectory(temporary);CheckLocal(temporary);
                string worker=Path.Combine(temporary,"Uninstall.exe");File.Copy(current,worker,false);
                if(FileDigest(worker)!=FileDigest(current))throw new IOException("卸载程序副本校验失败。");
                Process.Start(new ProcessStartInfo(worker,"--remove \""+folder+"\" "+Process.GetCurrentProcess().Id){UseShellExecute=false,WorkingDirectory=temporary});return 0;
            }
            int parent;
            if(args.Length!=3||args[0]!="--remove"||!Int32.TryParse(args[2],out parent))return 2;
            string destination=CheckLocal(args[1]);
            try {using(var process=Process.GetProcessById(parent))if(!process.WaitForExit(15000))throw new IOException("请先关闭旧的卸载窗口后重试。");}catch(ArgumentException){}
            string hash=FileDigest(current);RemovalPlan(destination,ProgramManifestHash,hash);
            DataApproval approval=null;
            using(var options=CreateUninstallOptions(destination,owner=>ReviewData(owner,destination),value=>approval=value))if(options.ShowDialog()!=DialogResult.OK)return 0;
            var notes=RemoveInstallationWithData(destination,ProgramManifestHash,hash,UninstallRegistry,new[]{Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs),"OfflineKeyVault")},approval);
            MessageBox.Show((approval==null?"卸载完成。密钥库和设置未删除。":"卸载完成。已删除明确勾选并确认的 "+approval.Files.Length+" 个数据文件。其余文件保留。")+(Directory.Exists(destination)?"\n保留文件的目录："+destination:"")+(notes.Count>0?"\n"+String.Join("\n",notes.ToArray()):""),"离线密钥柜",MessageBoxButtons.OK,MessageBoxIcon.Information);return 0;
        } catch(Exception error) {MessageBox.Show("卸载未完成。若已开始清理，请核对所选文件；未选择的数据不会主动删除。\n"+error.Message,"离线密钥柜",MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;}
    }
}
internal static class UninstallEntry {
    [STAThread] static int Main(string[] args) {return Installer.RunUninstaller(args);}
}
