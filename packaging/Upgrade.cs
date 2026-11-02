// Offline, journaled replacement of managed program components only.
using System;
using System.IO;
using System.Text;
using System.Reflection;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Threading;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

internal static partial class Installer {
    const string UpgradeJournal=".offline-key-vault-upgrade";
    static readonly HashSet<string> ComponentNames=new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
        "app","runtime","licenses","OfflineKeyVault.exe","manifest.sha256","build-info.json",
        "README.md","README.zh-CN.md","CONTRIBUTING.md","MACOS.md","COMPATIBILITY.md",
        "SECURITY_RECOVERY.md","requirements.txt","LICENSE","SECURITY.md","THIRD_PARTY_NOTICES.md",
        "RELEASING.md","launch.cmd","self-test.cmd","verify.cmd","START-HERE.txt"
    };
    sealed class Component {
        internal string Name;
        internal bool Old,New;
    }
    static bool Exists(string path) {return File.Exists(path)||Directory.Exists(path);}
    static void Plain(string path) {
        CheckLocal(Path.GetDirectoryName(path),true);
        if(Exists(path) && (File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("不允许链接或重解析点。");
    }
    static void MoveComponent(string source,string target) {
        for(int attempt=0;;attempt++) {
            Plain(source);Plain(target);
            if(Exists(target))throw new IOException("升级目标被其他文件占用，已停止。");
            try {if(Directory.Exists(source))Directory.Move(source,target);else File.Move(source,target);return;}
            catch(Exception error) {
                int code=error.HResult&0xffff;
                bool transient=(error is IOException || error is UnauthorizedAccessException)&&(code==5||code==32||code==33);
                if(!transient||attempt>=5||!Exists(source)||Exists(target))throw;
                Thread.Sleep(100*(1<<attempt));
            }
        }
    }
    static string FileDigest(string path) {
        Plain(path);
        using(var stream=File.OpenRead(path))using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-","").ToLowerInvariant();
    }
    static bool LooksInstalled(string path) {
        return File.Exists(Path.Combine(path,UpgradeJournal)) || (File.Exists(Path.Combine(path,"OfflineKeyVault.exe")) && File.Exists(Path.Combine(path,"manifest.sha256")) && File.Exists(Path.Combine(path,"app","launch.py")) && Directory.Exists(Path.Combine(path,"runtime")));
    }
    static Mutex InstallationGate(string path) {
        string name;
        using(var hash=SHA256.Create())name=BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(path.ToUpperInvariant()))).Replace("-","");
        var gate=new Mutex(false,@"Local\OfflineKeyVault.Install."+name);
        bool acquired=false;
        try {try{acquired=gate.WaitOne(0);}catch(AbandonedMutexException){acquired=true;}if(!acquired)throw new IOException("此目录正在安装或升级，请等待另一安装程序完成。");return gate;}
        catch {gate.Dispose();throw;}
    }
    static List<FileStream> GuardApplications(string folder) {
        var streams=new List<FileStream>();
        try {
            foreach(string relative in new[]{"OfflineKeyVault.exe","runtime/python.exe","runtime/pythonw.exe","runtime/python312.dll"}) {
                string path=Path.Combine(folder,relative);Plain(path);
                if(File.Exists(path)) streams.Add(new FileStream(path,FileMode.Open,FileAccess.ReadWrite,FileShare.Read|FileShare.Delete));
            }
            // Windows refuses a directory rename while descendants have open handles,
            // even with FILE_SHARE_DELETE. Probe runtimes, then retain only the root
            // launcher guard: legacy launchers stay alive for their Python child.
            for(int i=streams.Count-1;i>=0;i--) {
                if(!String.Equals(streams[i].Name,Path.Combine(folder,"OfflineKeyVault.exe"),StringComparison.OrdinalIgnoreCase)) {streams[i].Dispose();streams.RemoveAt(i);}
            }
            return streams;
        } catch {foreach(var stream in streams)stream.Dispose();throw new IOException("程序可能仍在运行，或文件不可写。请关闭密钥柜及其自检窗口后重试；不会强制结束进程。");}
    }
    static HashSet<string> ManagedComponents(string folder,bool allowLegacyCaches=false) {
        string manifest=Path.Combine(folder,"manifest.sha256");Plain(manifest);
        if(new FileInfo(manifest).Length>4*1024*1024)throw new IOException("程序清单过大。");
        var files=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var components=new HashSet<string>(StringComparer.OrdinalIgnoreCase){"OfflineKeyVault.exe","manifest.sha256"};
        foreach(string line in File.ReadAllLines(manifest,new UTF8Encoding(false,true))) {
            if(line.Length<67 || line.Substring(64,2)!="  ")throw new IOException("旧程序清单无效，未覆盖。");
            string relative=line.Substring(66),top=relative.Split('/')[0];
            if(!ComponentNames.Contains(top) || relative.IndexOfAny(new[]{'\\',':'})>=0 || Array.Exists(relative.Split('/'),p=>p=="."||p==".."||p.Length==0)||!files.Add(relative))throw new IOException("程序清单路径无效。");
            if(!String.Equals(FileDigest(Path.Combine(folder,relative)),line.Substring(0,64),StringComparison.Ordinal))throw new IOException("程序文件已被修改，未覆盖。请保留此目录并检查文件："+relative);
            components.Add(top);
        }
        foreach(string required in new[]{"app/launch.py","runtime/python.exe","runtime/pythonw.exe","runtime/python312._pth","build-info.json"})if(!files.Contains(required))throw new IOException("这不是完整的密钥柜安装目录。");
        // Unlisted user files are refused. Legacy interpreter caches are allowed
        // only in the old runtime and retained with the old program, never loaded
        // or copied into the newly verified runtime.
        foreach(string component in components) {
            string path=Path.Combine(folder,component);Plain(path);
            if(Directory.Exists(path))CheckManagedTree(path,folder,files,allowLegacyCaches);
            else if(!File.Exists(path))throw new IOException("程序组件缺失。");
        }
        return components;
    }
    static bool IsLegacyCache(string path,string relative,HashSet<string> files) {
        const string marker="/__pycache__/";
        if(!relative.StartsWith("runtime/Lib/",StringComparison.OrdinalIgnoreCase))return false;
        int split=relative.LastIndexOf(marker,StringComparison.OrdinalIgnoreCase);
        if(split<0)return false;
        string name=relative.Substring(split+marker.Length),source=null;
        foreach(string suffix in new[]{".cpython-312.pyc",".cpython-312.opt-1.pyc",".cpython-312.opt-2.pyc"})
            if(name.EndsWith(suffix,StringComparison.OrdinalIgnoreCase)) {source=relative.Substring(0,split)+"/"+name.Substring(0,name.Length-suffix.Length)+".py";break;}
        if(source==null||!files.Contains(source))return false;
        var info=new FileInfo(path);
        if(info.Length<16||info.Length>16*1024*1024)return false;
        // Check only the CPython 3.12 header. This is not code authentication;
        // the cache remains untrusted and is never executed by the installer.
        using(var reader=new BinaryReader(File.OpenRead(path))) {
            uint magic=reader.ReadUInt32(),flags=reader.ReadUInt32();
            return magic==0x0a0d0dcb && (flags==0||flags==1||flags==3);
        }
    }
    static void CheckManagedTree(string directory,string root,HashSet<string> files,bool allowLegacyCaches) {
        CheckLocal(directory);
        foreach(string path in Directory.GetFileSystemEntries(directory)) {
            Plain(path);
            if(Directory.Exists(path))CheckManagedTree(path,root,files,allowLegacyCaches);
            else {
                string relative=path.Substring(root.Length+1).Replace('\\','/');
                if(!files.Contains(relative)&&!(allowLegacyCaches&&IsLegacyCache(path,relative,files)))throw new IOException("程序内部目录含有额外文件，未覆盖。请将个人文件移出 app、runtime、licenses 后重试。");
            }
        }
    }
    static List<Component> ReadJournal(string destination,out string transaction) {
        string path=Path.Combine(destination,UpgradeJournal);Plain(path);
        if(new FileInfo(path).Length>16384)throw new IOException("升级记录无效。");
        string[] lines=File.ReadAllLines(path,new UTF8Encoding(false,true));Guid id;
        if(lines.Length<3 || lines.Length>ComponentNames.Count+2 || lines[0]!="OKV-UPGRADE1" || !Guid.TryParseExact(lines[1],"N",out id))throw new IOException("升级记录无效，保留现场供恢复。");
        transaction=CheckLocal(Path.Combine(Path.GetDirectoryName(destination),".offline-key-vault-upgrade-"+id.ToString("N")));
        var result=new List<Component>();var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(string line in new ArraySegment<string>(lines,2,lines.Length-2)) {
            if(line.Length<4 || line[2]!=' ' || (line.Substring(0,2)!="11" && line.Substring(0,2)!="10" && line.Substring(0,2)!="01"))throw new IOException("升级记录无效。");
            string name=line.Substring(3);
            if(!ComponentNames.Contains(name)||!names.Add(name))throw new IOException("升级记录包含无效组件。");
            result.Add(new Component{Name=name,Old=line[0]=='1',New=line[1]=='1'});
        }
        return result;
    }
    static void RecoverUpgrade(string destination,bool guardOld=true) {
        if(!File.Exists(Path.Combine(destination,UpgradeJournal)))return;
        string transaction;var plan=ReadJournal(destination,out transaction);
        var pins=new List<SafeFileHandle>();var txPins=new List<SafeFileHandle>();var guards=new List<FileStream>();
        try {
            pins=Pin(destination);txPins=Pin(transaction);
            if(guardOld)guards=GuardApplications(Path.Combine(transaction,"old"));
            string old=CheckLocal(Path.Combine(transaction,"old")),fresh=CheckLocal(Path.Combine(transaction,"new"));
            // Check every state before undoing any rename. Never delete a component.
            foreach(var part in plan) {
                string current=Path.Combine(destination,part.Name),backup=Path.Combine(old,part.Name),staged=Path.Combine(fresh,part.Name);
                Plain(current);Plain(backup);Plain(staged);
                bool c=Exists(current),b=Exists(backup),s=Exists(staged);
                bool valid=part.Old ? ((!b&&c&&s==part.New)||(b&&((part.New&&c!=s)||(!part.New&&!c&&!s)))) : (!b&&part.New&&c!=s);
                if(!valid)throw new IOException("升级现场不完整，未删除或覆盖文件；请保留升级备份目录。");
            }
            plan.Reverse();
            foreach(var part in plan) {
                string current=Path.Combine(destination,part.Name),backup=Path.Combine(old,part.Name),staged=Path.Combine(fresh,part.Name);
                if(part.New&&!Exists(staged))MoveComponent(current,staged);
                if(part.Old&&Exists(backup))MoveComponent(backup,current);
            }
            File.Move(Path.Combine(destination,UpgradeJournal),Path.Combine(transaction,"rolled-back"));
        } finally {foreach(var g in guards)g.Dispose();foreach(var p in txPins)p.Dispose();foreach(var p in pins)p.Dispose();}
    }
    static void ApplyUpgrade(string destination,string stage,Action<string> verify,Action<int> checkpoint) {
        var oldComponents=ManagedComponents(destination,true);var newComponents=ManagedComponents(stage);
        var names=new SortedSet<string>(oldComponents,StringComparer.OrdinalIgnoreCase);names.UnionWith(newComponents);
        var plan=new List<Component>();
        foreach(string name in names) {
            if(!oldComponents.Contains(name)&&Exists(Path.Combine(destination,name)))throw new IOException("新增程序文件与原有文件同名，未覆盖："+name);
            plan.Add(new Component{Name=name,Old=oldComponents.Contains(name),New=newComponents.Contains(name)});
        }
        string id=Guid.NewGuid().ToString("N");
        string transaction=Path.Combine(Path.GetDirectoryName(destination),".offline-key-vault-upgrade-"+id);
        Directory.CreateDirectory(transaction);CheckLocal(transaction);
        string old=Path.Combine(transaction,"old"),fresh=Path.Combine(transaction,"new");
        Directory.CreateDirectory(old);MoveComponent(stage,fresh);
        var pins=new List<SafeFileHandle>();var txPins=new List<SafeFileHandle>();
        try {
            pins=Pin(destination);txPins=Pin(transaction);
            var journal=new StringBuilder("OKV-UPGRADE1\n"+id+"\n");
            foreach(var part in plan)journal.Append((part.Old?"1":"0")+(part.New?"1":"0")+" "+part.Name+"\n");
            string pending=Path.Combine(transaction,"journal-pending");
            using(var stream=new FileStream(pending,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)) {
                byte[] bytes=Encoding.UTF8.GetBytes(journal.ToString());stream.Write(bytes,0,bytes.Length);stream.Flush(true);
            }
            File.Move(pending,Path.Combine(destination,UpgradeJournal));
            try {
                int moves=0;
                foreach(var part in plan) {
                    if(part.Old) {MoveComponent(Path.Combine(destination,part.Name),Path.Combine(old,part.Name));if(checkpoint!=null)checkpoint(++moves);}
                    if(part.New) {MoveComponent(Path.Combine(fresh,part.Name),Path.Combine(destination,part.Name));if(checkpoint!=null)checkpoint(++moves);}
                }
                verify(destination);
                File.Move(Path.Combine(destination,UpgradeJournal),Path.Combine(transaction,"committed"));
            } catch(Exception error) {
                try {RecoverUpgrade(destination,false);}catch(Exception recovery) {throw new IOException("升级中断。请关闭程序并重新运行安装器以恢复；旧程序备份未删除。",new AggregateException(error,recovery));}
                throw new IOException("升级未完成，已恢复原程序；密钥库与设置未改动。",error);
            }
        } finally {foreach(var p in txPins)p.Dispose();foreach(var p in pins)p.Dispose();}
    }
    static string ReadShortcutTarget(string path) {
        Plain(path);if(!File.Exists(path))return "";
        object shell=null,link=null;
        try {
            Type type=Type.GetTypeFromProgID("WScript.Shell",true);shell=Activator.CreateInstance(type);
            link=type.InvokeMember("CreateShortcut",BindingFlags.InvokeMethod,null,shell,new object[]{path});
            return (string)link.GetType().InvokeMember("TargetPath",BindingFlags.GetProperty,null,link,null);
        } finally {if(link!=null)Marshal.FinalReleaseComObject(link);if(shell!=null)Marshal.FinalReleaseComObject(shell);}
    }
    static void UpdateExistingShortcuts(string folder,string installed,List<string> issues) {
        try {
            if(!Directory.Exists(folder))return;CheckLocal(folder);
            foreach(string path in Directory.GetFiles(folder,"*.lnk")) {
                try {if(String.Equals(ReadShortcutTarget(path),Path.Combine(installed,"OfflineKeyVault.exe"),StringComparison.OrdinalIgnoreCase))Shortcut(folder,installed,Path.GetFileNameWithoutExtension(path));}
                catch(Exception error){issues.Add(error.Message);}
            }
        } catch(Exception error){issues.Add(error.Message);}
    }
}
