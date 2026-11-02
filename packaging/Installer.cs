using System;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using Microsoft.Win32.SafeHandles;

internal static partial class Installer {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    static string DefaultPath() {
        foreach(string link in new[]{Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),"离线密钥柜.lnk"),Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs),"OfflineKeyVault","离线密钥柜.lnk")}) {
            try { string target=ReadShortcutTarget(link); if(String.Equals(Path.GetFileName(target),"OfflineKeyVault.exe",StringComparison.OrdinalIgnoreCase)) {string folder=CheckLocal(Path.GetDirectoryName(target));if(LooksInstalled(folder))return folder;} } catch {}
        }
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "OfflineKeyVault");
    }
    static string CheckLocal(string path, bool allowRoot=false) {
        if (String.IsNullOrWhiteSpace(path) || path.Length<3 || !Char.IsLetter(path[0]) || path[1]!=':' || (path[2]!='\\'&&path[2]!='/') || path.StartsWith(@"\\") || path.StartsWith("//"))
            throw new IOException("请选择普通本地磁盘的完整路径，不允许网络或设备路径。");
        string full = Path.GetFullPath(path);
        string anchor = Path.GetPathRoot(full);
        if(full.Length>anchor.Length)full=full.TrimEnd(Path.DirectorySeparatorChar);
        if (!allowRoot && full.Length <= anchor.Length) throw new IOException("请选择磁盘中的新文件夹，不能安装到盘符根目录。");
        foreach (string part in full.Substring(anchor.Length).Split(new[]{Path.DirectorySeparatorChar},StringSplitOptions.RemoveEmptyEntries)) {
            string stem = part.Split('.')[0].ToUpperInvariant();
            if (part.Length == 0 || part.EndsWith(".") || part.EndsWith(" ") || part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
                stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" ||
                (stem.Length == 4 && (stem.StartsWith("COM") || stem.StartsWith("LPT")) && Char.IsDigit(stem[3])))
                throw new IOException("安装路径包含设备名或歧义字符。");
        }
        DriveInfo drive = new DriveInfo(anchor);
        if (drive.DriveType != DriveType.Fixed && drive.DriveType != DriveType.Removable)
            throw new IOException("仅允许本地固定磁盘或移动磁盘。");
        for (string item = full; !String.IsNullOrEmpty(item); item = Path.GetDirectoryName(item)) {
            if (Directory.Exists(item) || File.Exists(item)) {
                if ((File.GetAttributes(item) & FileAttributes.ReparsePoint) != 0) throw new IOException("不允许链接或重解析点路径。");
                if (!Directory.Exists(item)) throw new IOException("路径组件不是目录。");
            }
        }
        return full;
    }
    static List<SafeFileHandle> Pin(string path) {
        var chain = new List<string>();
        for (string item=path; !String.IsNullOrEmpty(item); item=Path.GetDirectoryName(item)) chain.Add(item);
        chain.Reverse(); var handles=new List<SafeFileHandle>();
        try {
            foreach (string item in chain) {
                var handle=CreateFile(item, 1, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
                if (handle.IsInvalid) { handle.Dispose(); throw new IOException("无法锁定安装目录，请检查访问权限。"); }
                handles.Add(handle);
                if ((File.GetAttributes(item) & FileAttributes.ReparsePoint)!=0) throw new IOException("不允许重解析点。");
            }
            return handles;
        } catch { foreach(var h in handles) h.Dispose(); throw; }
    }
    internal static Process StartChecked(Func<Process> launch) {
        for(int attempt=0;;attempt++) {
            try {return launch();}
            catch(System.ComponentModel.Win32Exception error) {
                if((error.NativeErrorCode!=32&&error.NativeErrorCode!=33)||attempt>=5)throw;
                System.Threading.Thread.Sleep(100*(1<<attempt));
            }
        }
    }
    static void Verify(string folder, string mode) {
        var info=new ProcessStartInfo(Path.Combine(folder,"OfflineKeyVault.exe"),mode);
        info.UseShellExecute=false; info.CreateNoWindow=true;
        info.WorkingDirectory=folder; info.RedirectStandardOutput=true; info.RedirectStandardError=true;
        using(var process=StartChecked(()=>Process.Start(info))) {
            process.OutputDataReceived+=(sender,e)=>{}; process.ErrorDataReceived+=(sender,e)=>{};
            process.BeginOutputReadLine(); process.BeginErrorReadLine();
            if (!process.WaitForExit(180000)) { process.Kill(); throw new IOException("安装包自检超时。"); }
            if (process.ExitCode!=0) throw new IOException("安装包自检失败，未创建快捷方式。");
        }
    }
    static FileStream OpenNewOutput(string output) {
        // A temporarily unavailable destination can deny creation before a file exists.
        // Retry only opening a new file, never truncate an existing/partial output.
        for(int attempt=0;;attempt++) {
            CheckLocal(Path.GetDirectoryName(output));
            if(File.Exists(output)||Directory.Exists(output)) throw new IOException("目标文件已存在，未覆盖。");
            try { return new FileStream(output,FileMode.CreateNew,FileAccess.Write,FileShare.None); }
            catch(Exception error) {
                int code=error.HResult & 0xffff;
                bool transient=(error is UnauthorizedAccessException && code==5) ||
                    (error is IOException && (code==5||code==32||code==33));
                if(!transient || attempt>=5) throw;
                System.Threading.Thread.Sleep(100 * (1 << attempt));
            }
        }
    }
    static string Extract(string destination, bool fullTest) {
        destination=CheckLocal(destination);
        string parent=CheckLocal(Path.GetDirectoryName(destination),true);
        Directory.CreateDirectory(parent); CheckLocal(parent,true);
        var pins=Pin(parent);
        System.Threading.Mutex gate=null;
        var guards=new List<FileStream>();
        string stage=Path.Combine(parent, ".offline-key-vault-install-"+Guid.NewGuid().ToString("N"));
        try {
            gate=InstallationGate(destination);
            if(Directory.Exists(destination)) {
                if(!LooksInstalled(destination))throw new IOException("此目录不是可识别的密钥柜安装目录，未改动其中的文件。");
                guards=GuardApplications(destination);
                bool recovering=File.Exists(Path.Combine(destination,UpgradeJournal));
                RecoverUpgrade(destination);
                if(recovering){foreach(var h in guards)h.Dispose();guards=GuardApplications(destination);}
            }
            Directory.CreateDirectory(stage);
            var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using(var input=Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip"))
            using(var zip=new ZipArchive(input,ZipArchiveMode.Read)) {
                long total=0;
                foreach(var entry in zip.Entries) {
                    const string prefix="OfflineKeyVault/";
                    if (!entry.FullName.StartsWith(prefix,StringComparison.Ordinal) || entry.FullName.EndsWith("/")) throw new IOException("安装包路径不合法。");
                    string relative=entry.FullName.Substring(prefix.Length);
                    if (relative.IndexOf('\\')>=0 || relative.IndexOf(':')>=0 || relative.StartsWith("/") || Array.Exists(relative.Split('/'),p=>p==".."||p=="."||p.Length==0))
                        throw new IOException("安装包包含不安全路径。");
                    string output=Path.GetFullPath(Path.Combine(stage,relative.Replace('/',Path.DirectorySeparatorChar)));
                    if (!output.StartsWith(stage+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase) || !seen.Add(output)) throw new IOException("安装包路径重复或越界。");
                    total+=entry.Length;
                    if (entry.Length>128*1024*1024 || total>512L*1024*1024 || seen.Count>10000) throw new IOException("安装包超出资源上限。");
                    Directory.CreateDirectory(Path.GetDirectoryName(output)); CheckLocal(Path.GetDirectoryName(output));
                    var outputPins=Pin(Path.GetDirectoryName(output));
                    try {
                        // Publish each complete file atomically; never expose a half-written DLL.
                        string pending=Path.Combine(stage,".okv-extract-"+Guid.NewGuid().ToString("N")+".tmp");
                        using(var source=entry.Open())using(var stream=OpenNewOutput(pending)) {
                            source.CopyTo(stream);
                            if(stream.Length!=entry.Length)throw new IOException("安装包文件长度不符。");
                        }
                        MoveComponent(pending,output);
                    } finally { foreach(var h in outputPins) h.Dispose(); }
                }
            }
            Verify(stage, "--verify");
            if (fullTest) Verify(stage,"--self-test");
            if(Directory.Exists(destination)) ApplyUpgrade(destination,stage,folder=>Verify(folder,"--verify"),null);
            else Directory.Move(stage,destination);
            return destination;
        } finally { foreach(var h in guards) h.Dispose(); if(gate!=null){gate.ReleaseMutex();gate.Dispose();}foreach(var h in pins) h.Dispose(); }
    }
    static void Shortcut(string folder,string installed,string name) {
        folder=CheckLocal(folder);
        Directory.CreateDirectory(folder);
        var pins=Pin(folder);
        object shell=null,link=null;
        try {
            string path=Path.Combine(folder,name+".lnk");
            bool replacing=File.Exists(path);
            if(Directory.Exists(path))throw new IOException("快捷方式名称被目录占用："+name);
            if(replacing && !String.Equals(ReadShortcutTarget(path),Path.Combine(installed,"OfflineKeyVault.exe"),StringComparison.OrdinalIgnoreCase))
                throw new IOException("同名快捷方式指向其他程序或安装目录，未覆盖："+name);
            string temporary=Path.Combine(folder,".okv-shortcut-"+Guid.NewGuid().ToString("N")+".lnk");
            Type type=Type.GetTypeFromProgID("WScript.Shell",true);
            shell=Activator.CreateInstance(type);
            link=type.InvokeMember("CreateShortcut",BindingFlags.InvokeMethod,null,shell,new object[]{temporary});
            Type lt=link.GetType();
            lt.InvokeMember("TargetPath",BindingFlags.SetProperty,null,link,new object[]{Path.Combine(installed,"OfflineKeyVault.exe")});
            lt.InvokeMember("WorkingDirectory",BindingFlags.SetProperty,null,link,new object[]{installed});
            lt.InvokeMember("Description",BindingFlags.SetProperty,null,link,new object[]{"Offline Key Vault"});
            string iconLocation=Path.Combine(installed,"OfflineKeyVault.exe")+",0";
            lt.InvokeMember("IconLocation",BindingFlags.SetProperty,null,link,new object[]{iconLocation});
            lt.InvokeMember("Save",BindingFlags.InvokeMethod,null,link,null);
            Marshal.FinalReleaseComObject(link);link=null;
            if(!String.Equals(ReadShortcutTarget(temporary),Path.Combine(installed,"OfflineKeyVault.exe"),StringComparison.OrdinalIgnoreCase))throw new IOException("快捷方式保存校验失败。");
            if(replacing)File.Replace(temporary,path,null);else File.Move(temporary,path);
            link=type.InvokeMember("CreateShortcut",BindingFlags.InvokeMethod,null,shell,new object[]{path});lt=link.GetType();
            if (!File.Exists(path)) throw new IOException("快捷方式未创建。");
            object target=lt.InvokeMember("TargetPath",BindingFlags.GetProperty,null,link,null);
            if (!String.Equals((string)target,Path.Combine(installed,"OfflineKeyVault.exe"),StringComparison.OrdinalIgnoreCase)) throw new IOException("快捷方式目标校验失败。");
            object icon=lt.InvokeMember("IconLocation",BindingFlags.GetProperty,null,link,null);
            if (!String.Equals((string)icon,iconLocation,StringComparison.OrdinalIgnoreCase)) throw new IOException("快捷方式图标校验失败。");
        } finally {
            if(link!=null) Marshal.FinalReleaseComObject(link);
            if(shell!=null) Marshal.FinalReleaseComObject(shell);
            foreach(var h in pins)h.Dispose();
        }
    }
    // Content-sized controls stay readable with larger fonts and narrow windows.
    static TableLayoutPanel Column() {
        return new TableLayoutPanel {Dock=DockStyle.Top,AutoSize=true,ColumnCount=1,Padding=new Padding(24),GrowStyle=TableLayoutPanelGrowStyle.AddRows};
    }
    static void Row(TableLayoutPanel layout,Control control) {
        control.Dock=DockStyle.Top;control.Margin=new Padding(0,6,0,6);
        layout.Controls.Add(control,0,layout.RowCount++);
    }
    static void WrapIn(TableLayoutPanel layout,Label label) {
        label.AutoSize=true;
        layout.SizeChanged+=(sender,e)=>label.MaximumSize=new Size(Math.Max(100,layout.ClientSize.Width-layout.Padding.Horizontal),0);
        Row(layout,label);
    }
    static FlowLayoutPanel Buttons(params Button[] buttons) {
        var row=new FlowLayoutPanel {Dock=DockStyle.Bottom,AutoSize=true,FlowDirection=FlowDirection.RightToLeft,Padding=new Padding(18,8,18,18)};
        foreach(var button in buttons) {button.AutoSize=true;button.MinimumSize=new Size(120,38);button.Margin=new Padding(6);row.Controls.Add(button);}
        return row;
    }
    static void Theme(Control parent,Button primary) {
        parent.BackColor=Color.White;parent.ForeColor=Color.FromArgb(37,37,45);
        foreach(Control control in parent.Controls) {
            Theme(control,primary);
            var button=control as Button;
            if(button!=null) {
                button.FlatStyle=FlatStyle.Flat;button.FlatAppearance.BorderSize=1;
                bool accent=button==primary;
                button.BackColor=accent?Color.FromArgb(220,53,69):Color.FromArgb(240,241,245);
                button.ForeColor=accent?Color.White:Color.FromArgb(37,37,45);
                button.FlatAppearance.BorderColor=accent?Color.FromArgb(220,53,69):Color.FromArgb(201,205,216);
                button.FlatAppearance.MouseOverBackColor=accent?Color.FromArgb(197,45,61):Color.FromArgb(229,232,239);
            } else if(control is TextBox || control is ListBox || control is ComboBox) control.BackColor=Color.FromArgb(250,251,252);
        }
    }
    // Both windows use the same drive + folder editor. The hidden model keeps
    // existing validation authoritative; the UI must never substitute a valid
    // stale path when the user's new input is incomplete or unsafe.
    internal sealed class LocationEditor : TableLayoutPanel {
        internal readonly ComboBox Drive=new ComboBox {Name="InstallDrive",AccessibleName="磁盘",DropDownStyle=ComboBoxStyle.DropDownList,Dock=DockStyle.Fill};
        internal readonly TextBox Folder=new TextBox {Name="InstallFolder",AccessibleName="具体路径",Dock=DockStyle.Fill};
        readonly TextBox model; bool syncing;
        internal LocationEditor(TextBox value,Button browse) {
            model=value;AutoSize=true;ColumnCount=3;RowCount=2;Dock=DockStyle.Top;
            ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,108));
            ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
            ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            Controls.Add(new Label {Text="磁盘",AutoSize=true,Margin=new Padding(0,0,0,8)},0,0);
            Controls.Add(new Label {Text="具体路径",AutoSize=true,Margin=new Padding(0,0,0,8)},1,0);
            Drive.Margin=new Padding(0,3,12,3);Folder.Margin=new Padding(0,3,12,3);
            browse.AutoSize=true;browse.MinimumSize=new Size(96,32);browse.Margin=new Padding(0);
            Controls.Add(Drive,0,1);Controls.Add(Folder,1,1);Controls.Add(browse,2,1);
            foreach(var drive in DriveInfo.GetDrives()) {
                try { if((drive.DriveType==DriveType.Fixed||drive.DriveType==DriveType.Removable)&&drive.IsReady)Drive.Items.Add(drive.Name); } catch(IOException) {} catch(UnauthorizedAccessException) {}
            }
            Drive.SelectedIndexChanged+=(s,e)=>Publish();Folder.TextChanged+=(s,e)=>Publish();
            model.TextChanged+=(s,e)=>ReadModel();model.EnabledChanged+=(s,e)=>Enabled=model.Enabled;
            ReadModel();
        }
        void ReadModel() {
            if(syncing)return;syncing=true;
            try {
                string text=model.Text.Replace('/','\\');
                if(text.Length>=3&&Char.IsLetter(text[0])&&text[1]==':'&&text[2]=='\\') {
                    string root=text.Substring(0,3).ToUpperInvariant();int index=Drive.FindStringExact(root);
                    Drive.SelectedIndex=index;Folder.Text=index>=0?text.Substring(3):text;
                } else Folder.Text=text;
            } finally {syncing=false;}
        }
        void Publish() {
            if(syncing)return;
            string text=Folder.Text.Replace('/','\\');
            // Pasting a complete path also changes the selected drive. UNC,
            // rooted and drive-relative input stays invalid, never rewritten.
            if(text.Length>=3&&Char.IsLetter(text[0])&&text[1]==':'&&text[2]=='\\') {model.Text=text;ReadModel();return;}
            syncing=true;
            try {model.Text=text.StartsWith("\\")||text.IndexOf(':')>=0||Drive.SelectedItem==null?String.Empty:(string)Drive.SelectedItem+text;}
            finally {syncing=false;}
        }
    }
    static void WizardLayout(Form form,Label title,Label intro,Label label,TextBox path,Button browse,Label status,CheckBox desktop,CheckBox menu,Label note,Button install,Button cancel) {
        form.SuspendLayout();form.Controls.Clear();form.FormBorderStyle=FormBorderStyle.FixedDialog;form.MaximizeBox=false;
        form.ClientSize=new Size(720,460);
        form.AutoScaleDimensions=new SizeF(96,96);form.AutoScaleMode=AutoScaleMode.Dpi;
        var body=new Panel {Dock=DockStyle.Fill};var column=Column();body.Controls.Add(column);
        var footer=Buttons(install,cancel);form.Controls.Add(body);form.Controls.Add(footer);
        WrapIn(column,title);title.Margin=new Padding(0,0,0,8);
        WrapIn(column,intro);intro.Margin=new Padding(0,0,0,22);
        WrapIn(column,label);label.Font=new Font(form.Font,FontStyle.Bold);label.Margin=new Padding(0,0,0,12);
        Row(column,new LocationEditor(path,browse));
        WrapIn(column,status);status.MinimumSize=new Size(0,26);status.Margin=new Padding(0,6,0,14);
        var choices=new FlowLayoutPanel {AutoSize=true,WrapContents=true};
        desktop.AutoSize=true;menu.AutoSize=true;desktop.Margin=new Padding(0,4,24,4);menu.Margin=new Padding(0,4,0,4);
        choices.Controls.AddRange(new Control[]{desktop,menu});Row(column,choices);
        WrapIn(column,note);note.Margin=new Padding(0,14,0,0);
        Theme(form,install);intro.ForeColor=note.ForeColor=Color.FromArgb(100,105,118);
        footer.BackColor=Color.FromArgb(247,248,250);
        form.CancelButton=cancel;
        form.Shown+=(s,e)=>{
            // Fit the content, not an arbitrary tall window. Only small screens
            // need scrolling; the action row always remains visible.
            int chrome=form.Height-form.ClientSize.Height;
            int height=column.PreferredSize.Height+footer.Height;
            int available=Screen.FromControl(form).WorkingArea.Height-chrome-24;
            form.ClientSize=new Size(form.ClientSize.Width,Math.Min(height,available));
            body.AutoScroll=height>available;
        };
        form.ResumeLayout(true);
    }
    static string ChooseFolder(Form owner,string initial) {
        string selected=null;
        using(var picker=CreateFolderPicker(owner,BrowseStart(initial),value=>selected=value))picker.ShowDialog(owner);
        return selected;
    }
    static string BrowseStart(string initial) {
        try {
            string folder=CheckLocal(initial,true);
            while(!Directory.Exists(folder))folder=Path.GetDirectoryName(folder);
            return CheckLocal(folder,true);
        } catch {return Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);}
    }
    static Form CreateFolderPicker(Form owner,string initial,Action<string> selected) {
        var picker=new Form {Text="选择本地父目录",ClientSize=new Size(680,560),MinimumSize=new Size(600,460),StartPosition=FormStartPosition.CenterParent,Font=owner.Font,AutoScaleDimensions=new SizeF(96,96),AutoScaleMode=AutoScaleMode.Dpi};
        picker.Icon=owner.Icon;
        var path=new TextBox {Left=20,Top=20,Width=480,Text=initial};
        var up=new Button {Text="上级",Left=510,Top=18,Width=90};
        var listing=new ListBox {Left=20,Top=94,Width=580,Height=290};
        var note=new Label {Left=20,Top=390,Width=580,Height=30};
        var choose=new Button {Name="ChooseDirectory",Text="选择此目录",Left=470,Top=432,Width=130};
        string current=null;
        Action refresh=()=>{try{
            string folder=CheckLocal(path.Text,true);
            if(!Directory.Exists(folder))throw new IOException();
            listing.Items.Clear();current=folder;
            foreach(string child in Directory.EnumerateDirectories(folder)){
                try{if((File.GetAttributes(child)&FileAttributes.ReparsePoint)==0)listing.Items.Add(Path.GetFileName(child));}catch(IOException){}
                if(listing.Items.Count>=10000)break;
            }
            note.Text="仅列出本地目录，不加载系统云盘扩展。";
            choose.Enabled=true;
        }catch{current=null;listing.Items.Clear();choose.Enabled=false;note.Text="路径未完成、不可访问或不属于本地目录。";}};
        var delay=new Timer {Interval=300};
        delay.Tick+=(sender,e)=>{delay.Stop();refresh();};
        path.TextChanged+=(sender,e)=>{current=null;listing.Items.Clear();choose.Enabled=false;delay.Stop();delay.Start();};
        up.Click+=(sender,e)=>{if(current!=null){string parent=Path.GetDirectoryName(current);if(parent!=null)path.Text=parent;}};
        listing.DoubleClick+=(sender,e)=>{if(current!=null&&listing.SelectedItem!=null)path.Text=Path.Combine(current,(string)listing.SelectedItem);};
        choose.Click+=(sender,e)=>{try{string folder=CheckLocal(path.Text,true);if(!Directory.Exists(folder))throw new IOException();selected(folder);picker.Close();}catch{note.Text="请选择有效的本地目录。";}};
        picker.FormClosed+=(sender,e)=>{delay.Stop();delay.Dispose();};
        var layout=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=1,RowCount=4,Padding=new Padding(24)};
        for(int i=0;i<4;i++)layout.RowStyles.Add(new RowStyle(i==1?SizeType.Percent:SizeType.AutoSize,i==1?100:0));
        var nav=new LocationEditor(path,up);nav.Margin=new Padding(0,0,0,16);
        listing.Dock=DockStyle.Fill;listing.HorizontalScrollbar=true;listing.IntegralHeight=false;listing.Margin=new Padding(0,0,0,12);
        note.AutoSize=true;note.Dock=DockStyle.Top;
        layout.SizeChanged+=(sender,e)=>note.MaximumSize=new Size(Math.Max(100,layout.ClientSize.Width-40),0);
        layout.Controls.Add(nav,0,0);layout.Controls.Add(listing,0,1);layout.Controls.Add(note,0,2);
        var footer=Buttons(choose);layout.Controls.Add(footer,0,3);
        picker.Controls.Add(layout);Theme(picker,choose);refresh();return picker;
    }
    [STAThread] static int Main(string[] args) {
        if(args.Length==2 && args[0]=="--test-install") {
            Console.SetError(new StreamWriter(Console.OpenStandardError(),new UTF8Encoding(false)){AutoFlush=true});
            try {
                string testDestination=CheckLocal(args[1]);
                string testParent=Path.GetDirectoryName(testDestination);
                if(Exists(testDestination)||Exists(Path.Combine(testParent,"shortcut-test"))||Exists(Path.Combine(testParent,"unrelated-folder")))
                    throw new IOException("测试模式仅允许全新的隔离目录，不能用于已有安装或已有测试文件夹。");
                string dest=Extract(args[1],true);
                // Test artifacts belong outside the immutable application payload.
                string links=Path.Combine(Path.GetDirectoryName(dest),"shortcut-test");
                Shortcut(links,dest,"OfflineKeyVault-Test");
                Directory.CreateDirectory(Path.Combine(dest,"vaults"));
                string vault=Path.Combine(dest,"vaults","synthetic.okv"),settings=Path.Combine(dest,".offline-key-vault-preferences.json");
                File.WriteAllText(vault,"synthetic encrypted vault placeholder");File.WriteAllText(settings,"synthetic settings placeholder");
                string originalVault=FileDigest(vault),originalSettings=FileDigest(settings);
                Extract(dest,false);
                Shortcut(links,dest,"OfflineKeyVault-Test");
                if(FileDigest(vault)!=originalVault||FileDigest(settings)!=originalSettings)throw new IOException("升级改变了用户数据。");
                Verify(dest,"--verify");
                // Ordinary unrelated folders must still never be overwritten.
                string unrelated=Path.Combine(Path.GetDirectoryName(dest),"unrelated-folder");Directory.CreateDirectory(unrelated);
                File.WriteAllText(Path.Combine(unrelated,"keep.txt"),"preserve unrelated content");
                bool rejected=false;
                try { Extract(unrelated,false); } catch(IOException) { rejected=true; }
                if(!rejected || File.ReadAllText(Path.Combine(unrelated,"keep.txt"))!="preserve unrelated content") return 2;
                return 0;
            } catch(Exception error) {Console.Error.WriteLine("Installer test failed: "+error.GetType().Name+" (0x"+error.HResult.ToString("X8")+"): "+error.Message+"\nCause: "+error.GetBaseException().Message);return 1;}
        }
        if(args.Length!=0)return 2;
        Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(CreateWizard());return 0;
    }
    static Form CreateWizard() {
        var form=new Form {Text="离线密钥柜 · 安装",ClientSize=new Size(650,400),StartPosition=FormStartPosition.CenterScreen,FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,Font=new Font("Microsoft YaHei UI",10)};
        form.Icon=Icon.ExtractAssociatedIcon(Application.ExecutablePath);
        var title=new Label {Text="安装离线密钥柜",Left=26,Top=24,Width=590,Height=40,Font=new Font("Microsoft YaHei UI",20,FontStyle.Bold)};
        var intro=new Label {Text="完全离线，无需管理员权限。已有密钥库与设置会保留。",Left=28,Top=76,Width=590,Height=28};
        var label=new Label {Text="安装位置",Left=28,Top=119,Width=590,Height=28};
        var path=new TextBox {Left=28,Top=151,Width=470,Text=DefaultPath()};
        var browse=new Button {Text="浏览…",Left=506,Top=148,Width=112,Height=30};
        browse.Click+=(sender,e)=>{string chosen=ChooseFolder(form,path.Text);if(chosen!=null)path.Text=LooksInstalled(chosen)?chosen:Path.Combine(chosen,"OfflineKeyVault");};
        var status=new Label {Left=28,Top=186,Width=590,Height=40,ForeColor=Color.DimGray};
        var desktop=new CheckBox {Text="创建 / 更新桌面快捷方式",Left=28,Top=233,Width=260,Checked=true};
        var menu=new CheckBox {Text="创建 / 更新开始菜单快捷方式",Left=315,Top=233,Width=280,Checked=true};
        var note=new Label {Text="选择原安装目录即可升级，旧程序会保留为回滚备份。\n请先关闭密钥柜，避免使用云同步目录。",Left=28,Top=276,Width=590,Height=48};
        var install=new Button {Text="安装",Left=492,Top=342,Width=126,Height=38,BackColor=Color.FromArgb(220,53,69),ForeColor=Color.White,FlatStyle=FlatStyle.Flat};
        var cancel=new Button {Text="取消",Left=350,Top=342,Width=126,Height=38};
        Action check=()=>{try{string value=CheckLocal(path.Text);bool upgrade=LooksInstalled(value);install.Enabled=upgrade||!Directory.Exists(value);install.Text=upgrade?"升级":"安装";status.ForeColor=install.Enabled?Color.FromArgb(73,105,91):Color.FromArgb(180,45,60);status.Text=upgrade?"检测到已有安装，将在原目录升级并保留个人数据。":Directory.Exists(value)?"此文件夹已有其他内容，请选择空的新路径或原安装目录。":"路径可用，将在安装时创建文件夹。";}catch{install.Enabled=false;status.ForeColor=Color.FromArgb(180,45,60);status.Text="请选择本地磁盘，并输入有效的文件夹路径。";}};
        path.TextChanged+=(sender,e)=>check(); check();
        cancel.Click+=(sender,e)=>form.Close();
        install.Click+=(sender,e)=>{
            string destination=null;
            try {
                install.Enabled=false;path.Enabled=false;browse.Enabled=false;desktop.Enabled=false;menu.Enabled=false;cancel.Enabled=false;
                status.Text="正在验证与安装 / 升级，请稍候…";form.Refresh();
                destination=Extract(path.Text,false);
                RegisterInstallation(destination);
                var issues=new List<string>();
                UpdateExistingShortcuts(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),destination,issues);
                UpdateExistingShortcuts(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs),"OfflineKeyVault"),destination,issues);
                if(desktop.Checked)try{Shortcut(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),destination,"离线密钥柜");}catch(Exception error){issues.Add(error.Message);}
                if(menu.Checked)try{Shortcut(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs),"OfflineKeyVault"),destination,"离线密钥柜");}catch(Exception error){issues.Add(error.Message);}
                MessageBox.Show(form,"程序已安装到：\n"+destination+(issues.Count==0?"\n快捷方式按所选项创建。":"\n部分快捷方式未创建：\n"+String.Join("\n",issues.ToArray()))+"\n可直接打开目录中的 OfflineKeyVault.exe。","安装完成",MessageBoxButtons.OK,issues.Count==0?MessageBoxIcon.Information:MessageBoxIcon.Warning);
                form.Close();
            }catch(Exception error){MessageBox.Show(form,error.Message,"安装未完成",MessageBoxButtons.OK,MessageBoxIcon.Error);}
            finally{if(!form.IsDisposed){path.Enabled=true;browse.Enabled=true;desktop.Enabled=true;menu.Enabled=true;cancel.Enabled=true;check();}}
        };
        WizardLayout(form,title,intro,label,path,browse,status,desktop,menu,note,install,cancel);
        check();return form;
    }
}
