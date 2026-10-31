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

internal static class Installer {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    static string DefaultPath() { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "OfflineKeyVault"); }
    static string CheckLocal(string path, bool allowRoot=false) {
        if (String.IsNullOrWhiteSpace(path) || !Path.IsPathRooted(path) || path.StartsWith(@"\\") || path.StartsWith("//"))
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
    static void Verify(string folder, string mode) {
        var info=new ProcessStartInfo(Path.Combine(folder,"OfflineKeyVault.exe"),mode);
        info.UseShellExecute=false; info.CreateNoWindow=true;
        info.WorkingDirectory=folder; info.RedirectStandardOutput=true; info.RedirectStandardError=true;
        using(var process=Process.Start(info)) {
            process.OutputDataReceived+=(sender,e)=>{}; process.ErrorDataReceived+=(sender,e)=>{};
            process.BeginOutputReadLine(); process.BeginErrorReadLine();
            if (!process.WaitForExit(180000)) { process.Kill(); throw new IOException("安装包自检超时。"); }
            if (process.ExitCode!=0) throw new IOException("安装包自检失败，未创建快捷方式。");
        }
    }
    static string Extract(string destination, bool fullTest) {
        destination=CheckLocal(destination);
        if (Directory.Exists(destination) || File.Exists(destination)) throw new IOException("目标已存在。请选择新的安装文件夹，避免覆盖旧程序和密钥。");
        string parent=CheckLocal(Path.GetDirectoryName(destination),true);
        Directory.CreateDirectory(parent); CheckLocal(parent,true);
        var pins=Pin(parent);
        string stage=Path.Combine(parent, ".offline-key-vault-install-"+Guid.NewGuid().ToString("N"));
        try {
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
                    using(var source=entry.Open()) using(var stream=new FileStream(output,FileMode.CreateNew,FileAccess.Write,FileShare.None)) source.CopyTo(stream);
                }
            }
            Verify(stage, "--verify");
            if (fullTest) Verify(stage,"--self-test");
            // No overwrite or recursive removal. A failed attempt leaves its isolated staging directory.
            Directory.Move(stage,destination);
            return destination;
        } finally { foreach(var h in pins) h.Dispose(); }
    }
    static void Shortcut(string folder,string installed,string name) {
        folder=CheckLocal(folder);
        Directory.CreateDirectory(folder);
        var pins=Pin(folder);
        object shell=null,link=null;
        try {
            string path=Path.Combine(folder,name+".lnk");
            if (File.Exists(path)||Directory.Exists(path)) throw new IOException("快捷方式已存在，未覆盖："+name);
            Type type=Type.GetTypeFromProgID("WScript.Shell",true);
            shell=Activator.CreateInstance(type);
            link=type.InvokeMember("CreateShortcut",BindingFlags.InvokeMethod,null,shell,new object[]{path});
            Type lt=link.GetType();
            lt.InvokeMember("TargetPath",BindingFlags.SetProperty,null,link,new object[]{Path.Combine(installed,"OfflineKeyVault.exe")});
            lt.InvokeMember("WorkingDirectory",BindingFlags.SetProperty,null,link,new object[]{installed});
            lt.InvokeMember("Description",BindingFlags.SetProperty,null,link,new object[]{"Offline Key Vault"});
            lt.InvokeMember("Save",BindingFlags.InvokeMethod,null,link,null);
            if (!File.Exists(path)) throw new IOException("快捷方式未创建。");
            object target=lt.InvokeMember("TargetPath",BindingFlags.GetProperty,null,link,null);
            if (!String.Equals((string)target,Path.Combine(installed,"OfflineKeyVault.exe"),StringComparison.OrdinalIgnoreCase)) throw new IOException("快捷方式目标校验失败。");
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
    static void WizardLayout(Form form,Label title,Label intro,Label label,TextBox path,Button browse,Label status,CheckBox desktop,CheckBox menu,Label note,Button install,Button cancel) {
        form.SuspendLayout();form.Controls.Clear();form.FormBorderStyle=FormBorderStyle.Sizable;
        form.MinimumSize=new Size(600,440);form.ClientSize=new Size(700,530);
        form.AutoScaleDimensions=new SizeF(96,96);form.AutoScaleMode=AutoScaleMode.Dpi;
        var body=new Panel {Dock=DockStyle.Fill,AutoScroll=true};var column=Column();body.Controls.Add(column);
        var footer=Buttons(install,cancel);form.Controls.Add(body);form.Controls.Add(footer);
        WrapIn(column,title);WrapIn(column,intro);WrapIn(column,label);
        var location=new TableLayoutPanel {AutoSize=true,ColumnCount=2};
        location.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));location.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        path.Dock=DockStyle.Fill;path.Margin=new Padding(0,4,8,4);browse.AutoSize=true;browse.MinimumSize=new Size(112,34);
        location.Controls.Add(path,0,0);location.Controls.Add(browse,1,0);Row(column,location);
        WrapIn(column,status);
        var choices=new FlowLayoutPanel {AutoSize=true,WrapContents=true};
        desktop.AutoSize=true;menu.AutoSize=true;desktop.Margin=new Padding(0,4,20,4);menu.Margin=new Padding(0,4,0,4);
        choices.Controls.AddRange(new Control[]{desktop,menu});Row(column,choices);WrapIn(column,note);
        Theme(form,install);status.ForeColor=Color.FromArgb(100,105,118);
        form.ResumeLayout(true);
    }
    static string ChooseFolder(Form owner) {
        var picker=new Form {Text="选择本地父目录",ClientSize=new Size(680,560),MinimumSize=new Size(600,460),StartPosition=FormStartPosition.CenterParent,Font=owner.Font,AutoScaleDimensions=new SizeF(96,96),AutoScaleMode=AutoScaleMode.Dpi};
        var path=new TextBox {Left=20,Top=20,Width=480,Text=Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)};
        var up=new Button {Text="上级",Left=510,Top=18,Width=90};
        var drives=new ComboBox {Left=20,Top=56,Width=580,DropDownStyle=ComboBoxStyle.DropDownList};
        foreach(var drive in DriveInfo.GetDrives()) if(drive.DriveType==DriveType.Fixed||drive.DriveType==DriveType.Removable)drives.Items.Add(drive.Name);
        var listing=new ListBox {Left=20,Top=94,Width=580,Height=290};
        var note=new Label {Left=20,Top=390,Width=580,Height=30};
        var choose=new Button {Text="选择此目录",Left=470,Top=432,Width=130};
        string selected=null,current=null;
        Action refresh=()=>{try{
            string folder=CheckLocal(path.Text,true);
            if(!Directory.Exists(folder))throw new IOException();
            listing.Items.Clear();current=folder;
            foreach(string child in Directory.EnumerateDirectories(folder)){
                try{if((File.GetAttributes(child)&FileAttributes.ReparsePoint)==0)listing.Items.Add(Path.GetFileName(child));}catch(IOException){}
                if(listing.Items.Count>=10000)break;
            }
            note.Text="仅列出本地目录，不加载系统云盘扩展。";
        }catch{note.Text="路径未完成、不可访问或不属于本地目录。";}};
        var delay=new Timer {Interval=300};
        delay.Tick+=(sender,e)=>{delay.Stop();refresh();};
        path.TextChanged+=(sender,e)=>{delay.Stop();delay.Start();};
        up.Click+=(sender,e)=>{if(current!=null){string parent=Path.GetDirectoryName(current);if(parent!=null)path.Text=parent;}};
        drives.SelectedIndexChanged+=(sender,e)=>path.Text=(string)drives.SelectedItem;
        listing.DoubleClick+=(sender,e)=>{if(current!=null&&listing.SelectedItem!=null)path.Text=Path.Combine(current,(string)listing.SelectedItem);};
        choose.Click+=(sender,e)=>{try{string folder=CheckLocal(path.Text,true);if(!Directory.Exists(folder))throw new IOException();selected=folder;picker.Close();}catch{note.Text="请选择有效的本地目录。";}};
        picker.FormClosed+=(sender,e)=>{delay.Stop();delay.Dispose();};
        var layout=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=1,RowCount=5,Padding=new Padding(20)};
        for(int i=0;i<5;i++)layout.RowStyles.Add(new RowStyle(i==2?SizeType.Percent:SizeType.AutoSize,i==2?100:0));
        var nav=new TableLayoutPanel {Dock=DockStyle.Fill,AutoSize=true,ColumnCount=2};
        nav.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));nav.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        path.Dock=DockStyle.Fill;up.AutoSize=true;path.Margin=new Padding(0,4,8,4);nav.Controls.Add(path,0,0);nav.Controls.Add(up,1,0);
        drives.Dock=DockStyle.Fill;listing.Dock=DockStyle.Fill;listing.HorizontalScrollbar=true;
        note.AutoSize=true;note.Dock=DockStyle.Top;
        layout.SizeChanged+=(sender,e)=>note.MaximumSize=new Size(Math.Max(100,layout.ClientSize.Width-40),0);
        layout.Controls.Add(nav,0,0);layout.Controls.Add(drives,0,1);layout.Controls.Add(listing,0,2);layout.Controls.Add(note,0,3);
        var footer=Buttons(choose);layout.Controls.Add(footer,0,4);
        picker.Controls.Add(layout);Theme(picker,choose);refresh();picker.ShowDialog(owner);picker.Dispose();return selected;
    }
    [STAThread] static int Main(string[] args) {
        if(args.Length==2 && args[0]=="--test-install") {
            try {
                string dest=Extract(args[1],true);
                Shortcut(Path.Combine(dest,"shortcut-test"),dest,"OfflineKeyVault-Test");
                bool rejected=false;
                try { Extract(dest,false); } catch(IOException) { rejected=true; }
                if(!rejected) return 2;
                return 0;
            } catch(Exception error) {Console.Error.WriteLine("Installer test failed: "+error.GetType().Name+": "+error.Message);return 1;}
        }
        if(args.Length!=0)return 2;
        Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
        var form=new Form {Text="离线密钥柜 · 安装",ClientSize=new Size(650,400),StartPosition=FormStartPosition.CenterScreen,FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,Font=new Font("Microsoft YaHei UI",10)};
        var title=new Label {Text="安装离线密钥柜",Left=26,Top=24,Width=590,Height=40,Font=new Font("Microsoft YaHei UI",20,FontStyle.Bold)};
        var intro=new Label {Text="完整离线安装 · 无需管理员权限 · 不改动已有密钥库",Left=28,Top=76,Width=590,Height=28};
        var label=new Label {Text="安装位置（输入新的本地文件夹路径）",Left=28,Top=119,Width=590,Height=28};
        var path=new TextBox {Left=28,Top=151,Width=470,Text=DefaultPath()};
        var browse=new Button {Text="选择位置…",Left=506,Top=148,Width=112,Height=30};
        browse.Click+=(sender,e)=>{string chosen=ChooseFolder(form);if(chosen!=null)path.Text=Path.Combine(chosen,"OfflineKeyVault");};
        var status=new Label {Left=28,Top=186,Width=590,Height=40,ForeColor=Color.DimGray};
        var desktop=new CheckBox {Text="创建桌面快捷方式",Left=28,Top=233,Width=260,Checked=true};
        var menu=new CheckBox {Text="创建开始菜单快捷方式",Left=315,Top=233,Width=280,Checked=true};
        var note=new Label {Text="已有目录不会覆盖；升级请安装到新目录，再打开旧库。\n请选择非云同步目录。安装程序不会自动启动应用。",Left=28,Top=276,Width=590,Height=48};
        var install=new Button {Text="安装",Left=492,Top=342,Width=126,Height=38,BackColor=Color.FromArgb(220,53,69),ForeColor=Color.White,FlatStyle=FlatStyle.Flat};
        var cancel=new Button {Text="取消",Left=350,Top=342,Width=126,Height=38};
        Action check=()=>{try{string value=CheckLocal(path.Text);status.Text=Directory.Exists(value)||File.Exists(value)?"目录已存在，请换一个新文件夹名称。":"路径可用，将在安装时创建文件夹。";}catch{status.Text="请输入允许的本地绝对路径。";}};
        path.TextChanged+=(sender,e)=>check(); check();
        cancel.Click+=(sender,e)=>form.Close();
        install.Click+=(sender,e)=>{
            string destination=null;
            try {
                install.Enabled=false;path.Enabled=false;browse.Enabled=false;desktop.Enabled=false;menu.Enabled=false;cancel.Enabled=false;
                status.Text="正在解压和验证，请稍候…";form.Refresh();
                destination=Extract(path.Text,false);
                var issues=new List<string>();
                if(desktop.Checked)try{Shortcut(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),destination,"离线密钥柜");}catch(Exception error){issues.Add(error.Message);}
                if(menu.Checked)try{Shortcut(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs),"OfflineKeyVault"),destination,"离线密钥柜");}catch(Exception error){issues.Add(error.Message);}
                MessageBox.Show(form,"程序已安装到：\n"+destination+(issues.Count==0?"\n快捷方式按所选项创建。":"\n部分快捷方式未创建：\n"+String.Join("\n",issues.ToArray()))+"\n可直接打开目录中的 OfflineKeyVault.exe。","安装完成",MessageBoxButtons.OK,issues.Count==0?MessageBoxIcon.Information:MessageBoxIcon.Warning);
                form.Close();
            }catch(Exception error){MessageBox.Show(form,error.Message+"\n安装未完成；原有程序和密钥未被覆盖。","安装未完成",MessageBoxButtons.OK,MessageBoxIcon.Error);}
            finally{if(!form.IsDisposed){install.Enabled=true;path.Enabled=true;browse.Enabled=true;desktop.Enabled=true;menu.Enabled=true;cancel.Enabled=true;}}
        };
        WizardLayout(form,title,intro,label,path,browse,status,desktop,menu,note,install,cancel);
        Application.Run(form);return 0;
    }
}
