using System;
using System.IO;
using System.Text;
using System.Drawing;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;

internal static partial class Installer {
    internal const string PreferencesName=".offline-key-vault-preferences.json";
    const int DataFileLimit=16*1024*1024, DataCountLimit=200;
    const long DataTotalLimit=128L*1024*1024;
    [StructLayout(LayoutKind.Sequential)] internal struct DataFileInfo {
        internal uint Attributes,CreationLow,CreationHigh,AccessLow,AccessHigh,WriteLow,WriteHigh;
        internal uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
    }
    [StructLayout(LayoutKind.Sequential)] struct DataDisposition {[MarshalAs(UnmanagedType.Bool)] internal bool Delete;}
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle,out DataFileInfo info);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle handle,int kind,ref DataDisposition info,uint size);
    internal sealed class DataSnapshot {
        internal readonly string Path,Kind,Digest,Identity;
        internal readonly long Size;
        internal DataSnapshot(string path,string kind,string digest,DataFileInfo info) {
            Path=path;Kind=kind;Digest=digest;Size=((long)info.SizeHigh<<32)|info.SizeLow;
            Identity=info.Volume.ToString("x8")+":"+info.IndexHigh.ToString("x8")+info.IndexLow.ToString("x8");
        }
        public override string ToString(){return Path;}
    }
    internal sealed class DataApproval {
        readonly DataSnapshot[] files;
        internal DataSnapshot[] Files {get{return (DataSnapshot[])files.Clone();}}
        internal DataApproval(DataSnapshot[] selected){files=(DataSnapshot[])selected.Clone();}
    }
    internal static DataApproval ApproveDataDeletion(DataSnapshot[] selected,string confirmation) {
        if(confirmation!="删除"||selected==null||selected.Length==0||selected.Length>DataCountLimit)throw new IOException("请核对文件列表并输入“删除”再次确认。");
        long size=0;var identities=new HashSet<string>();
        foreach(var file in selected){if(file==null||!identities.Add(file.Identity))throw new IOException("删除列表重复或无效。");size+=file.Size;}
        if(size>DataTotalLimit)throw new IOException("所选数据超过本次清理上限。");
        return new DataApproval(selected);
    }
    static string DataPath(string value) {
        if(String.IsNullOrWhiteSpace(value)||value.Length<3||value[1]!=':'||(value[2]!='\\'&&value[2]!='/'))throw new IOException("请选择本地文件的完整路径。");
        string parent=CheckLocal(Path.GetDirectoryName(value),true),name=Path.GetFileName(value);
        if(name.Length==0||name.EndsWith(".")||name.EndsWith(" ")||name.IndexOfAny(Path.GetInvalidFileNameChars())>=0)throw new IOException("文件名无效。");
        string path=Path.GetFullPath(Path.Combine(parent,name));Plain(path);return path;
    }
    internal static string DataLocation(string value) {
        // Validate before Directory.Exists: UNC input must never trigger a
        // network lookup, and ancestor junctions must not be followed.
        if(String.IsNullOrWhiteSpace(value)||value.Length<3||value[1]!=':'||(value[2]!='\\'&&value[2]!='/'))throw new IOException("请输入本地文件或目录的完整路径。");
        string full=Path.GetFullPath(value);
        return full==Path.GetPathRoot(full)?CheckLocal(full,true):DataPath(full.TrimEnd('\\','/'));
    }
    static DataFileInfo DataInfo(FileStream stream) {
        DataFileInfo info;
        if(!GetFileInformationByHandle(stream.SafeFileHandle,out info)||(info.Attributes&0x410)!=0||info.Links!=1)throw new IOException("不允许目录、链接、重解析点或硬链接文件。");
        return info;
    }
    static FileStream OpenData(string path,bool deleting,bool lockFile=false) {
        Plain(path);
        // No FILE_SHARE_DELETE: the selected file cannot be renamed/replaced
        // while held. DELETE access lets us dispose this exact handle later.
        uint access=lockFile?0xc0000000u:deleting?0x80010000u:0x80000000u;
        var handle=CreateFile(path,access,lockFile?0u:1u,IntPtr.Zero,lockFile?4u:3u,0x00200000,IntPtr.Zero);
        if(handle.IsInvalid){handle.Dispose();throw new IOException("文件正在使用或无法取得清理权限："+path);}
        FileStream stream=null;
        try {
            stream=new FileStream(handle,lockFile?FileAccess.ReadWrite:FileAccess.Read);
            var info=DataInfo(stream);
            if(deleting&&(info.Attributes&1)!=0)throw new IOException("文件为只读，请先处理后重新确认："+path);
            return stream;
        } catch {if(stream!=null)stream.Dispose();else handle.Dispose();throw;}
    }
    static string StreamDigest(FileStream stream) {
        stream.Position=0;using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-","").ToLowerInvariant();
    }
    static Dictionary<string,object> DataDocument(FileStream stream,int limit) {
        if(stream.Length<=0||stream.Length>limit)throw new IOException("文件为空或超过识别上限。");
        stream.Position=0;var bytes=new byte[(int)stream.Length];int used=0;
        while(used<bytes.Length){int count=stream.Read(bytes,used,bytes.Length-used);if(count==0)throw new IOException("文件读取不完整。");used+=count;}
        try {
            var parser=new JavaScriptSerializer {MaxJsonLength=limit,RecursionLimit=32};
            var doc=parser.DeserializeObject(new UTF8Encoding(false,true).GetString(bytes)) as Dictionary<string,object>;
            if(doc==null)throw new IOException("不是可识别的数据文件。");return doc;
        } catch(ArgumentException){throw new IOException("数据文件格式无法识别。");}
        catch(InvalidOperationException){throw new IOException("数据文件结构过于复杂。");}
        finally {Array.Clear(bytes,0,bytes.Length);}
    }
    static bool IsPreferences(Dictionary<string,object> doc) {
        object format;
        if(!doc.TryGetValue("format",out format))return false;
        string version=format as string;
        var allowed=new HashSet<string>(version=="OKV-PREFERENCES1"?new[]{"format","export_directory"}:new[]{"format","export_directory","vault_directory","import_directory"});
        if((version!="OKV-PREFERENCES1"&&version!="OKV-PREFERENCES2")||doc.Count!=allowed.Count)return false;
        foreach(var item in doc)if(!allowed.Contains(item.Key)||!(item.Value is string)||((string)item.Value).Length>4096)return false;
        return true;
    }
    internal static DataSnapshot InspectData(string value) {
        string path=DataPath(value);bool settings=Path.GetFileName(path)==PreferencesName;
        if(!settings&&!Path.GetExtension(path).Equals(".okv",StringComparison.OrdinalIgnoreCase))throw new IOException("只接受密钥库 .okv 和本程序的路径设置文件。");
        var pins=Pin(Path.GetDirectoryName(path));
        try {using(var stream=OpenData(path,false)) {
            var info=DataInfo(stream);var doc=DataDocument(stream,settings?16384:DataFileLimit);object format;
            if(settings?!IsPreferences(doc):!doc.TryGetValue("format",out format)||Array.IndexOf(new[]{"OKV1","OKV2","OKV-DESTROYED"},format as string)<0)throw new IOException("文件不是可识别的密钥库或设置。");
            return new DataSnapshot(path,settings?"设置（当前用户共用）":"密钥库 / 加密备份",StreamDigest(stream),info);
        }} finally {foreach(var pin in pins)pin.Dispose();}
    }
    internal sealed class DataBatch : IDisposable {
        readonly List<FileStream> streams=new List<FileStream>(),locks=new List<FileStream>();
        readonly List<SafeFileHandle> pins=new List<SafeFileHandle>();
        internal int Deleted {get;private set;}
        internal DataBatch(DataApproval approval) {
            try {
                foreach(var expected in approval.Files) {
                    string path=DataPath(expected.Path);pins.AddRange(Pin(Path.GetDirectoryName(path)));
                    // The app keeps an adjacent lock even when the vault file is
                    // closed between operations. Reject other running instances.
                    locks.Add(OpenData(path+".lock",false,true));
                    var stream=OpenData(path,true);streams.Add(stream);
                    var actual=new DataSnapshot(path,expected.Kind,StreamDigest(stream),DataInfo(stream));
                    if(actual.Identity!=expected.Identity||actual.Size!=expected.Size||actual.Digest!=expected.Digest)throw new IOException("确认后文件发生变化，未开始清理。请重新检查列表："+path);
                }
            } catch {Dispose();throw;}
        }
        internal void DeleteConfirmed() {
            foreach(var stream in streams) {
                var disposition=new DataDisposition {Delete=true};
                if(!SetFileInformationByHandle(stream.SafeFileHandle,4,ref disposition,4))throw new IOException("部分文件无法删除；已处理 "+Deleted+" 个，请核对所选文件后重试。");
                Deleted++;
            }
        }
        public void Dispose(){foreach(var s in streams)s.Dispose();foreach(var s in locks)s.Dispose();foreach(var p in pins)p.Dispose();}
    }
    internal sealed class DataCatalog {
        internal readonly List<DataSnapshot> Files=new List<DataSnapshot>();
        internal int Skipped;internal bool Limited;
        long total;
        internal void Add(string path) {
            var file=InspectData(path);
            if(Files.Exists(item=>item.Identity==file.Identity))return;
            if(Files.Count>=DataCountLimit||total+file.Size>DataTotalLimit){Limited=true;throw new IOException("列表达到上限，请清空列表后单独添加需要清理的位置。");}
            Files.Add(file);total+=file.Size;
        }
        internal void Clear(){Files.Clear();total=0;Skipped=0;Limited=false;}
        internal void Scan(string directory,bool recursive) {
            directory=CheckLocal(directory,true);var pending=new Queue<KeyValuePair<string,int>>();pending.Enqueue(new KeyValuePair<string,int>(directory,0));int entries=0;
            while(pending.Count>0&&!Limited) {
                var item=pending.Dequeue();var held=new List<SafeFileHandle>();
                try {
                    held=Pin(CheckLocal(item.Key,true));
                    foreach(string path in Directory.EnumerateFileSystemEntries(item.Key)) {
                        if(++entries>10000){Limited=true;break;}
                        try {
                            Plain(path);
                            if(Directory.Exists(path)){if(recursive&&item.Value<12)pending.Enqueue(new KeyValuePair<string,int>(path,item.Value+1));else if(recursive)Limited=true;}
                            else if(Path.GetExtension(path).Equals(".okv",StringComparison.OrdinalIgnoreCase))Add(path);
                        } catch(IOException){Skipped++;}catch(UnauthorizedAccessException){Skipped++;}
                    }
                } catch(IOException){Skipped++;}catch(UnauthorizedAccessException){Skipped++;}
                finally {foreach(var handle in held)handle.Dispose();}
            }
        }
    }
    internal static DataCatalog DiscoverData(string installed,string preferences) {
        var catalog=new DataCatalog();catalog.Scan(installed,true);
        var settings=new HashSet<string>(StringComparer.OrdinalIgnoreCase){preferences,Path.Combine(installed,PreferencesName)};
        foreach(string path in settings) {
            try {
                DataPath(path);if(!File.Exists(path))continue;
                catalog.Add(path);var pins=Pin(CheckLocal(Path.GetDirectoryName(path),true));
                try {using(var stream=OpenData(DataPath(path),false)) {
                    var doc=DataDocument(stream,16384);object value;
                    if(IsPreferences(doc)&&doc.TryGetValue("vault_directory",out value)&&!String.IsNullOrWhiteSpace(value as string))catalog.Scan((string)value,false);
                }} finally {foreach(var pin in pins)pin.Dispose();}
            } catch(IOException){catalog.Skipped++;}catch(UnauthorizedAccessException){catalog.Skipped++;}
        }
        return catalog;
    }
    static Form UninstallForm(string title,Size size) {
        return new Form {Text=title,ClientSize=size,StartPosition=FormStartPosition.CenterScreen,Font=new Font("Microsoft YaHei UI",10),AutoScaleMode=AutoScaleMode.Dpi,AutoScaleDimensions=new SizeF(96,96),FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false,Icon=Icon.ExtractAssociatedIcon(Application.ExecutablePath)};
    }
    internal static Form CreateUninstallOptions(string destination,Func<Form,DataApproval> review,Action<DataApproval> chosen) {
        var form=UninstallForm("卸载离线密钥柜",new Size(700,350));var column=Column();form.Controls.Add(column);
        WrapIn(column,new Label {Text="卸载离线密钥柜",Font=new Font(form.Font.FontFamily,20,FontStyle.Bold)});
        WrapIn(column,new Label {Text="移除程序及其快捷方式。请选择是否保留个人数据。"});
        WrapIn(column,new Label {Text="安装位置："+destination});
        var keep=new CheckBox {Name="KeepData",Text="保留密钥库和设置（推荐）",Checked=true,AutoSize=true,Margin=new Padding(0,14,0,14)};Row(column,keep);
        var note=new Label {Text="密钥库、设置、恢复文件、导出文件和升级备份会保留。"};WrapIn(column,note);
        var remove=new Button {Name="UninstallAction",Text="卸载程序"};var cancel=new Button {Text="取消",DialogResult=DialogResult.Cancel};
        var footer=Buttons(remove,cancel);form.Controls.Add(footer);form.CancelButton=cancel;
        keep.CheckedChanged+=(s,e)=>{remove.Text=keep.Checked?"卸载程序":"下一步：选择数据";note.Text=keep.Checked?"密钥库、设置、恢复文件、导出文件和升级备份会保留。":"下一步列出具体文件；只有再次确认后才会卸载并删除所选数据。";};
        remove.Click+=(s,e)=>{var data=keep.Checked?null:review(form);if(!keep.Checked&&data==null)return;chosen(data);form.DialogResult=DialogResult.OK;form.Close();};
        Theme(form,remove);note.ForeColor=Color.FromArgb(100,105,118);
        form.Shown+=(s,e)=>form.ClientSize=new Size(form.ClientSize.Width,column.PreferredSize.Height+footer.Height);
        return form;
    }
    internal static Form CreateDataReview(string destination,DataCatalog catalog,Action<DataApproval> approved) {
        var form=UninstallForm("确认卸载与数据删除",new Size(820,620));form.MinimumSize=new Size(720,550);form.FormBorderStyle=FormBorderStyle.Sizable;
        var layout=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=1,RowCount=6,Padding=new Padding(24)};
        for(int i=0;i<6;i++)layout.RowStyles.Add(new RowStyle(i==1?SizeType.Percent:SizeType.AutoSize,i==1?100:0));
        var intro=new Label {Text="仅删除勾选的文件。请核对完整路径，再输入“删除”确认。\n设置由本机当前用户的所有安装实例共用。恢复文件和导出的单独密钥保留。",AutoSize=true,Dock=DockStyle.Top,Margin=new Padding(0,0,0,14)};
        var list=new ListView {Name="DataFiles",Dock=DockStyle.Fill,View=View.Details,CheckBoxes=true,FullRowSelect=true,HideSelection=false,ShowItemToolTips=true};
        list.Columns.Add("类型",155);list.Columns.Add("完整路径",550);
        var status=new Label {AutoSize=true,Dock=DockStyle.Top,MaximumSize=new Size(750,0),Margin=new Padding(0,10,0,10)};
        layout.SizeChanged+=(s,e)=>{int width=Math.Max(100,layout.ClientSize.Width-48);intro.MaximumSize=new Size(width,0);status.MaximumSize=new Size(width,0);};
        var path=new TextBox {Name="AdditionalDataPath",Dock=DockStyle.Fill,AccessibleName="补充本地库文件或目录"};
        var add=new Button {Text="添加位置",AutoSize=true};var browse=new Button {Text="浏览目录…",AutoSize=true};var clear=new Button {Text="清空列表",AutoSize=true};
        var input=new TableLayoutPanel {Dock=DockStyle.Top,AutoSize=true,ColumnCount=4};input.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));for(int i=0;i<3;i++)input.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));input.Controls.Add(path,0,0);input.Controls.Add(add,1,0);input.Controls.Add(browse,2,0);input.Controls.Add(clear,3,0);
        var confirm=new TextBox {Name="DeleteConfirmation",Width=100,AccessibleName="输入删除二次确认"};
        var confirmation=new FlowLayoutPanel {AutoSize=true,Dock=DockStyle.Top,WrapContents=true,Margin=new Padding(0,14,0,0)};
        confirmation.Controls.Add(new Label {Text="输入“删除”：",AutoSize=true,Margin=new Padding(0,6,6,0)});confirmation.Controls.Add(confirm);
        confirmation.Controls.Add(new Label {Text="不进入回收站；并非安全擦除，其他副本不受影响。",AutoSize=true,Margin=new Padding(8,6,0,0)});
        var finish=new Button {Name="ConfirmDataDeletion",Text="确认卸载并删除所选数据",Enabled=false};var back=new Button {Text="返回",DialogResult=DialogResult.Cancel};
        var footer=Buttons(finish,back);form.CancelButton=back;
        // Paths must remain readable in full, including with larger system fonts.
        // Only the file list scrolls; its columns can be resized by the user.
        Action sizeColumns=()=>{list.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);list.Columns[0].Width=Math.Max(155,list.Columns[0].Width);list.Columns[1].Width=Math.Max(list.ClientSize.Width-list.Columns[0].Width-8,list.Columns[1].Width);};
        list.FontChanged+=(s,e)=>sizeColumns();form.Shown+=(s,e)=>sizeColumns();
        Action refreshStatus=()=>{finish.Enabled=list.CheckedItems.Count>0&&confirm.Text=="删除";status.Text="已选 "+list.CheckedItems.Count+" / "+list.Items.Count+" 个文件。安装目录含子目录；默认库目录与补充目录仅扫描当前层。"+(catalog.Skipped>0?"\n部分文件不可识别或不可访问，未加入列表。":"")+(catalog.Limited?"\n扫描达到上限，请清空列表后单独添加其他位置。":"");};
        Action fill=()=>{var checks=new HashSet<string>();foreach(ListViewItem item in list.Items)if(item.Checked)checks.Add(((DataSnapshot)item.Tag).Identity);var previous=new HashSet<string>();foreach(ListViewItem item in list.Items)previous.Add(((DataSnapshot)item.Tag).Identity);list.BeginUpdate();list.Items.Clear();foreach(var file in catalog.Files){var item=new ListViewItem(new[]{file.Kind,file.Path}){Tag=file,Checked=!previous.Contains(file.Identity)||checks.Contains(file.Identity),ToolTipText=file.Path+"\n"+file.Size+" 字节"};list.Items.Add(item);}list.EndUpdate();sizeColumns();confirm.Text="";refreshStatus();};
        list.ItemChecked+=(s,e)=>{confirm.Text="";refreshStatus();};confirm.TextChanged+=(s,e)=>refreshStatus();
        Action<string> addPosition=value=>{try{value=DataLocation(value);if(Directory.Exists(value))catalog.Scan(value,false);else catalog.Add(value);fill();}catch(Exception error){MessageBox.Show(form,error.Message,"未加入列表",MessageBoxButtons.OK,MessageBoxIcon.Information);}};
        add.Click+=(s,e)=>addPosition(path.Text);browse.Click+=(s,e)=>{string selected=ChooseFolder(form,destination);if(selected!=null){path.Text=selected;addPosition(selected);}};
        clear.Click+=(s,e)=>{catalog.Clear();fill();};
        finish.Click+=(s,e)=>{var selected=new List<DataSnapshot>();foreach(ListViewItem item in list.CheckedItems)selected.Add((DataSnapshot)item.Tag);var approval=ApproveDataDeletion(selected.ToArray(),confirm.Text);approved(approval);form.DialogResult=DialogResult.OK;form.Close();};
        layout.Controls.Add(intro,0,0);layout.Controls.Add(list,0,1);layout.Controls.Add(status,0,2);layout.Controls.Add(input,0,3);layout.Controls.Add(confirmation,0,4);layout.Controls.Add(footer,0,5);form.Controls.Add(layout);Theme(form,finish);fill();return form;
    }
    static DataApproval ReviewData(Form owner,string destination) {
        var catalog=DiscoverData(destination,Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),PreferencesName));DataApproval approval=null;
        using(var review=CreateDataReview(destination,catalog,value=>approval=value)){review.StartPosition=FormStartPosition.CenterParent;review.ShowDialog(owner);}return approval;
    }
}
