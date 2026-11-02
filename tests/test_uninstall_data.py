"""Optional deletion is exercised only against isolated synthetic user data."""
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
using System.Drawing;
using System.Windows.Forms;
using System.Runtime.InteropServices;
internal static partial class Installer {
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern bool CreateHardLink(string name,string existing,IntPtr reserved);
    static void CheckData(bool value,string why) {if(!value)throw new Exception(why);}
    static string VaultFixture(string folder,string name) {Directory.CreateDirectory(folder);string p=Path.Combine(folder,name);File.WriteAllText(p,"{\"format\":\"OKV2\",\"fixture\":\"synthetic, no secrets\"}");return p;}
    static void BoundsData(Control parent) {
        foreach(Control child in parent.Controls) {
            if(!child.Visible)continue;
            CheckData(child.Left>=0&&child.Top>=0&&child.Right<=parent.ClientSize.Width+1&&child.Bottom<=parent.ClientSize.Height+1,"Clipped "+child.GetType().Name+": "+child.Text);
            var label=child as Label;if(label!=null)CheckData(label.Height>=label.PreferredHeight,"Label clipped "+label.Text);
            BoundsData(child);
        }
    }
    internal static string DataTest(string mode,string folder) {
        string a=VaultFixture(folder,"selected.okv"),b=VaultFixture(folder,"keep.okv");
        string recovery=Path.Combine(folder,"keep.okvr");File.WriteAllText(recovery,"{\"format\":\"OKV-RECOVERY1\"}");
        if(mode=="paths") {
            CheckData(DataLocation(a)==a&&DataLocation(folder+Path.DirectorySeparatorChar)==folder,"Local file and directory accepted");
            foreach(string unsafePath in new[]{@"\\server\share\vault.okv",@"\\?\C:\vault.okv",@"C:relative.okv",@"relative.okv"}) {
                bool denied=false;try{DataLocation(unsafePath);}catch(IOException){denied=true;}CheckData(denied,"Nonlocal or relative path accepted");
            }return "passed";
        }
        if(mode.StartsWith("ui-")) {
            Application.EnableVisualStyles();bool chosen=false;int reviews=0;
            using(var form=CreateUninstallOptions(folder,owner=>{reviews++;return null;},value=>chosen=true)) {
                if(mode=="ui-large")form.Font=new Font(form.Font.FontFamily,14);
                form.Show();Application.DoEvents();BoundsData(form);
                using(var bitmap=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(bitmap,new Rectangle(Point.Empty,bitmap.Size));bitmap.Save(Path.Combine(folder,"options.png"));}
                var keep=(CheckBox)form.Controls.Find("KeepData",true)[0];var action=(Button)form.Controls.Find("UninstallAction",true)[0];
                CheckData(keep.Checked,"Default must preserve data");keep.Checked=false;action.PerformClick();
                CheckData(reviews==1&&!chosen&&form.Visible,"Cancelled review must not uninstall");
                keep.Checked=true;action.PerformClick();CheckData(chosen&&reviews==1,"Preserve must not discover data");
            }
            var catalog=new DataCatalog();catalog.Add(a);catalog.Add(b);DataApproval result=null;
            using(var form=CreateDataReview(folder,catalog,value=>result=value)) {
                if(mode=="ui-large") {form.Font=new Font(form.Font.FontFamily,14);form.ClientSize=new Size(1000,760);}
                if(mode=="ui-small")form.Size=form.MinimumSize;
                form.Show();Application.DoEvents();BoundsData(form);
                using(var bitmap=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(bitmap,new Rectangle(Point.Empty,bitmap.Size));bitmap.Save(Path.Combine(folder,"review.png"));}
                var list=(ListView)form.Controls.Find("DataFiles",true)[0];var confirm=(TextBox)form.Controls.Find("DeleteConfirmation",true)[0];var finish=(Button)form.Controls.Find("ConfirmDataDeletion",true)[0];
                CheckData(!finish.Enabled&&list.CheckedItems.Count==2,"Confirmation required");
                confirm.Text="删除";CheckData(finish.Enabled,"Correct phrase enables confirmation");
                list.Items[1].Checked=false;CheckData(confirm.Text==""&&!finish.Enabled,"Selection change must reset confirmation");
                confirm.Text="删除";finish.PerformClick();CheckData(result!=null&&result.Files.Length==1,"Only checked files approved");
                CheckData(File.Exists(a)&&File.Exists(b),"Review must not delete files");
            }
            return "passed";
        }
        if(mode=="discovery") {
            string defaults=Path.Combine(folder,"defaults"),exports=Path.Combine(folder,"exports"),imports=Path.Combine(folder,"imports");
            string d=VaultFixture(defaults,"default.okv"),deep=VaultFixture(Path.Combine(defaults,"child"),"not-recursive.okv");VaultFixture(exports,"keep.okv");VaultFixture(imports,"keep.okv");
            string installed=Path.Combine(folder,"installed");string nested=VaultFixture(Path.Combine(installed,"child"),"nested.okv");
            string pref=Path.Combine(folder,PreferencesName);
            var json=new System.Web.Script.Serialization.JavaScriptSerializer();
            File.WriteAllText(pref,json.Serialize(new {format="OKV-PREFERENCES2",vault_directory=defaults,export_directory=exports,import_directory=imports}));
            var catalog=DiscoverData(installed,pref);
            CheckData(catalog.Files.Count==3,"Only install/default vaults and preferences discovered");
            CheckData(catalog.Files.Exists(f=>f.Path==d)&&catalog.Files.Exists(f=>f.Path==nested)&&catalog.Files.Exists(f=>f.Path==pref),"Discovery scope mismatch");
            catalog.Add(d);CheckData(catalog.Files.Count==3,"Duplicate not removed");catalog.Scan(defaults,false);CheckData(catalog.Files.Count==3,"Supplemental scan must be shallow");
            catalog.Add(deep);CheckData(catalog.Files.Count==4,"Exact supplemental file supported");
            return "passed";
        }
        if(mode=="hardlink") {
            CheckData(CreateHardLink(Path.Combine(folder,"alias.okv"),a,IntPtr.Zero),"Fixture hardlink failed");bool denied=false;
            try{InspectData(a);}catch(IOException){denied=true;}CheckData(denied,"Hardlink accepted");return "passed";
        }
        if(mode=="wrong-type") {
            foreach(string path in new[]{recovery,Path.Combine(folder,"export.pem"),Path.Combine(folder,"invalid.okv")}) {
                if(!File.Exists(path))File.WriteAllText(path,"{\"format\":\"OTHER\"}");bool denied=false;
                try{InspectData(path);}catch(IOException){denied=true;}CheckData(denied,"Unrecognized data accepted");
            }return "passed";
        }
        if(mode=="limit") {
            var catalog=new DataCatalog();for(int i=0;i<200;i++)catalog.Add(VaultFixture(folder,"limit-"+i+".okv"));
            bool denied=false;try{catalog.Add(a);}catch(IOException){denied=true;}CheckData(denied&&catalog.Limited&&catalog.Files.Count==200,"Catalog must be bounded");return "passed";
        }
        var first=InspectData(a);var second=InspectData(b);
        if(mode=="confirmation") {
            foreach(string value in new[]{"","delete"," 删除","删除 "}){bool denied=false;try{ApproveDataDeletion(new[]{first},value);}catch(IOException){denied=true;}CheckData(denied,"Incorrect confirmation accepted");}
            bool duplicate=false;try{ApproveDataDeletion(new[]{first,first},"删除");}catch(IOException){duplicate=true;}CheckData(duplicate,"Duplicate deletion accepted");return "passed";
        }
        if(mode=="settings") {
            a=Path.Combine(folder,PreferencesName);File.WriteAllText(a,"{\"format\":\"OKV-PREFERENCES1\",\"export_directory\":\"\"}");first=InspectData(a);
        }
        var approval=ApproveDataDeletion(mode=="locked"||mode=="readonly"?new[]{first,second}:new[]{first},"删除");
        FileStream held=null;
        if(mode=="changed")File.AppendAllText(a," ");
        if(mode=="replaced"){File.Move(a,a+".old");File.Copy(a+".old",a);}
        if(mode=="locked")held=new FileStream(b+".lock",FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.ReadWrite);
        if(mode=="readonly")File.SetAttributes(b,FileAttributes.ReadOnly);
        bool rejected=false;
        try {
            using(var batch=new DataBatch(approval)) {
                if(mode=="rename") {bool denied=false;try{File.Move(a,a+".moved");}catch(IOException){denied=true;}CheckData(denied,"Selected file can be replaced while held");}
                batch.DeleteConfirmed();CheckData(batch.Deleted==1,"Only one file deleted");
            }
        } catch(IOException){rejected=true;}
        finally {if(held!=null)held.Dispose();if(mode=="readonly")File.SetAttributes(b,FileAttributes.Normal);}
        bool expected=mode=="changed"||mode=="replaced"||mode=="locked"||mode=="readonly";
        CheckData(rejected==expected,"Unexpected deletion outcome: "+mode);
        CheckData(File.Exists(a)==expected&&File.Exists(b)&&File.Exists(recovery),"Selection or all-file preflight violated");
        return "passed";
    }
}
public static class DataBridge {public static string Run(string mode,string folder){return Installer.DataTest(mode,folder);}}
'''

@pytest.fixture(scope='module')
def compiled(tmp_path_factory):
    work = tmp_path_factory.mktemp('uninstall-data')
    harness = work / 'Harness.cs'
    harness.write_text(HARNESS, encoding='utf-8')
    dll = work / 'Tests.dll'
    compiler = Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    result = subprocess.run([str(compiler), '/nologo', '/target:library', '/r:System.Windows.Forms.dll',
                             '/r:System.Web.Extensions.dll', '/r:System.Drawing.dll', '/r:System.IO.Compression.dll', '/out:' + str(dll),
                             *(str(ROOT / 'packaging' / name) for name in ('Installer.cs', 'Upgrade.cs', 'Uninstall.cs', 'UninstallData.cs')),
                             str(harness)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    script = work / 'Run.ps1'
    script.write_text("param($Assembly,$Mode,$Folder)\n$ErrorActionPreference='Stop'\nAdd-Type -Path $Assembly\n[DataBridge]::Run($Mode,$Folder)\n", encoding='utf-8')
    return dll, script

@pytest.mark.parametrize('mode', ['delete', 'settings', 'confirmation', 'discovery', 'hardlink', 'wrong-type', 'limit',
                                  'changed', 'replaced', 'locked', 'readonly', 'rename', 'paths', 'ui-normal', 'ui-small', 'ui-large'])
def test_explicit_data_deletion(compiled, tmp_path, mode):
    dll, script = compiled
    result = subprocess.run(['powershell.exe', '-NoProfile', '-STA', '-File', str(script), str(dll), mode, str(tmp_path)],
                            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=40)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'passed'
