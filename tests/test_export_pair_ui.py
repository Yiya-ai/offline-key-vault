import tkinter as tk
from tkinter import ttk
from unittest.mock import patch
from keyvault.app import Application
from keyvault import keys
from keyvault.localdialog import asksaveasfilename, askdirectory


def descendants(widget):
    for child in widget.winfo_children():
        yield child
        yield from descendants(child)


def dialog(root): return next(w for w in root.winfo_children() if isinstance(w,tk.Toplevel))

def press(widget,label): next(w for w in descendants(widget) if isinstance(w,ttk.Button) and w.cget('text')==label).invoke()


def test_directory_chooser_and_initial_filename(tmp_path):
    root=tk.Tk(); root.withdraw()
    try:
        def save():
            win=dialog(root)
            entries=[w for w in descendants(win) if type(w)==ttk.Entry]
            assert entries[0].get()==str(tmp_path)
            assert entries[-1].get()=='服务器.pem'
            press(win,'保存到此位置')
        root.after(50,save)
        assert asksaveasfilename(parent=root,initialdir=str(tmp_path),initialfile='服务器.pem',defaultextension='.pem')==str(tmp_path/'服务器.pem')
        root.after(50,lambda:press(dialog(root),'选择此目录'))
        assert askdirectory(parent=root,initialdir=str(tmp_path))==str(tmp_path)
    finally: root.destroy()


def test_export_uses_record_name_and_saved_directory(tmp_path):
    root=tk.Tk(); root.withdraw(); app=Application(root,preferences_path=tmp_path/'prefs.json')
    errors=[]; root.report_callback_exception=lambda *a:errors.append(a[1])
    try:
        app.preferences.save(tmp_path)
        app.vault.create(tmp_path/'synthetic.okv','synthetic master password')
        rid,_=app.vault.add(keys.generate('Ed25519'),'我的服务器')
        app.show_manager(); app.tree.selection_set(rid)
        with patch('keyvault.app.messagebox.showinfo'):
            app.export_dialog(False); win=dialog(root)
            with patch('keyvault.app.filedialog.asksaveasfilename',return_value=str(tmp_path/'public.pem')) as chooser:
                press(win,'导出文件')
            assert chooser.call_args.kwargs['initialfile']=='我的服务器.pem'
            assert chooser.call_args.kwargs['initialdir']==str(tmp_path)
            app.export_dialog(True); win=dialog(root)
            entries=[w for w in descendants(win) if type(w)==ttk.Entry]
            for entry,value in zip(entries,['synthetic master password','synthetic export password','synthetic export password']): entry.insert(0,value)
            with patch('keyvault.app.filedialog.asksaveasfilename',return_value=str(tmp_path/'private.pem')) as chooser:
                press(win,'验证并导出')
            assert chooser.call_args.kwargs['initialfile']=='我的服务器.pem'
        assert not errors
    finally: app.quit()


def test_pair_check_ui_masks_private_and_clears_after_use(tmp_path):
    root=tk.Tk(); root.withdraw(); app=Application(root,preferences_path=tmp_path/'prefs.json')
    errors=[]; root.report_callback_exception=lambda *a:errors.append(a[1])
    try:
        app.pair_check_dialog(); win=dialog(root)
        private=keys.generate('Ed25519')
        public=keys.export_public(private,'PEM').decode()
        secret=keys.export_private(private,'PEM',plaintext=True).decode()
        text=next(w for w in descendants(win) if isinstance(w,tk.Text)); text.insert('1.0',public)
        entries=[w for w in descendants(win) if type(w)==ttk.Entry]
        assert entries[1].cget('show')
        entries[1].insert(0,secret)
        assert entries[1].get()==secret
        with patch('keyvault.app.messagebox.showerror',side_effect=lambda *a,**k:errors.append(a)):
            press(win,'校验是否匹配')
        labels=[w.cget('text') for w in descendants(win) if isinstance(w,ttk.Label)]
        assert any(t.startswith('匹配：') for t in labels)
        assert all(not w.get() for w in entries)
        assert not app.vault.unlocked and not (tmp_path/'prefs.json').exists()
        assert not errors,errors
        entries[1].insert(0,secret)
        assert any(w.cget('text').startswith('输入已改变') for w in descendants(win) if isinstance(w,ttk.Label))
    finally: app.quit()


def test_export_settings_ui_persists(tmp_path):
    root=tk.Tk(); root.withdraw(); app=Application(root,preferences_path=tmp_path/'prefs.json')
    try:
        app.export_settings_dialog(); win=dialog(root)
        entry=next(w for w in descendants(win) if type(w)==ttk.Entry); entry.insert(0,str(tmp_path))
        with patch('keyvault.app.messagebox.showinfo'): press(win,'保存导出设置')
        assert app.preferences.export_directory()==str(tmp_path)
    finally: app.quit()


def test_encrypted_rsa_native_paste_and_visible_password(tmp_path):
    root=tk.Tk(); app=Application(root,preferences_path=tmp_path/'prefs.json')
    errors=[]; root.report_callback_exception=lambda *a:errors.append(a[1])
    try:
        app.pair_check_dialog(); win=dialog(root); root.update()
        key=keys.generate('RSA-2048')
        public=keys.export_public(key,'PEM').decode()
        secret=keys.export_private(key,'PEM','synthetic export password').decode()
        text=next(w for w in descendants(win) if isinstance(w,tk.Text)); text.insert('1.0',public)
        entries=[w for w in descendants(win) if type(w)==ttk.Entry]
        # Test Tk's actual paste command with a synthetic selection provider, not the OS clipboard.
        root.tk.eval('rename ::tk::GetSelection ::tk::SavedGetSelection')
        root.tk.createcommand('::tk::GetSelection',lambda *a:secret)
        root.tk.call('ttk::entry::Paste',str(entries[1]))
        assert entries[1].get()==secret
        canvas=next(w for w in descendants(win) if isinstance(w,tk.Canvas))
        assert entries[2].winfo_rooty()+entries[2].winfo_height() <= canvas.winfo_rooty()+canvas.winfo_height()
        messages=[]
        def receive_error(title, message, **kw):
            messages.append(message)
            assert all(not entry.get() for entry in entries)
            assert any('导出文件时设置' in w.cget('text') for w in descendants(win) if isinstance(w,ttk.Label))
        with patch('keyvault.app.messagebox.showerror',side_effect=receive_error):
            press(win,'校验是否匹配')
        assert len(messages)==1 and messages[0].startswith('私钥：')
        root.tk.call('ttk::entry::Paste',str(entries[1]))
        entries[2].insert(0,'synthetic export password')
        with patch('keyvault.app.messagebox.showerror',side_effect=lambda *a,**k:errors.append(a)):
            press(win,'校验是否匹配')
        root.update()
        assert any(w.cget('text').startswith('匹配：') for w in descendants(win) if isinstance(w,ttk.Label))
        assert all(not entry.get() for entry in entries)
        assert not errors,errors
    finally: app.quit()
