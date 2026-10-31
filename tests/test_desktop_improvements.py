import base64
import json
from pathlib import Path
from unittest.mock import patch
import tkinter as tk
from tkinter import ttk
import pytest
from cryptography.hazmat.primitives import serialization as S
from keyvault import keys, conversion
from keyvault.vault import Vault
from keyvault.preferences import Preferences
from keyvault.app import Application
from test_ui import descendants, dialog, press

PASSWORD = 'synthetic master password'


def test_three_directories_migrate_and_preserve(tmp_path):
    prefs = Preferences(tmp_path / 'prefs.json')
    prefs.save(tmp_path)
    assert prefs.load_all()['export_directory'] == str(tmp_path)
    for name in ('vaults', 'imports'): (tmp_path/name).mkdir()
    prefs.save_all(tmp_path, tmp_path/'vaults', tmp_path/'imports')
    assert Preferences(prefs.path).directory('vault') == str(tmp_path/'vaults')
    prefs.save('')
    assert prefs.directory('import') == str(tmp_path/'imports')
    assert prefs.export_directory() == ''
    before = prefs.path.read_bytes()
    with pytest.raises(ValueError): prefs.save_all('', r'\\host\share', '')
    assert prefs.path.read_bytes() == before


@pytest.mark.parametrize('encrypted', [False, True])
def test_original_survives_reopen_without_leaking_in_listing(tmp_path, encrypted):
    key = keys.generate('Ed25519')
    source = keys.export_private(key, 'PEM', PASSWORD, plaintext=not encrypted).replace(b'\n', b'\r\n')
    source = b'\xef\xbb\xbf' + source
    vault = Vault(); file = tmp_path/'vault.okv'
    try:
        vault.create(file, PASSWORD)
        rid, _ = vault.add_many([keys.import_key(source, PASSWORD if encrypted else '')], 'sample', source=source)
        assert 'original' not in vault.records()[0]
        assert source not in file.read_bytes()
        assert base64.b64encode(source) not in file.read_bytes()
        vault.close(); vault.open(file, PASSWORD)
        with pytest.raises(ValueError): vault.original_bytes(rid, 'wrong password')
        assert vault.original_bytes(rid, PASSWORD) == source
        vault.export_original(rid, tmp_path/'original.txt', PASSWORD)
        assert (tmp_path/'original.txt').read_bytes() == source
        vault.export(rid, tmp_path/'new.pem', 'PEM', private=True, password=PASSWORD, export_password=PASSWORD)
        restored = S.load_pem_private_key((tmp_path/'new.pem').read_bytes(), PASSWORD.encode())
        assert keys.fingerprint(restored) == keys.fingerprint(key)
        assert (tmp_path/'new.pem').read_bytes() != source
    finally: vault.close()


def test_original_is_not_saved_for_multi_record_container(tmp_path):
    vault = Vault()
    try:
        vault.create(tmp_path/'multi.okv', PASSWORD)
        vault.add_many([keys.generate('Ed25519'), keys.generate('X25519')], 'multi', source=b'synthetic multi container')
        assert all(not r['has_original'] for r in vault.records())
    finally: vault.close()


def test_private_converter_rejects_no_export_password_and_preserves_identity():
    key = keys.generate('RSA-2048')
    source = keys.export_private(key, 'PKCS1-PEM', plaintext=True)
    with pytest.raises(ValueError): conversion.convert(source)
    result, info = conversion.convert(source, export_password=PASSWORD)
    assert info['private']
    with pytest.raises((ValueError, TypeError)): S.load_pem_private_key(result, None)
    assert S.load_pem_private_key(result, PASSWORD.encode()).private_numbers() == key.private_numbers()
    with pytest.raises(ValueError): conversion.convert(source, 'Original')
    assert conversion.convert(source, 'Original', plaintext=True)[0] == source


def test_private_content_requires_reauthentication(tmp_path):
    vault = Vault()
    try:
        vault.create(tmp_path/'view.okv', PASSWORD)
        rid,_=vault.add(keys.generate('Ed25519'), 'sample')
        assert 'PUBLIC KEY' in vault.content(rid)
        with pytest.raises(ValueError): vault.content(rid, private=True, password='wrong')
        assert 'PRIVATE KEY' in vault.content(rid, private=True, password=PASSWORD)
        vault.close()
        with pytest.raises(ValueError): vault.content(rid)
    finally: vault.close()


def test_password_toggle_and_form_wheel(tmp_path):
    root=tk.Tk(); app=Application(root,preferences_path=tmp_path/'prefs.json')
    try:
        win,pane=app.dialog('test',650,440)
        entry=app.field(pane,'password',secret=True); entry.insert(0,PASSWORD)
        for i in range(25): app.field(pane, 'synthetic '+str(i))
        root.update()
        entry.visibility_button.invoke(); assert not entry.cget('show')
        entry.visibility_button.invoke(); assert entry.cget('show')
        canvas=next(w for w in descendants(win) if isinstance(w,tk.Canvas))
        before=canvas.yview()[0]
        entry.event_generate('<MouseWheel>',delta=-120);root.update()
        assert canvas.yview()[0]>before
    finally:app.quit()


def test_directory_input_refreshes_without_go_button(tmp_path):
    from keyvault.localdialog import askdirectory
    root=tk.Tk();root.withdraw()
    folder=tmp_path/'child';folder.mkdir();(folder/'synthetic.txt').write_text('test')
    errors=[]
    root.report_callback_exception=lambda *a:errors.append(a[1])
    def edit():
        win=dialog(root)
        entry=next(w for w in descendants(win) if type(w)==ttk.Entry)
        entry.delete(0,'end');entry.insert(0,str(folder))
        def confirm():
            box=next(w for w in descendants(win) if isinstance(w,tk.Listbox))
            assert any('synthetic.txt' in row for row in box.get(0,'end'))
            press(win,'选择此目录')
        root.after(450,confirm)
    try:
        root.after(50,edit)
        root.after(3000,lambda: dialog(root).destroy() if any(isinstance(c,tk.Toplevel) for c in root.winfo_children()) else None)
        assert askdirectory(parent=root,initialdir=str(tmp_path))==str(folder)
        assert not errors
    finally:root.destroy()


def test_locked_private_conversion_ui(tmp_path):
    root=tk.Tk();root.withdraw();app=Application(root,preferences_path=tmp_path/'prefs.json')
    errors=[]; root.report_callback_exception=lambda *a:errors.append(a[1])
    try:
        app.convert_key_dialog();win=dialog(root)
        source=keys.export_private(keys.generate('Ed25519'),'PEM',plaintext=True).decode()
        next(w for w in descendants(win) if isinstance(w,tk.Text)).insert('1.0',source)
        entries=[w for w in descendants(win) if type(w)==ttk.Entry]
        entries[-2].insert(0,PASSWORD);entries[-1].insert(0,PASSWORD)
        with patch('keyvault.content_ui.filedialog.asksaveasfilename',return_value=str(tmp_path/'converted.pem')),patch('keyvault.content_ui.messagebox.showinfo'),patch('keyvault.app.messagebox.showerror',side_effect=lambda *a,**kw:errors.append(a)):
            press(win,'校验并保存文件')
        assert not app.vault.unlocked
        assert keys.fingerprint(keys.import_key((tmp_path/'converted.pem').read_bytes(),PASSWORD))==keys.fingerprint(keys.import_key(source))
        assert not errors
    finally:app.quit()


def test_private_view_is_cleared_on_lock(tmp_path):
    root=tk.Tk();root.withdraw();app=Application(root,preferences_path=tmp_path/'prefs.json')
    try:
        app.vault.create(tmp_path/'view.okv',PASSWORD)
        rid,_=app.vault.add(keys.generate('Ed25519'),'sample')
        app.show_manager();app.tree.selection_set(rid)
        app.view_key_dialog();win=dialog(root)
        entry=next(w for w in descendants(win) if type(w)==ttk.Entry);entry.insert(0,PASSWORD)
        press(win,'显示私钥')
        text=next(w for w in descendants(win) if isinstance(w,tk.Text))
        assert 'PRIVATE KEY' in text.get('1.0','end')
        press(win,'隐藏私钥 / 显示公钥')
        assert 'PRIVATE KEY' not in text.get('1.0','end')
        entry.insert(0,PASSWORD);press(win,'显示私钥')
        app.lock();assert not win.winfo_exists()
    finally:app.quit()


def test_latest_typed_folder_used_before_debounce(tmp_path):
    from keyvault.localdialog import asksaveasfilename
    root=tk.Tk();root.withdraw()
    child=tmp_path/'child';child.mkdir()
    def submit():
        win=dialog(root)
        entries=[w for w in descendants(win) if type(w)==ttk.Entry]
        entries[0].delete(0,'end');entries[0].insert(0,str(child))
        entries[-1].insert(0,'synthetic.pem')
        press(win,'保存到此位置')
    try:
        root.after(50,submit)
        assert asksaveasfilename(parent=root,initialdir=str(tmp_path))==str(child/'synthetic.pem')
    finally:root.destroy()


def test_converter_output_password_is_visible_without_scrolling(tmp_path):
    root=tk.Tk();app=Application(root,preferences_path=tmp_path/'prefs.json')
    try:
        app.convert_key_dialog();win=dialog(root);root.update()
        entries=[w for w in descendants(win) if type(w)==ttk.Entry]
        canvas=next(w for w in descendants(win) if isinstance(w,tk.Canvas))
        for entry in entries[-2:]:
            assert entry.winfo_rooty()+entry.winfo_height() <= canvas.winfo_rooty()+canvas.winfo_height()
    finally:app.quit()
