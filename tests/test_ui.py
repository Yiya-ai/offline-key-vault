import os
from pathlib import Path
import sys
import tkinter as tk
from tkinter import ttk
from unittest.mock import patch
from keyvault.offline import install
from keyvault.app import Application
from keyvault import keys


def descendants(widget):
    for child in widget.winfo_children():
        yield child
        yield from descendants(child)


def dialog(root):
    return next(c for c in root.winfo_children() if isinstance(c, tk.Toplevel))


def press(widget, text):
    next(w for w in descendants(widget) if isinstance(w, ttk.Button) and w.cget('text') == text).invoke()


def test_desktop_workflow(tmp_path):
    root = tk.Tk()
    root.withdraw()
    app = Application(root)
    errors = []
    root.report_callback_exception = lambda *args: errors.append(args[1])
    try:
        with patch('keyvault.app.messagebox.showerror', side_effect=lambda title, text, **kw: errors.append(text)), patch('keyvault.app.messagebox.showinfo'):
            app.vault.create(tmp_path / 'ui.okv', 'test desktop password 123')
            app.show_manager()
            root.update()
            app.generate_dialog()
            win = dialog(root)
            entries = [w for w in descendants(win) if type(w) == ttk.Entry]
            entries[0].insert(0, '界面测试密钥')
            entries[1].insert(0, '测试, 签名')
            press(win, '生成并加密保存')
            root.update()
            assert len(app.rows) == 1
            rid = next(iter(app.rows))
            app.tree.selection_set(rid)
            app.edit_dialog()
            win = dialog(root)
            entry = next(w for w in descendants(win) if type(w) == ttk.Entry)
            entry.delete(0, 'end'); entry.insert(0, '已编辑名称')
            press(win, '保存修改')
            root.update()
            assert app.rows[rid]['name'] == '已编辑名称'
            app.export_dialog(False)
            win = dialog(root)
            with patch('keyvault.app.filedialog.asksaveasfilename', return_value=str(tmp_path / 'public.pem')):
                press(win, '导出文件')
            assert (tmp_path / 'public.pem').exists()
            app.export_dialog(True)
            win = dialog(root)
            entries = [w for w in descendants(win) if type(w) == ttk.Entry]
            for entry, value in zip(entries, ['test desktop password 123', 'export passphrase 123', 'export passphrase 123']):
                entry.insert(0, value)
            with patch('keyvault.app.filedialog.asksaveasfilename', return_value=str(tmp_path / 'private.pem')):
                press(win, '验证并导出')
            assert keys.fingerprint(keys.import_key((tmp_path / 'private.pem').read_bytes(), 'export passphrase 123')) == app.rows[rid]['fingerprint']
            app.import_dialog()
            win = dialog(root)
            entries = [w for w in descendants(win) if type(w) == ttk.Entry]
            entries[2].insert(0, '导入的公钥')
            next(w for w in descendants(win) if isinstance(w, tk.Text)).insert('1.0', keys.export_public(keys.generate('X25519'), 'PEM').decode())
            press(win, '校验并加密入库')
            assert len(app.rows) == 2
            app.import_dialog()
            app.last_activity -= 301
            app.tick()
            assert not app.vault.unlocked
            assert not any(isinstance(c, tk.Toplevel) for c in root.winfo_children())
            assert not app.rows
            assert not errors, errors
    finally:
        app.quit()

def test_local_file_chooser(tmp_path):
    from keyvault.localdialog import asksaveasfilename, askopenfilename
    root = tk.Tk()
    root.withdraw()
    target = tmp_path / 'new-file.okv'
    errors = []
    def fill_and_press(label, value):
        win = dialog(root)
        entries = [w for w in descendants(win) if type(w) == ttk.Entry]
        entries[-1].delete(0, 'end')
        entries[-1].insert(0, str(value))
        press(win, label)
    try:
        root.after(50, lambda: fill_and_press('保存到此位置', target))
        assert asksaveasfilename(parent=root, defaultextension='.okv') == str(target)
        target.write_bytes(b'file chooser test only')
        root.after(50, lambda: fill_and_press('打开', target))
        assert askopenfilename(parent=root) == str(target)
        def try_remote():
            fill_and_press('打开', r'\\example\share\key.pem')
            dialog(root).destroy()
        with patch('keyvault.localdialog.messagebox.showerror', side_effect=lambda *a, **k: errors.append(a)):
            root.after(50, try_remote)
            assert askopenfilename(parent=root) == ''
        assert errors
    finally:
        root.destroy()


def test_manager_action_buttons_visible(tmp_path):
    root = tk.Tk()
    app = Application(root)
    try:
        app.vault.create(tmp_path / 'layout.okv', 'layout-only password 123')
        app.show_manager()
        root.geometry('1040x680')
        root.update()
        for label in ('编辑名称 / 标签 / 备注', '导出公钥文件', '导出私钥文件', '删除记录'):
            button = app.detail_buttons[label]
            assert button.winfo_ismapped()
            assert button.winfo_rooty() + button.winfo_height() <= root.winfo_rooty() + root.winfo_height()
            assert button.winfo_rooty() + button.winfo_height() <= button.master.winfo_rooty() + button.master.winfo_height()
    finally:
        app.quit()
