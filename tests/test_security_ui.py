"""Exercise real Tk forms with synthetic data and local test paths."""
import tkinter as tk
from tkinter import ttk
from unittest.mock import patch
from keyvault.app import Application
from keyvault.protection import DESTROY_CONFIRMATION
from keyvault import keys

MASTER = 'synthetic UI master password 123'
RECOVERY = 'synthetic UI recovery password 456'
NEW = 'synthetic UI replacement password 789'


def descendants(widget):
    for child in widget.winfo_children():
        yield child
        yield from descendants(child)


def dialog(root):
    return next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel))


def press(widget, label):
    next(w for w in descendants(widget) if isinstance(w, ttk.Button) and w.cget('text') == label).invoke()


def fill(entry, text):
    entry.delete(0, 'end'); entry.insert(0, text)


def test_security_enrollment_and_recovery_forms(tmp_path):
    root = tk.Tk(); root.withdraw(); app = Application(root)
    errors = []
    root.report_callback_exception = lambda *args: errors.append(args[1])
    path, factor = tmp_path / 'ui-security.okv', tmp_path / 'ui-factor.okvr'
    try:
        with patch('keyvault.app.messagebox.showerror', side_effect=lambda title, text, **kw: errors.append(text)), patch('keyvault.app.messagebox.showinfo'):
            app.vault.create(path, MASTER)
            app.vault.add(keys.generate('Ed25519'), 'UI synthetic record')
            app.show_manager()
            app.security_dialog()
            win = dialog(root)
            mode = next(w for w in descendants(win) if isinstance(w, ttk.Combobox))
            mode.current(1); mode.event_generate('<<ComboboxSelected>>'); root.update()
            next(w for w in descendants(win) if isinstance(w, ttk.Checkbutton)).invoke()
            entries = [w for w in descendants(win) if type(w) == ttk.Entry]
            for entry, value in zip(entries, ['5', DESTROY_CONFIRMATION, RECOVERY, RECOVERY, MASTER]): fill(entry, value)
            with patch('keyvault.security_ui.filedialog.asksaveasfilename', return_value=str(factor)):
                press(win, '验证并保存安全设置')
            assert factor.exists() and app.vault.security_status()['recovery']
            assert app.vault.security_status()['max_failures'] == 5
            app.lock()
            with patch('keyvault.security_ui.filedialog.askopenfilename', return_value=str(path)):
                app.recovery_dialog()
            win = dialog(root)
            with patch('keyvault.security_ui.filedialog.askopenfilename', return_value=str(factor)):
                press(win, '选择恢复文件')
            for entry, value in zip([w for w in descendants(win) if type(w) == ttk.Entry], [RECOVERY, NEW, NEW]): fill(entry, value)
            press(win, '验证双因素并重置')
            root.update()
            assert app.vault.unlocked and len(app.rows) == 1
            app.vault.verify(NEW)
            assert not errors, errors
    finally:
        app.quit()


def test_destruction_clears_manager_and_dialogs(tmp_path):
    root = tk.Tk(); root.withdraw(); app = Application(root)
    callback_errors, messages = [], []
    root.report_callback_exception = lambda *args: callback_errors.append(args[1])
    try:
        app.vault.create(tmp_path / 'ui-destroy.okv', MASTER)
        app.vault.add(keys.generate('Ed25519'), 'UI synthetic record')
        app.vault.configure_security(MASTER, 5, confirmation=DESTROY_CONFIRMATION)
        app.show_manager(); app.password_dialog()
        win = dialog(root)
        with patch('keyvault.app.messagebox.showerror', side_effect=lambda title, text, **kw: messages.append(text)):
            for _ in range(5):
                assert app.attempt(lambda: app.vault.verify('wrong'), win) == (False, None)
            root.update()
        assert not app.vault.unlocked and not app.rows
        assert not any(isinstance(w, tk.Toplevel) for w in root.winfo_children())
        assert len(messages) == 5 and '已永久销毁' in messages[-1]
        assert not callback_errors, callback_errors
    finally:
        app.quit()


def test_security_cancel_does_not_migrate_or_enable(tmp_path):
    root = tk.Tk(); root.withdraw(); app = Application(root)
    path = tmp_path / 'ui-cancel.okv'
    try:
        app.vault.create(path, MASTER); app.show_manager()
        before = path.read_bytes()
        app.security_dialog(); win = dialog(root)
        next(w for w in descendants(win) if isinstance(w, ttk.Checkbutton)).invoke()
        press(win, '取消')
        assert path.read_bytes() == before and app.vault.security_status()['max_failures'] == 0
    finally:
        app.quit()


def test_security_controls_fit_small_window(tmp_path):
    root = tk.Tk(); app = Application(root)
    try:
        app.vault.create(tmp_path / 'layout.okv', MASTER)
        app.show_manager(); root.geometry('1040x680'); root.update()
        button = next(w for w in descendants(root) if isinstance(w, ttk.Button) and w.cget('text') == '安全设置')
        assert button.winfo_ismapped()
        assert button.winfo_rooty() + button.winfo_height() <= root.winfo_rooty() + root.winfo_height()
        offline = next(w for w in descendants(root) if isinstance(w, ttk.Label) and w.cget('text') == '不联网 · 不上传')
        assert offline.winfo_ismapped()
        assert offline.winfo_rooty() + offline.winfo_height() <= root.winfo_rooty() + root.winfo_height()
        app.security_dialog(); win = dialog(root); win.geometry('650x500'); root.update()
        action = next(w for w in descendants(win) if isinstance(w, ttk.Button) and w.cget('text') == '验证并保存安全设置')
        assert action.winfo_ismapped()
        assert action.winfo_rooty() + action.winfo_height() <= win.winfo_rooty() + win.winfo_height()
    finally:
        app.quit()
