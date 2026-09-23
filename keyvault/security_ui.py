"""Local security configuration and two-factor password reset dialogs."""
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox
from . import localdialog as filedialog
from .protection import DESTROY_CONFIRMATION


def policy_text(status):
    if not status['max_failures']:
        return '自毁未启用。' + ('已配置双因素恢复。' if status['recovery'] else '未配置密码恢复。')
    remaining = status['max_failures'] - status['failures']
    return f"已启用永久自毁：再失败 {remaining} 次，将销毁当前库及恢复入口。恢复口令验证也计入次数。"


def show_settings(app):
    from .app import UI_FONT
    status = app.vault.security_status()
    win, pane = app.dialog('安全设置', 740, 740)
    ttk.Label(pane, text='保护与恢复', font=(UI_FONT, 20, 'bold')).pack(anchor='w')
    ttk.Label(pane, text=policy_text(status), wraplength=645, foreground='#777783').pack(anchor='w', pady=(10, 16))
    enabled = tk.BooleanVar(win, value=bool(status['max_failures']))
    ttk.Checkbutton(pane, text='连续凭据校验失败后，永久销毁当前密钥库', variable=enabled).pack(anchor='w')
    threshold = app.field(pane, '失败次数上限（5–100；默认 10）', str(status['max_failures'] or 10))
    ttk.Label(pane, text='成功校验会清零；次数跨重启保存。解锁、恢复、私钥导出等主口令校验共用计数。\n达到上限后，恢复口令和恢复文件也无法恢复当前库。', wraplength=645, foreground='#dc3545').pack(anchor='w', pady=10)
    confirmation = app.field(pane, '启用自毁时，请输入：' + DESTROY_CONFIRMATION)
    ttk.Separator(pane).pack(fill='x', pady=18)
    ttk.Label(pane, text='离线双因素恢复').pack(anchor='w')
    mode = ttk.Combobox(pane, state='readonly', values=('保持现有恢复设置', '设置 / 更换恢复凭据', '关闭恢复功能'))
    mode.current(0)
    mode.pack(fill='x', pady=8)
    recovery = app.field(pane, '恢复口令（至少 12 字符，必须不同于主口令）', secret=True)
    repeat = app.field(pane, '再次输入恢复口令', secret=True)
    def mode_changed(event=None):
        state = 'normal' if mode.current() == 1 else 'disabled'
        recovery.configure(state=state); repeat.configure(state=state)
    mode.bind('<<ComboboxSelected>>', mode_changed)
    mode_changed()
    ttk.Label(pane, text='恢复需要同时持有恢复口令与独立恢复文件，请分开保管。保存时选择恢复文件位置。更换凭据会使旧凭据对当前库失效。', wraplength=645, foreground='#777783').pack(anchor='w', pady=10)
    master = app.field(pane, '当前主口令（保存设置前校验）', secret=True)
    ttk.Label(pane, text='仅作用于当前文件，不能销毁历史备份、导出文件或 SSD 历史块。离线计数不能阻止文件回滚或对复制文件的破解。保存后升级为 OKV2，旧版程序不能打开，请使用新版并重新备份。', wraplength=645, foreground='#777783').pack(anchor='w', pady=12)
    def submit():
        try:
            maximum = int(threshold.get()) if enabled.get() else 0
            if enabled.get() and not 5 <= maximum <= 100:
                raise ValueError()
        except ValueError:
            messagebox.showerror('检查次数', '请输入 5 到 100 的整数。', parent=win)
            return
        if enabled.get() and confirmation.get() != DESTROY_CONFIRMATION:
            messagebox.showerror('确认销毁范围', '请输入“' + DESTROY_CONFIRMATION + '”后再保存。', parent=win)
            return
        options = {'max_failures': maximum, 'confirmation': confirmation.get(), 'remove_recovery': mode.current() == 2}
        if mode.current() == 1:
            if recovery.get() != repeat.get():
                messagebox.showerror('口令不一致', '两次恢复口令必须一致。', parent=win)
                return
            path = filedialog.asksaveasfilename(parent=win, title='保存独立恢复文件（建议离线移动介质，与恢复口令分开保管）', defaultextension='.okvr', filetypes=[('离线恢复文件', '*.okvr')])
            if not path:
                return
            options.update(recovery_password=recovery.get(), recovery_path=path)
        ok, _ = app.attempt(lambda: app.vault.configure_security(master.get(), **options), win)
        master.delete(0, 'end')
        if ok:
            win.destroy()
            messagebox.showinfo('安全设置已保存', '设置仅对当前库生效。请妥善分开保存恢复材料，并重新制作加密备份。', parent=app.root)
    ttk.Button(win.actions, text='验证并保存安全设置', style='Accent.TButton', command=submit).pack(side='right')
    ttk.Button(win.actions, text='取消', command=win.destroy).pack(side='left')


def show_recovery(app):
    from .app import UI_FONT
    path = filedialog.askopenfilename(parent=app.root, title='选择需要恢复的本地密钥库', filetypes=[('加密密钥库', '*.okv'), ('所有文件', '*.*')])
    if not path:
        return
    ok, status = app.attempt(lambda: app.vault.inspect_security(path))
    if not ok:
        return
    if not status['recovery']:
        messagebox.showerror('未配置恢复', '必须在忘记主口令前，先在安全设置中配置双因素恢复。无法找回原口令。', parent=app.root)
        return
    win, pane = app.dialog('双因素恢复 / 重置主口令', 720, 670)
    ttk.Label(pane, text='重新掌握你的密钥库', font=(UI_FONT, 19, 'bold')).pack(anchor='w')
    ttk.Label(pane, text=Path(path).name, foreground='#777783').pack(anchor='w', pady=8)
    notice = ttk.Label(pane, text=policy_text(status), wraplength=625, foreground='#dc3545')
    notice.pack(anchor='w', pady=8)
    selected = tk.StringVar(win)
    file_label = ttk.Label(pane, text='尚未选择恢复文件', wraplength=625, foreground='#777783')
    file_label.pack(anchor='w', pady=8)
    def choose():
        value = filedialog.askopenfilename(parent=win, title='选择独立恢复文件', filetypes=[('离线恢复文件', '*.okvr'), ('所有文件', '*.*')])
        if value:
            selected.set(value)
            file_label.configure(text=Path(value).name)
    ttk.Button(pane, text='选择恢复文件', command=choose).pack(anchor='w')
    password = app.field(pane, '恢复口令', secret=True)
    new = app.field(pane, '新主口令（至少 12 字符，必须不同于恢复口令）', secret=True)
    repeat = app.field(pane, '再次输入新主口令', secret=True)
    ttk.Label(pane, text='两份材料缺一不可。验证通过后重置主口令并解锁，不会显示旧口令。历史备份的口令不会改变。已触发销毁的当前库无法恢复。', wraplength=625, foreground='#777783').pack(anchor='w', pady=16)
    def submit():
        if not selected.get():
            messagebox.showerror('缺少恢复文件', '请先选择独立恢复文件。', parent=win)
            return
        if new.get() != repeat.get():
            messagebox.showerror('口令不一致', '两次新主口令必须一致。', parent=win)
            return
        ok, _ = app.attempt(lambda: app.vault.recover(path, password.get(), selected.get(), new.get()), win)
        password.delete(0, 'end')
        if ok:
            app.failures, app.retry_at = 0, 0
            win.destroy()
            app.show_manager()
            messagebox.showinfo('已重置主口令', '当前库已使用新主口令。请重新制作加密备份。', parent=app.root)
        else:
            try:
                notice.configure(text=policy_text(app.vault.inspect_security(path)))
            except (ValueError, OSError):
                notice.configure(text='当前库不可用，请关闭对话框后检查文件。')
    ttk.Button(win.actions, text='验证双因素并重置', style='Accent.TButton', command=submit).pack(side='right')
    ttk.Button(win.actions, text='取消', command=win.destroy).pack(side='left')
