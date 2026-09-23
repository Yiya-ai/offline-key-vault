"""Offline export preferences and public/private key matching tools."""
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox
from . import localdialog as filedialog
from .safeio import local_path, read_limited
from . import keys


def show_export_settings(app):
    from .app import UI_FONT, MUTED
    win, pane = app.dialog('导出设置', 710, 440)
    ttk.Label(pane, text='默认导出目录', font=(UI_FONT, 19, 'bold')).pack(anchor='w')
    try:
        saved = app.preferences.load()
        notice = '公钥、私钥和公钥文本转换共用此目录；每次导出仍可选择其他位置。'
    except (ValueError, OSError):
        saved = ''
        notice = '原设置无法读取；可重新选择目录并保存。'
    ttk.Label(pane, text=notice, wraplength=620, foreground=MUTED).pack(anchor='w', pady=12)
    folder = app.field(pane, '本地目录（留空使用本机用户目录）', saved)
    def choose():
        initial = ''
        if folder.get().strip():
            ok, initial = app.attempt(lambda: str(local_path(folder.get().strip(), directory=True)), win)
            if not ok: return
        path = filedialog.askdirectory(parent=win, title='选择默认导出目录（非云同步目录）', initialdir=initial)
        if path:
            folder.delete(0, 'end'); folder.insert(0, path)
    row = ttk.Frame(pane); row.pack(fill='x', pady=12)
    ttk.Button(row, text='选择本地目录', command=choose).pack(side='left')
    ttk.Button(row, text='清除默认目录', command=lambda: folder.delete(0, 'end')).pack(side='left', padx=10)
    ttk.Label(pane, text='设置仅在当前用户的本机保存，不保存密钥或口令。目录不能是网络共享或链接。文件默认以密钥名称命名，已有文件不会覆盖。', wraplength=620, foreground=MUTED).pack(anchor='w', pady=12)
    def save():
        ok, _ = app.attempt(lambda: app.preferences.save(folder.get().strip()), win)
        if ok:
            win.destroy()
            messagebox.showinfo('设置已保存', '默认导出目录已保存，重启后仍然生效。', parent=app.root)
    ttk.Button(win.actions, text='保存导出设置', style='Accent.TButton', command=save).pack(side='right')
    ttk.Button(win.actions, text='取消', command=win.destroy).pack(side='left')


def show_pair_check(app):
    from .app import UI_FONT, MUTED
    from .paircheck import compare, PairCheckError
    win, pane = app.dialog('公钥 / 私钥配对校验', 940, 740)
    win.minsize(min(820, win.winfo_screenwidth() - 80), min(620, win.winfo_screenheight() - 130))
    ttk.Label(pane, text='这两把密钥是否匹配？', font=(UI_FONT, 20, 'bold')).pack(anchor='w')
    ttk.Label(pane, text='本机导出的私钥默认加密，请填写导出时设置的口令。格式读取失败不等于密钥不匹配。', foreground=MUTED, wraplength=820).pack(anchor='w', pady=(8, 10))
    mode = ttk.Combobox(pane, state='readonly', values=('自动识别格式', 'X25519 原始 Base64 / Base64url'))
    mode.current(0); mode.pack(fill='x', pady=(0, 12))
    columns = ttk.Frame(pane); columns.pack(fill='x')
    columns.columnconfigure(0, weight=1, uniform='input'); columns.columnconfigure(1, weight=1, uniform='input')
    left_pane = ttk.Frame(columns); left_pane.grid(row=0, column=0, sticky='nsew', padx=(0, 12))
    right_pane = ttk.Frame(columns); right_pane.grid(row=0, column=1, sticky='nsew', padx=(12, 0))
    ttk.Label(left_pane, text='01  公钥 / 证书', font=(UI_FONT, 12, 'bold')).pack(anchor='w')
    public = app.textfield(left_pane, '粘贴完整文本，或选择本地文件', height=5)
    public.configure(width=1)
    public_path, private_path = tk.StringVar(win), tk.StringVar(win)
    public_label = ttk.Label(left_pane, text='尚未选择公钥文件', foreground=MUTED, wraplength=360)
    public_label.pack(anchor='w', pady=6)
    private = None
    result = ttk.Label(win.actions, text='等待校验', wraplength=840, foreground=MUTED)
    clearing = [False]
    def invalidate(event=None):
        if not clearing[0]:
            result.configure(text='输入已改变，请重新校验', foreground=MUTED)
    def choose(is_private):
        path = filedialog.askopenfilename(parent=win, title='选择私钥文件' if is_private else '选择公钥或证书文件', filetypes=[('密钥文件', '*.*')])
        if path:
            if is_private:
                private_path.set(path); private.delete(0, 'end'); private_label.configure(text=Path(path).name)
            else:
                public_path.set(path); public.delete('1.0', 'end'); public_label.configure(text=Path(path).name)
            invalidate()
    ttk.Button(left_pane, text='选择公钥文件', command=lambda: choose(False)).pack(anchor='w')
    public_pw = app.field(left_pane, '公钥容器口令（仅 JKS 等需要）', secret=True)
    ttk.Label(right_pane, text='02  私钥与解密口令', font=(UI_FONT, 12, 'bold')).pack(anchor='w')
    private = app.field(right_pane, '私钥文本（隐藏输入，可粘贴多行）', secret=True)
    private_label = ttk.Label(right_pane, text='尚未选择私钥文件', foreground=MUTED, wraplength=360)
    private_label.pack(anchor='w', pady=6)
    ttk.Button(right_pane, text='选择私钥文件', command=lambda: choose(True)).pack(anchor='w')
    private_pw = app.field(right_pane, '私钥解密口令（导出时设置的口令）', secret=True)
    ttk.Label(right_pane, text='不是密钥库主口令。仅未加密私钥留空。', foreground='#996114', wraplength=360).pack(anchor='w', pady=6)
    entry_pw = app.field(right_pane, 'JKS 条目口令（与容器口令相同则留空）', secret=True)
    result.pack(fill='x', pady=(0, 8))
    ttk.Label(pane, text='有粘贴文本时优先使用文本。校验后清空私钥输入和口令；可选择原始文件以便重试。全程只读，不入库、不导出、不上传。证书仅比较公钥，不判断信任与有效性。', wraplength=820, foreground=MUTED).pack(anchor='w', pady=(16, 0))
    for widget in (public, private, public_pw, private_pw, entry_pw):
        widget.bind('<KeyRelease>', invalidate, add='+')
    for entry in (private, public_pw, private_pw, entry_pw):
        variable = tk.StringVar(win, value=entry.get())
        entry.configure(textvariable=variable)
        entry.input_variable = variable
        variable.trace_add('write', lambda *args: invalidate())
    def public_changed(event=None):
        if public.edit_modified():
            public.edit_modified(False)
            invalidate()
    public.bind('<<Modified>>', public_changed)
    mode.bind('<<ComboboxSelected>>', invalidate)
    def submit():
        public.edit_modified(False)
        result.configure(text='正在校验…', foreground=MUTED)
        error_text = ['']
        def read_source(text, path, side):
            if text: return text
            if not path: raise PairCheckError(side, 'missing', '请粘贴完整文本或选择本地文件。')
            try:
                return read_limited(path, keys.MAX_KEY_BYTES)
            except (ValueError, OSError):
                raise PairCheckError(side, 'file', '无法读取所选本地文件，请检查文件位置、权限及大小（最多 128 KiB）。') from None
        def action():
            try:
                left = read_source(public.get('1.0', 'end-1c').strip(), public_path.get(), 'public')
                right = read_source(private.get().strip(), private_path.get(), 'private')
                return compare(left, right, private_pw.get(), public_password=public_pw.get(), raw=mode.current() == 1, private_entry_password=entry_pw.get())
            except PairCheckError as error:
                error_text[0] = str(error)
                result.configure(text=error_text[0], foreground='#dc3545')
                raise
            finally:
                # Clear before error dialogs are shown, without erasing the diagnostic.
                clearing[0] = True
                try:
                    for entry in (private, public_pw, private_pw, entry_pw):
                        entry.delete(0, 'end')
                finally:
                    clearing[0] = False
        ok, value = app.attempt(action, win)
        if not win.winfo_exists(): return
        if not ok:
            result.configure(text=error_text[0] or '未完成校验，请检查输入格式和文件口令。尚未判断是否匹配。', foreground='#dc3545')
            return
        title = '匹配：公钥与私钥属于同一密钥对' if value['matched'] else '不匹配：所选校验范围内的公私钥参数不一致'
        result.configure(text=title + '\n范围：' + value['scope'] + '\n公钥：' + value['public_algorithm'] + '  ' + value['public_fingerprint'] + '\n私钥推导公钥：' + value['private_algorithm'] + '  ' + value['derived_fingerprint'], foreground='#33816d' if value['matched'] else '#dc3545')
    ttk.Button(win.actions, text='校验是否匹配', style='Accent.TButton', command=submit).pack(side='right')
    ttk.Button(win.actions, text='关闭', command=win.destroy).pack(side='left')
