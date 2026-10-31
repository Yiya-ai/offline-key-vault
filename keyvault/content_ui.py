"""Explicit local key conversion and authenticated content viewing."""
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox
from . import keys, conversion
from . import localdialog as filedialog
from .safeio import read_limited, write_new


def show_converter(app):
    from .app import UI_FONT, MUTED
    win, pane = app.dialog('密钥文本转文件 / 无需密钥库', 940, 740)
    ttk.Label(pane, text='公钥或私钥，直接转文件', font=(UI_FONT, 19, 'bold')).pack(anchor='w')
    ttk.Label(pane, text='只在本机校验和保存，不入库。私钥原文可见，请留意旁观者。', foreground=MUTED).pack(anchor='w', pady=8)
    mode = ttk.Combobox(pane, state='readonly', values=('自动识别', 'X25519 原始公钥', 'X25519 原始私钥'))
    mode.current(0); mode.pack(fill='x')
    columns = ttk.Frame(pane); columns.pack(fill='x', pady=12)
    columns.columnconfigure(0, weight=1, uniform='conversion'); columns.columnconfigure(1, weight=1, uniform='conversion')
    left = ttk.Frame(columns); left.grid(row=0, column=0, sticky='nsew', padx=(0, 12))
    right = ttk.Frame(columns); right.grid(row=0, column=1, sticky='nsew', padx=(12, 0))
    from .widgets import responsive_columns
    responsive_columns(columns, left, right)
    text = app.textfield(left, '密钥文本（保留换行和空格；有文本时优先）', height=6)
    text.configure(width=1)
    selected = [None]
    file_label = ttk.Label(left, text='未选择文件', foreground=MUTED); file_label.pack(anchor='w')
    def choose():
        ok, initial = app.attempt(lambda: app.preferences.directory('import'), win)
        if not ok: return
        path = filedialog.askopenfilename(parent=win, title='选择本地密钥文件', initialdir=initial)
        if path:
            ok, data = app.attempt(lambda: read_limited(path, keys.MAX_KEY_BYTES), win)
            if ok:
                selected[0] = data
                text.delete('1.0', 'end')
                file_label.configure(text='已选择：' + Path(path).name)
    ttk.Button(left, text='选择本地文件', command=choose).pack(anchor='w', pady=6)
    input_pw = app.field(left, '输入文件口令（未加密留空）', secret=True)
    entry_pw = app.field(left, 'JKS 条目口令（相同则留空）', secret=True)
    name = app.field(right, '输出文件名', 'key')
    formats = ('PEM', 'DER', 'OpenSSH', 'JWK', 'PKCS1-PEM', 'PKCS1-DER', 'SEC1-PEM', 'SEC1-DER', 'PPK-v3', 'PPK-v2', 'PKCS12', 'OpenPGP', 'OpenPGP-Binary', 'Raw-base64', 'Raw-base64url', 'Original')
    ttk.Label(right, text='输出格式（Original：逐字节保留原文）').pack(anchor='w', pady=(10, 5))
    fmt = ttk.Combobox(right, state='readonly', values=formats); fmt.set('PEM'); fmt.pack(fill='x')
    plain = tk.BooleanVar(win, value=False)
    ttk.Checkbutton(right, text='明确允许明文私钥 / 私钥原文输出', variable=plain).pack(anchor='w', pady=10)
    output_pw = app.field(right, '输出私钥口令（默认加密，至少 12 字符）', secret=True)
    repeat = app.field(right, '再次输入输出口令', secret=True)
    def changed(*args):
        disabled = plain.get() or fmt.get() == 'Original'
        for field in (output_pw, repeat):
            if disabled: field.delete(0, 'end')
            field.configure(state='disabled' if disabled else 'normal')
    plain.trace_add('write', changed); fmt.bind('<<ComboboxSelected>>', changed)
    notice = ttk.Label(pane, text='格式转换不改变密钥。重新加密的密文通常不同；Original 不改变原文件加密状态。', wraplength=720, foreground=MUTED)
    notice.pack(anchor='w', pady=12)
    def submit():
        data = text.get('1.0', 'end-1c')
        if not data.strip(): data = selected[0]
        raw_kind = {1:'X25519-public', 2:'X25519-private'}.get(mode.current())
        ok, inspected = app.attempt(lambda: conversion.inspect(data, input_pw.get(), raw_kind, entry_pw.get()), win)
        if not ok: return
        _, key = inspected
        private = keys.normalized(key)[1] is not None
        if private and fmt.get() != 'Original' and not plain.get() and output_pw.get() != repeat.get():
            messagebox.showerror('口令不一致', '两次输出口令必须一致。', parent=win); return
        if private and (plain.get() or fmt.get() == 'Original'):
            if not plain.get():
                messagebox.showerror('需要明确确认', '私钥原文可能未加密，请明确允许原文输出。', parent=win); return
            if not messagebox.askyesno('确认私钥输出', '输出内容可能是不受口令保护的私钥。确认继续？', parent=win, default='no'): return
        ok, result = app.attempt(lambda: conversion.convert(data, fmt.get(), input_pw.get(), output_pw.get(), plain.get(), raw_kind, entry_pw.get()), win)
        if not ok: return
        output, info = result
        extension = '.pem' if 'PEM' in fmt.get() else {'DER':'.der', 'PKCS1-DER':'.der', 'SEC1-DER':'.der', 'OpenSSH':'.key' if private else '.pub', 'JWK':'.jwk', 'PKCS12':'.p12', 'PPK-v3':'.ppk', 'PPK-v2':'.ppk', 'OpenPGP':'.asc', 'OpenPGP-Binary':'.pgp'}.get(fmt.get(), '.txt')
        if fmt.get() == 'Original': extension = conversion.original_extension(output)
        ok, defaults = app.attempt(lambda: app.export_defaults(name.get(), extension), win)
        if not ok: return
        path = filedialog.asksaveasfilename(parent=win, title='保存密钥文件', defaultextension=extension, **defaults)
        if not path: return
        ok, _ = app.attempt(lambda: write_new(path, output), win)
        if ok:
            text.delete('1.0', 'end'); selected[0] = None
            for field in (input_pw, entry_pw, output_pw, repeat): field.delete(0, 'end')
            win.destroy()
            messagebox.showinfo('密钥已保存', '已校验并保存到本机。没有创建或修改密钥库。', parent=app.root)
    ttk.Button(win.actions, text='校验并保存文件', style='Accent.TButton', command=submit).pack(side='right')
    ttk.Button(win.actions, text='关闭', command=win.destroy).pack(side='left')


def show_content(app):
    from .app import MUTED
    record = app.selected()
    if not record: return
    win, pane = app.dialog('查看密钥内容', 850, 700)
    ttk.Label(pane, text=record['name']).pack(anchor='w')
    ttk.Label(pane, text='公钥可直接查看。查看明文私钥需复核主口令；60 秒后隐藏，锁库立即关闭。内容不自动复制或写入文件。', wraplength=740, foreground=MUTED).pack(anchor='w', pady=10)
    text = app.textfield(pane, '密钥内容（库内规范化表示，可能与导入原文编码不同）', height=13)
    ok, public = app.attempt(lambda: app.vault.content(record['id']), win)
    if not ok: win.destroy(); return
    text.insert('1.0', public); text.configure(state='disabled')
    password = app.field(pane, '查看私钥前输入当前主口令', secret=True)
    timer = [None]
    def hide():
        if timer[0] is not None: win.after_cancel(timer[0]); timer[0] = None
        if not text.winfo_exists(): return
        text.configure(state='normal'); text.delete('1.0', 'end'); text.insert('1.0', public); text.configure(state='disabled')
    def reveal():
        hide()
        ok, value = app.attempt(lambda: app.vault.content(record['id'], private=True, password=password.get()), win)
        password.delete(0, 'end'); password.hide_secret()
        if not ok: return
        hide()
        text.configure(state='normal'); text.delete('1.0', 'end'); text.insert('1.0', value); text.configure(state='disabled')
        timer[0] = win.after(60000, hide)
    def destroyed(event):
        if event.widget == win and timer[0] is not None:
            win.after_cancel(timer[0]); timer[0] = None
    win.bind('<Destroy>', destroyed, add='+')
    ttk.Button(win.actions, text='显示私钥', command=reveal, state='normal' if record['has_private'] else 'disabled').pack(side='left')
    ttk.Button(win.actions, text='隐藏私钥 / 显示公钥', command=hide).pack(side='left', padx=8)
    ttk.Button(win.actions, text='关闭', command=win.destroy).pack(side='right')


def show_original_export(app):
    record = app.selected()
    if not record: return
    win, pane = app.dialog('导出导入原文', 720, 450)
    ttk.Label(pane, text='逐字节还原最近一次单记录导入内容').pack(anchor='w')
    ttk.Label(pane, text='保留原格式、换行和原有加密状态；不重新加密。原文可能含明文私钥，任何原有口令仍然有效。旧记录或多条目容器未保存原文时不可用。', wraplength=620).pack(anchor='w', pady=14)
    password = app.field(pane, '验证当前主口令', secret=True)
    def save():
        credential = password.get()
        password.delete(0, 'end')
        try:
            # Carry only format metadata across modal event loops, never key bytes.
            ok, extension = app.attempt(lambda: conversion.original_extension(
                app.vault.original_bytes(record['id'], credential)), win)
            if not ok: return
            if not messagebox.askyesno('原文可能含私钥', '确认按导入时的加密状态原样导出？不会增加新的文件口令。', parent=win, default='no'): return
            ok, defaults = app.attempt(lambda: app.export_defaults(record['name'] + '-original', extension), win)
            if not ok: return
            path = filedialog.asksaveasfilename(parent=win, title='保存导入原文（后缀不改变格式）', **defaults)
            if not path: return
            # Reauthenticate against the live vault at the actual write boundary.
            ok, _ = app.attempt(lambda: app.vault.export_original(record['id'], path, credential), win)
            if ok: win.destroy(); messagebox.showinfo('已保存', '内容与保存的导入原文逐字节一致。', parent=app.root)
        finally:
            credential = ''
    ttk.Button(win.actions, text='验证并导出原文', command=save, style='Accent.TButton').pack(side='right')
