"""Explicit opt-in interface for a locally supplied PKCS#11 driver."""
import hashlib
import os
import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from . import localdialog as filedialog
from .safeio import read_limited
from .widgets import responsive_columns


def show(app):
    from .app import UI_FONT, MUTED
    win, pane = app.dialog('硬件令牌 / PKCS#11', 900, 760)
    pane.configure(padding=(24, 24, 24, 12))
    ttk.Label(pane, text='硬件令牌', font=(UI_FONT, 20, 'bold')).pack(anchor='w')
    ttk.Label(pane, text='连接本地 PKCS#11 设备，管理留存在设备中的密钥。', foreground=MUTED).pack(anchor='w', pady=(6, 12))
    ttk.Label(pane, text='驱动连接', font=(UI_FONT, 11, 'bold')).pack(anchor='w')
    ttk.Label(pane, text='模块路径', foreground=MUTED).pack(anchor='w', pady=(8, 4))
    driver_row = ttk.Frame(pane); driver_row.pack(fill='x')
    driver = ttk.Entry(driver_row); driver.pack(side='left', fill='x', expand=True)
    ttk.Label(pane, text='已核对的模块 SHA-256', foreground=MUTED).pack(anchor='w', pady=(8, 4))
    digest_row = ttk.Frame(pane); digest_row.pack(fill='x')
    digest = ttk.Entry(digest_row); digest.pack(side='left', fill='x', expand=True)
    state = {'token': None, 'slots': [], 'keys': []}
    status = ttk.Label(pane, text='尚未连接设备', foreground=MUTED, font=(UI_FONT, 9)); status.pack(anchor='w', pady=(6, 0))
    ttk.Separator(pane).pack(fill='x', pady=10)
    columns = ttk.Frame(pane); columns.pack(fill='x')
    left = ttk.Frame(columns); right = ttk.Frame(columns)
    left.grid(row=0, column=0, sticky='nsew'); right.grid(row=0, column=1, sticky='nsew')
    responsive_columns(columns, left, right, minimum=320)
    ttk.Label(left, text='设备与公钥', font=(UI_FONT, 11, 'bold')).pack(anchor='w')
    ttk.Label(left, text='设备', foreground=MUTED).pack(anchor='w', pady=(8, 4))
    slot = ttk.Combobox(left, state='disabled'); slot.set('请先连接设备'); slot.pack(fill='x')
    pin = app.field(left, '用户 PIN（仅用于当前操作）', secret=True)
    ttk.Label(left, text='设备公钥', foreground=MUTED).pack(anchor='w', pady=(8, 4))
    public_row = ttk.Frame(left); public_row.pack(fill='x')
    selected = ttk.Combobox(public_row, state='disabled', width=12)
    selected.set('读取后选择公钥'); selected.pack(side='left', fill='x', expand=True)
    key_actions = ttk.Frame(left); key_actions.pack(fill='x', pady=(8, 0))
    ttk.Label(right, text='在设备上生成密钥', font=(UI_FONT, 11, 'bold')).pack(anchor='w')
    ttk.Label(right, text='生成 RSA-3072 密钥对。私钥标记为敏感且不可导出，始终留在设备中。', foreground=MUTED).pack(anchor='w', pady=(10, 4))
    label = app.field(right, '新设备密钥名称')
    generation = ttk.Frame(right); generation.pack(fill='x', pady=(8, 0))
    ttk.Label(right, text='需要已连接设备和有效 PIN；生成前会再次确认。', foreground=MUTED, font=(UI_FONT, 9)).pack(anchor='w', pady=(10, 0))
    ttk.Label(pane, text='只加载已核对来源的厂商驱动。驱动是本机可执行代码，严格离线时请断网使用。此工具不重置设备、不导出设备私钥。', foreground=MUTED, font=(UI_FONT, 9)).pack(anchor='w', pady=(12, 0))
    def update_actions(event=None):
        connected = state['token'] is not None and 0 <= slot.current() < len(state['slots'])
        available = connected and 0 <= selected.current() < len(state['keys'])
        for button, enabled in ((read_button, connected), (generate_button, connected), (challenge_button, available), (save_button, available and app.vault.unlocked)):
            button.configure(state='normal' if enabled else 'disabled')
    def choose():
        path = filedialog.askopenfilename(parent=win, title='选择厂商 PKCS#11 驱动', filetypes=[('驱动模块', '*.dll *.dylib *.so'), ('所有文件', '*.*')])
        if path:
            ok, data = app.attempt(lambda: read_limited(path, 64 * 1024 * 1024), win)
            if ok:
                driver.delete(0, 'end'); driver.insert(0, path)
                digest.delete(0, 'end'); digest.insert(0, hashlib.sha256(data).hexdigest())
    ttk.Button(driver_row, text='选择驱动', width=10, command=choose).pack(side='right', padx=(10, 0))
    def invoke(action):
        try: return action()
        except (ValueError, OSError): raise
        except Exception: raise ValueError('PKCS#11 操作失败；请检查设备、驱动、PIN 和支持的机制。不会自动重试 PIN。') from None
    def connect():
        if not messagebox.askyesno('加载本地驱动', '确认该模块来自可信厂商，且摘要已核对？模块将在本进程执行。', parent=win, default='no'): return
        def action():
            from .token import PKCS11Token
            token = PKCS11Token(driver.get(), digest.get())
            slots = token.slots()
            state.update(token=token, slots=slots, keys=[])
            slot.configure(values=[s['label'] + ' / ' + s['serial'] for s in slots], state='readonly' if slots else 'disabled')
            selected.set('读取后选择公钥'); selected.configure(values=[], state='disabled')
            if slots: slot.current(0)
            else:
                slot.set('未发现设备'); raise ValueError('驱动已加载，未发现插入的令牌')
        clear_connection()
        ok, _ = app.attempt(lambda: invoke(action), win)
        status.configure(text='已连接，可选择设备并读取公钥' if ok else '连接未完成，请检查驱动与设备')
        update_actions()
    ttk.Button(digest_row, text='核对并连接', width=10, style='Accent.TButton', command=connect).pack(side='right', padx=(10, 0))
    def current_slot():
        if state['token'] is None or not 0 <= slot.current() < len(state['slots']): raise ValueError('请先连接并选择设备')
        return state['slots'][slot.current()]['slot']
    def refresh():
        def action():
            state['keys'] = state['token'].public_keys(current_slot(), pin.get())
            selected.configure(values=[k['label'] + ' / ' + k['id'] for k in state['keys']], state='readonly' if state['keys'] else 'disabled')
            if state['keys']: selected.current(0)
            else: selected.set('设备中没有公钥')
        try: app.attempt(lambda: invoke(action), win)
        finally: pin.delete(0, 'end'); pin.hide_secret(); update_actions()
    read_button = ttk.Button(public_row, text='读取', width=5, command=refresh)
    read_button.pack(side='right', padx=(8, 0))
    def key():
        if not 0 <= selected.current() < len(state['keys']): raise ValueError('请选择设备公钥')
        return state['keys'][selected.current()]
    def save():
        def action():
            item = key()
            return app.vault.add(item['public'], item['label'] or '硬件令牌公钥', '硬件令牌', 'PKCS#11 对象 ID: ' + item['id'] + '\n驱动 SHA-256: ' + state['token'].digest + '\n私钥留在设备内；此记录只保存公钥。')
        ok, result = app.attempt(lambda: invoke(action), win)
        if ok: app.refresh(result[0])
    def generate():
        if not messagebox.askyesno('在设备上生成密钥', '将在设备中永久创建 RSA-3072 密钥对，私钥设为敏感且不可导出。继续？', parent=win, default='no'): return
        try:
            ok, ident = app.attempt(lambda: invoke(lambda: state['token'].generate_rsa(current_slot(), pin.get(), label.get())), win)
            if ok: messagebox.showinfo('设备密钥已生成', '对象 ID：' + ident + '\n请重新读取公钥列表。', parent=win)
        finally: pin.delete(0, 'end'); pin.hide_secret()
    generate_button = ttk.Button(generation, text='生成设备密钥', command=generate); generate_button.pack(anchor='w')
    def challenge():
        def action():
            item = key(); data = os.urandom(32)
            signature = state['token'].sign_rsa_sha256(current_slot(), pin.get(), item['id'], data)
            item['public'].verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        try:
            ok, _ = app.attempt(lambda: invoke(action), win)
            if ok: messagebox.showinfo('验证通过', '设备已签名随机挑战，本地公钥验证通过。', parent=win)
        finally: pin.delete(0, 'end'); pin.hide_secret()
    challenge_button = ttk.Button(key_actions, text='验证签名', command=challenge); challenge_button.pack(side='left')
    save_button = ttk.Button(key_actions, text='存入密钥库', command=save); save_button.pack(side='left', padx=(8, 0))
    def slot_changed(event=None):
        state['keys'] = []; selected.set('读取后选择公钥'); selected.configure(values=[], state='disabled'); pin.delete(0, 'end'); pin.hide_secret(); update_actions()
    slot.bind('<<ComboboxSelected>>', slot_changed); selected.bind('<<ComboboxSelected>>', update_actions)
    def clear_connection(*args):
        state.update(token=None, slots=[], keys=[])
        slot.configure(values=[], state='disabled'); slot.set('请先连接设备')
        selected.configure(values=[], state='disabled'); selected.set('读取后选择公钥')
        pin.delete(0, 'end'); pin.hide_secret()
        status.configure(text='尚未连接设备'); update_actions()
    for field in (driver, digest):
        variable = tk.StringVar(win, value=field.get()); field.configure(textvariable=variable)
        field.module_variable = variable; variable.trace_add('write', clear_connection)
    update_actions()
    ttk.Button(win.actions, text='关闭', command=win.destroy).pack(side='right')
