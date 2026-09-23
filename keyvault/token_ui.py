"""Explicit opt-in interface for a locally supplied PKCS#11 driver."""
import hashlib
import os
from tkinter import ttk, messagebox
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from . import localdialog as filedialog
from .safeio import read_limited


def show(app):
    win, pane = app.dialog('硬件令牌 / PKCS#11', 800, 740)
    ttk.Label(pane, text='通用 PKCS#11 接口', font=('Microsoft YaHei UI', 16, 'bold')).pack(anchor='w')
    ttk.Label(pane, text='需要厂商提供的本地驱动和设备。驱动是可执行代码，必须可信。\n驱动自身行为不受 Python 网络钩子约束；严格离线环境请断网使用。\nPIN 只在当前操作中使用；此入口不重置设备，也不导出设备私钥。').pack(anchor='w', pady=10)
    driver = app.field(pane, '本地 PKCS#11 模块路径')
    digest = app.field(pane, '已核对的模块 SHA-256')
    state = {'token': None, 'slots': [], 'keys': []}
    slot = ttk.Combobox(pane, state='readonly'); slot.pack(fill='x', pady=8)
    pin = app.field(pane, '用户 PIN（不会保存）', secret=True)
    selected = ttk.Combobox(pane, state='readonly'); selected.pack(fill='x', pady=8)
    def choose():
        path = filedialog.askopenfilename(parent=win, title='选择厂商 PKCS#11 驱动', filetypes=[('驱动模块', '*.dll *.dylib *.so'), ('所有文件', '*.*')])
        if path:
            ok, data = app.attempt(lambda: read_limited(path, 64 * 1024 * 1024), win)
            if ok:
                driver.delete(0, 'end'); driver.insert(0, path)
                digest.delete(0, 'end'); digest.insert(0, hashlib.sha256(data).hexdigest())
    ttk.Button(pane, text='选择本地驱动并计算摘要', command=choose).pack(anchor='w')
    def invoke(action):
        try:
            return action()
        except (ValueError, OSError): raise
        except Exception: raise ValueError('PKCS#11 操作失败；请检查设备、驱动、PIN 和支持的机制。不会自动重试 PIN。') from None
    def connect():
        if not messagebox.askyesno('加载本地驱动', '确认该模块来自可信厂商，且摘要已核对？模块将在本进程执行。', parent=win, default='no'): return
        def action():
            from .token import PKCS11Token
            token = PKCS11Token(driver.get(), digest.get())
            slots = token.slots()
            state.update(token=token, slots=slots, keys=[])
            slot.configure(values=[s['label'] + ' / ' + s['serial'] for s in slots])
            selected.set(''); selected.configure(values=[])
            if slots: slot.current(0)
            else: raise ValueError('驱动已加载，未发现插入的令牌')
        app.attempt(lambda: invoke(action), win)
    ttk.Button(pane, text='核对并连接设备', command=connect).pack(anchor='w', pady=8)
    def current_slot():
        if state['token'] is None or not 0 <= slot.current() < len(state['slots']): raise ValueError('请先连接并选择设备')
        return state['slots'][slot.current()]['slot']
    def refresh():
        def action():
            state['keys'] = state['token'].public_keys(current_slot(), pin.get())
            selected.configure(values=[k['label'] + ' / ' + k['id'] for k in state['keys']])
            if state['keys']: selected.current(0)
        try: app.attempt(lambda: invoke(action), win)
        finally: pin.delete(0, 'end')
    ttk.Button(pane, text='读取公钥列表', command=refresh).pack(anchor='w', pady=8)
    def key():
        if not 0 <= selected.current() < len(state['keys']): raise ValueError('请选择设备公钥')
        return state['keys'][selected.current()]
    def save():
        def action():
            item = key()
            return app.vault.add(item['public'], item['label'] or '硬件令牌公钥', '硬件令牌', 'PKCS#11 对象 ID: ' + item['id'] + '\n驱动 SHA-256: ' + state['token'].digest + '\n私钥留在设备内；此记录只保存公钥。')
        ok, result = app.attempt(lambda: invoke(action), win)
        if ok: app.refresh(result[0])
    ttk.Button(pane, text='将选中公钥存入已解锁密钥库', command=save).pack(anchor='w', pady=8)
    label = app.field(pane, '新设备密钥名称（RSA-3072，不可导出）')
    def generate():
        if not messagebox.askyesno('在设备上生成密钥', '将在设备中永久创建 RSA-3072 密钥对，私钥设为敏感且不可导出。继续？', parent=win, default='no'): return
        try:
            ok, ident = app.attempt(lambda: invoke(lambda: state['token'].generate_rsa(current_slot(), pin.get(), label.get())), win)
            if ok: messagebox.showinfo('设备密钥已生成', '对象 ID：' + ident + '\n请重新读取公钥列表。', parent=win)
        finally: pin.delete(0, 'end')
    ttk.Button(pane, text='在设备上生成密钥', command=generate).pack(anchor='w', pady=8)
    def challenge():
        def action():
            item = key(); data = os.urandom(32)
            signature = state['token'].sign_rsa_sha256(current_slot(), pin.get(), item['id'], data)
            item['public'].verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        try:
            ok, _ = app.attempt(lambda: invoke(action), win)
            if ok: messagebox.showinfo('验证通过', '设备已签名随机挑战，本地公钥验证通过。', parent=win)
        finally: pin.delete(0, 'end')
    ttk.Button(win.actions, text='验证 RSA 签名', command=challenge).pack(side='left')
    ttk.Button(win.actions, text='关闭', command=win.destroy).pack(side='right')
