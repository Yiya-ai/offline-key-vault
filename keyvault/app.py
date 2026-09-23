"""Chinese offline desktop UI. Sensitive data stays in this process."""
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
import time
import sys
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from . import localdialog as filedialog
from . import keys
from .safeio import read_limited, write_new
from .vault import Vault, VaultDestroyed

BG = '#ffffff'
SIDEBAR = '#f7f7f9'
INK = '#25252d'
MUTED = '#777783'
ACCENT = '#dc3545'
SOFT = '#fff0f2'
LINE = '#eaeaf0'
IDLE_SECONDS = 300
UI_FONT = 'PingFang SC' if sys.platform == 'darwin' else 'Microsoft YaHei UI'
LATIN_FONT = 'Helvetica' if sys.platform == 'darwin' else 'Segoe UI'


class Application:
    def __init__(self, root, preferences_path=None):
        self.root = root
        self.vault = Vault()
        from .preferences import Preferences
        self.preferences = Preferences(preferences_path)
        self.last_activity = time.monotonic()
        self.retry_at = 0
        self.failures = 0
        self._closing = False
        self._tick_id = None
        self.rows = {}
        self.record_filter = 'all'
        self.nav_buttons = {}
        self.root.title('密钥柜 · 完全离线密钥管理')
        self.root.geometry('1200x760')
        self.root.minsize(1040, 680)
        self.root.configure(bg=BG)
        self.root.protocol('WM_DELETE_WINDOW', self.quit)
        self.root.report_callback_exception = self.callback_error
        style = ttk.Style(root)
        style.theme_use('clam')
        style.configure('.', font=(UI_FONT, 10), foreground=INK, background=BG)
        style.configure('TFrame', background=BG)
        style.configure('TLabel', background=BG)
        style.configure('Muted.TLabel', foreground=MUTED)
        style.configure('Side.TFrame', background=SIDEBAR)
        style.configure('Side.TLabel', background=SIDEBAR, foreground=MUTED)
        style.configure('TButton', padding=(14, 8), background=BG, foreground=INK,
                        bordercolor=LINE, lightcolor=BG, darkcolor=BG, borderwidth=1, relief='flat')
        style.map('TButton', background=[('active', '#f4f4f7')],
                  foreground=[('disabled', '#aaaab3')], bordercolor=[('focus', ACCENT)])
        style.configure('Accent.TButton', background=ACCENT, foreground='white', bordercolor=ACCENT,
                        lightcolor=ACCENT, darkcolor=ACCENT)
        style.map('Accent.TButton', background=[('active', '#c52d3d')],
                  foreground=[('disabled', '#f0b7bd'), ('!disabled', 'white')],
                  bordercolor=[('focus', '#9d2030'), ('!focus', ACCENT)])
        style.configure('Nav.TButton', background=SIDEBAR, borderwidth=0, anchor='w', padding=(16, 5))
        style.map('Nav.TButton', background=[('active', '#eeeef2')])
        style.configure('Selected.Nav.TButton', foreground=ACCENT, background=SOFT, font=(UI_FONT, 10, 'bold'))
        style.map('Selected.Nav.TButton', background=[('active', '#ffe5e9'), ('!active', SOFT)])
        style.configure('Danger.TButton', foreground=ACCENT)
        style.configure('TEntry', padding=(10, 7), fieldbackground=BG, bordercolor=LINE,
                        lightcolor=BG, darkcolor=BG, insertcolor=INK)
        style.map('TEntry', bordercolor=[('focus', ACCENT)])
        style.configure('TCombobox', padding=(10, 6), fieldbackground=BG, background=BG,
                        arrowcolor=MUTED, bordercolor=LINE, lightcolor=BG, darkcolor=BG)
        style.map('TCombobox', fieldbackground=[('readonly', BG)], selectbackground=[('readonly', BG)],
                  selectforeground=[('readonly', INK)], bordercolor=[('focus', ACCENT)])
        style.layout('Vertical.TScrollbar', [('Vertical.Scrollbar.trough', {'sticky': 'ns', 'children': [('Vertical.Scrollbar.thumb', {'sticky': 'nswe', 'expand': '1'})]})])
        style.configure('Vertical.TScrollbar', background='#dedee5', troughcolor='#fafafb',
                        lightcolor='#dedee5', darkcolor='#dedee5', bordercolor=BG, borderwidth=0, arrowsize=8)
        style.map('Vertical.TScrollbar', background=[('active', '#bdbdc8')])
        style.configure('Treeview', rowheight=48, borderwidth=0, relief='flat', background=BG,
                        fieldbackground=BG, bordercolor=BG, lightcolor=BG, darkcolor=BG)
        style.configure('Treeview.Heading', padding=(12, 12), background='#fafafb',
                        foreground=MUTED, borderwidth=0, relief='flat', font=(UI_FONT, 9))
        style.map('Treeview', background=[('selected', SOFT)], foreground=[('selected', ACCENT)])
        self.root.bind_all('<KeyPress>', self.activity, add='+')
        self.root.bind_all('<ButtonPress>', self.activity, add='+')
        self.root.bind_all('<Control-l>', lambda e: (self.lock(), 'break')[1])
        self.root.bind_all('<Control-L>', lambda e: (self.lock(), 'break')[1])
        if sys.platform == 'darwin':
            self.root.bind_all('<Command-l>', lambda e: (self.lock(), 'break')[1])
            self.root.bind_all('<Command-L>', lambda e: (self.lock(), 'break')[1])
        self.screen = None
        self.show_locked()
        self._tick_id = self.root.after(1000, self.tick)

    def callback_error(self, kind, error, traceback):
        # Do not print traceback/locals: they can contain imported key material.
        if self._closing:
            return
        messagebox.showerror('操作未完成', '操作失败，未输出任何密钥或诊断日志。请检查输入及文件权限。', parent=self.root)

    def expire_if_needed(self):
        if self.vault.unlocked and time.monotonic() - self.last_activity >= IDLE_SECONDS:
            self.lock('已因空闲自动锁定')
            return True
        return False

    def activity(self, event=None):
        if self.expire_if_needed():
            return 'break'
        self.last_activity = time.monotonic()

    def tick(self):
        if self._closing:
            return
        if self._tick_id:
            self.root.after_cancel(self._tick_id)
        self.expire_if_needed()
        self._tick_id = self.root.after(1000, self.tick)

    @contextmanager
    def busy(self):
        self.root.configure(cursor='watch')
        self.root.update_idletasks()
        try:
            yield
        finally:
            self.root.configure(cursor='')
            # A slow RSA/KDF operation should not count as inactivity.
            self.last_activity = time.monotonic()

    def attempt(self, action, parent=None):
        # Widget/Return callbacks can run before Tk's global activity binding.
        if self.expire_if_needed():
            return False, None
        was_unlocked = self.vault.unlocked
        try:
            with self.busy():
                return True, action()
        except (ValueError, OSError) as error:
            messagebox.showerror('操作未完成', str(error), parent=parent or self.root)
            if isinstance(error, VaultDestroyed) or (was_unlocked and not self.vault.unlocked):
                self.root.after_idle(lambda reason=str(error): self.lock(reason) if not self._closing else None)
            return False, None
        except Exception:
            messagebox.showerror('操作未完成', '操作失败：所选算法或格式不可用。没有输出敏感诊断信息。', parent=parent or self.root)
            if was_unlocked and not self.vault.unlocked:
                self.root.after_idle(lambda: self.lock('安全操作未完成，密钥库已锁定') if not self._closing else None)
            return False, None

    def clear_screen(self):
        if self.screen is not None:
            self.screen.destroy()
        self.screen = ttk.Frame(self.root)
        self.screen.pack(fill='both', expand=True)
        self.nav_buttons = {}

    def shell(self, unlocked=False):
        self.clear_screen()
        side = ttk.Frame(self.screen, style='Side.TFrame', width=190)
        side.pack(side='left', fill='y')
        side.pack_propagate(False)
        brand = tk.Canvas(side, width=166, height=60, bg=SIDEBAR, highlightthickness=0)
        brand.pack(padx=12, pady=(6, 6))
        brand.create_oval(10, 17, 46, 53, fill=ACCENT, outline='')
        brand.create_oval(20, 25, 30, 35, outline='white', width=2)
        brand.create_line(28, 34, 37, 43, fill='white', width=2)
        brand.create_line(32, 39, 35, 36, fill='white', width=2)
        brand.create_text(60, 34, text='密钥柜', anchor='w', fill=INK, font=(UI_FONT, 19, 'bold'))
        ttk.Label(side, text='我的密钥库', style='Side.TLabel', font=(UI_FONT, 9)).pack(anchor='w', padx=26, pady=(0, 10))
        if unlocked:
            for mode, label in (('all', '全部密钥'), ('public', '仅公钥'), ('private', '含私钥')):
                button = ttk.Button(side, text=label, style='Nav.TButton', command=lambda m=mode: self.set_filter(m))
                button.pack(fill='x', padx=12, pady=2)
                self.nav_buttons[mode] = button
        else:
            ttk.Button(side, text='打开密钥库', style='Selected.Nav.TButton', command=lambda: self.unlock_dialog(False)).pack(fill='x', padx=12)
        ttk.Label(side, text='本地工具', style='Side.TLabel', font=(UI_FONT, 9)).pack(anchor='w', padx=26, pady=(14, 10))
        ttk.Button(side, text='硬件令牌', style='Nav.TButton', command=self.token_dialog).pack(fill='x', padx=12, pady=2)
        ttk.Button(side, text='公钥文本转文件', style='Nav.TButton', command=self.convert_public_dialog).pack(fill='x', padx=12, pady=2)
        ttk.Button(side, text='公私钥配对校验', style='Nav.TButton', command=self.pair_check_dialog).pack(fill='x', padx=12, pady=2)
        ttk.Button(side, text='导出设置', style='Nav.TButton', command=self.export_settings_dialog).pack(fill='x', padx=12, pady=2)
        if unlocked:
            ttk.Button(side, text='加密备份', style='Nav.TButton', command=self.backup).pack(fill='x', padx=12, pady=2)
            ttk.Button(side, text='更改主口令', style='Nav.TButton', command=self.password_dialog).pack(fill='x', padx=12, pady=2)
            ttk.Button(side, text='安全设置', style='Nav.TButton', command=self.security_dialog).pack(fill='x', padx=12, pady=2)
        else:
            ttk.Button(side, text='双因素恢复', style='Nav.TButton', command=self.recovery_dialog).pack(fill='x', padx=12, pady=2)
        bottom = ttk.Frame(side, style='Side.TFrame')
        bottom.pack(side='bottom', fill='x', padx=14, pady=12)
        ttk.Button(bottom, text='使用说明', style='Nav.TButton', command=self.help_dialog).pack(fill='x')
        ttk.Label(bottom, text='●  完全离线', style='Side.TLabel', foreground='#33816d').pack(anchor='w', padx=16, pady=(10, 4))
        ttk.Label(bottom, text='不联网 · 不上传', style='Side.TLabel', font=(UI_FONT, 9)).pack(anchor='w', padx=16)
        tk.Frame(self.screen, width=1, bg=LINE).pack(side='left', fill='y')
        content = ttk.Frame(self.screen, padding=(28, 24))
        content.pack(side='left', fill='both', expand=True)
        return content

    def show_locked(self, reason='所有密钥与备注均保存在本地加密文件中'):
        content = self.shell()
        ttk.Label(content, text='欢迎回来', font=(UI_FONT, 13), foreground=MUTED).pack(anchor='w')
        pane = ttk.Frame(content)
        pane.place(relx=.5, rely=.47, anchor='center', width=610)
        art = tk.Canvas(pane, width=148, height=148, bg=BG, highlightthickness=0)
        art.pack(anchor='w')
        art.create_oval(4, 4, 140, 140, fill=SOFT, outline='')
        art.create_oval(23, 23, 121, 121, fill='#ffe1e6', outline='')
        art.create_arc(52, 38, 92, 85, start=0, extent=180, style='arc', outline=ACCENT, width=5)
        art.create_rectangle(44, 64, 100, 105, fill=ACCENT, outline='')
        art.create_oval(68, 77, 77, 86, fill=BG, outline='')
        art.create_line(73, 82, 73, 93, fill=BG, width=3)
        ttk.Label(pane, text='你的密钥，安心收好。', font=(UI_FONT, 27, 'bold')).pack(anchor='w', pady=(26, 12))
        ttk.Label(pane, text=reason, foreground=MUTED, wraplength=590).pack(anchor='w')
        actions = ttk.Frame(pane)
        actions.pack(fill='x', pady=(30, 20))
        ttk.Button(actions, text='打开密钥库 / 备份', style='Accent.TButton', command=lambda: self.unlock_dialog(False)).pack(side='left', padx=(0, 12))
        ttk.Button(actions, text='创建加密密钥库', command=lambda: self.unlock_dialog(True)).pack(side='left')
        ttk.Label(pane, text='只想转换公钥？左侧「公钥文本转文件」无需创建密钥库。', foreground=MUTED, font=(UI_FONT, 9)).pack(anchor='w')
        ttk.Label(content, text='主口令仅由你掌握，请妥善保存。', foreground=MUTED, font=(UI_FONT, 9)).pack(side='bottom', anchor='w')

    def dialog(self, title, width=660, height=560):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=BG)
        height = min(height, max(440, self.root.winfo_screenheight() - 130))
        width = min(width, self.root.winfo_screenwidth() - 80)
        win.geometry(f'{width}x{height}')
        win.minsize(min(width, 580), min(height, 420))
        win.transient(self.root)
        win.grab_set()
        # Scrollable forms keep actions reachable on smaller displays / high DPI.
        win.actions = ttk.Frame(win, padding=(24, 10, 36, 18))
        win.actions.pack(side='bottom', fill='x')
        outer = ttk.Frame(win)
        outer.pack(fill='both', expand=True)
        canvas = tk.Canvas(outer, bg=BG, highlightthickness=0)
        scroll = ttk.Scrollbar(outer, orient='vertical', command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        canvas.pack(side='left', fill='both', expand=True)
        pane = ttk.Frame(canvas, padding=24)
        item = canvas.create_window((0, 0), window=pane, anchor='nw')
        canvas.bind('<Configure>', lambda e: canvas.itemconfigure(item, width=e.width))
        pane.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        return win, pane

    def field(self, pane, label, value='', secret=False):
        ttk.Label(pane, text=label).pack(anchor='w', pady=(10, 5))
        entry = ttk.Entry(pane, show='●' if secret else '')
        entry.insert(0, value)
        entry.pack(fill='x')
        return entry

    def textfield(self, pane, label, value='', height=5):
        ttk.Label(pane, text=label).pack(anchor='w', pady=(10, 5))
        text = tk.Text(pane, height=height, wrap='word', undo=False, font=(UI_FONT, 10), relief='flat', bd=0, bg='#fafafb', fg=INK, insertbackground=ACCENT, padx=12, pady=10, highlightthickness=1, highlightbackground=LINE, highlightcolor=ACCENT)
        text.insert('1.0', value)
        text.pack(fill='both', expand=True)
        return text

    def unlock_dialog(self, create):
        if time.monotonic() < self.retry_at:
            messagebox.showinfo('请稍候', '上次口令验证失败，请稍候再试。', parent=self.root)
            return
        options = dict(parent=self.root, filetypes=[('加密密钥库', '*.okv'), ('所有文件', '*.*')])
        path = filedialog.asksaveasfilename(defaultextension='.okv', title='选择新密钥库位置（非云同步目录）', **options) if create else filedialog.askopenfilename(title='打开本地密钥库或备份', **options)
        if not path:
            return
        win, pane = self.dialog('创建密钥库' if create else '解锁密钥库', 650, 470)
        ttk.Label(pane, text=Path(path).name, font=(UI_FONT, 16, 'bold')).pack(anchor='w')
        ttk.Label(pane, text='主口令至少 12 字符。忘记后仅可使用预先配置的双因素恢复。', foreground=MUTED).pack(anchor='w', pady=8)
        from .security_ui import policy_text
        protection_notice = ttk.Label(pane, text='', foreground=ACCENT, wraplength=560)
        protection_notice.pack(anchor='w', pady=6)
        def update_notice():
            if not create:
                try:
                    protection_notice.configure(text=policy_text(self.vault.inspect_security(path)))
                except (ValueError, OSError):
                    protection_notice.configure(text='文件完整性或状态异常，请检查所选文件。')
        update_notice()
        password = self.field(pane, '主口令', secret=True)
        confirm = self.field(pane, '再次输入主口令', secret=True) if create else None
        def submit():
            if time.monotonic() < self.retry_at:
                messagebox.showinfo('请稍候', '请稍候再试。', parent=win)
                return
            value = password.get()
            if confirm and value != confirm.get():
                messagebox.showerror('口令不一致', '两次输入必须一致。', parent=win)
                return
            ok, _ = self.attempt(lambda: self.vault.create(path, value) if create else self.vault.open(path, value), win)
            password.delete(0, 'end')
            if confirm:
                confirm.delete(0, 'end')
            if ok:
                self.failures = 0
                self.retry_at = 0
                win.destroy()
                self.show_manager()
            else:
                update_notice()
                self.failures += 1
                self.retry_at = time.monotonic() + min(30, 2 ** min(self.failures, 5))
        ttk.Button(win.actions, text='创建并解锁' if create else '解锁', style='Accent.TButton', command=submit).pack(anchor='e', pady=24)
        password.focus_set()
        win.bind('<Return>', lambda e: submit())

    def show_manager(self):
        content = self.shell(unlocked=True)
        top = ttk.Frame(content)
        top.pack(fill='x')
        self.page_title = ttk.Label(top, text='全部密钥', font=(UI_FONT, 23, 'bold'))
        self.page_title.pack(side='left')
        shortcut = '⌘L' if sys.platform == 'darwin' else 'Ctrl+L'
        ttk.Button(top, text='锁定  ' + shortcut, command=self.lock).pack(side='right')
        ttk.Label(content, text=Path(self.vault.path).name + '  ·  内容自动加密保存', foreground=MUTED, font=(UI_FONT, 9)).pack(anchor='w', pady=(8, 24))
        bar = ttk.Frame(content)
        bar.pack(fill='x')
        ttk.Button(bar, text='＋ 生成密钥', style='Accent.TButton', command=self.generate_dialog).pack(side='left', padx=(0, 10))
        ttk.Button(bar, text='导入 / 文本转文件', command=self.import_dialog).pack(side='left')
        searchbar = ttk.Frame(content)
        searchbar.pack(fill='x', pady=(24, 16))
        ttk.Label(searchbar, text='搜索', foreground=MUTED).pack(side='left', padx=(0, 10))
        self.search = ttk.Entry(searchbar)
        self.search.pack(side='left', fill='x', expand=True)
        self.search.bind('<KeyRelease>', lambda e: self.refresh())
        ttk.Label(content, text='名称、标签、备注或指纹', foreground=MUTED, font=(UI_FONT, 8)).pack(anchor='w', pady=(0, 8))
        self.status = ttk.Label(content, text='', foreground=MUTED, font=(UI_FONT, 9))
        self.status.pack(side='bottom', anchor='w', pady=(18, 0))
        body = ttk.Frame(content)
        body.pack(fill='both', expand=True)
        table = ttk.Frame(body)
        table.pack(side='left', fill='both', expand=True)
        self.tree = ttk.Treeview(table, columns=('name', 'algorithm', 'tags', 'kind'), show='headings', selectmode='browse')
        for col, title, width in [('name', '名称', 158), ('algorithm', '算法', 100), ('tags', '标签', 100), ('kind', '类型', 70)]:
            self.tree.heading(col, text=title, anchor='w')
            self.tree.column(col, width=width, minwidth=60, anchor='w')
        self.tree.tag_configure('alternate', background='#fafafb')
        self.tree.tag_configure('legacy', foreground='#9b6717')
        scrollbar = ttk.Scrollbar(table, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        self.tree.pack(fill='both', expand=True)
        self.tree.bind('<<TreeviewSelect>>', lambda e: self.show_detail())
        self.empty = ttk.Frame(table, padding=18)
        ttk.Label(self.empty, text='还没有匹配的密钥', font=(UI_FONT, 14, 'bold')).pack()
        ttk.Label(self.empty, text='生成或导入一把密钥，开始整理。', foreground=MUTED).pack(pady=(10, 0))
        tk.Frame(body, width=1, bg=LINE).pack(side='left', fill='y', padx=(20, 20))
        detail = ttk.Frame(body, width=236)
        detail.pack(side='right', fill='y')
        detail.pack_propagate(False)
        ttk.Label(detail, text='密钥详情', font=(UI_FONT, 13, 'bold')).pack(anchor='w', pady=(9, 12))
        detail_area = ttk.Frame(detail)
        detail_area.pack(fill='both', expand=True, pady=(4, 12))
        self.detail = tk.Text(detail_area, height=1, width=24, wrap='word', relief='flat', bg=BG, fg=MUTED,
                              font=(UI_FONT, 9), state='disabled', padx=0, pady=4, spacing1=0, spacing3=1)
        detail_scroll = ttk.Scrollbar(detail_area, orient='vertical', command=self.detail.yview)
        self.detail.configure(yscrollcommand=detail_scroll.set)
        detail_scroll.pack(side='right', fill='y')
        self.detail.pack(side='left', fill='both', expand=True)
        self.detail_buttons = {}
        for label, command in [('编辑名称 / 标签 / 备注', self.edit_dialog), ('导出公钥文件', lambda: self.export_dialog(False)), ('导出私钥文件', lambda: self.export_dialog(True)), ('删除记录', self.delete)]:
            button = ttk.Button(detail, text=label, command=command, style='Danger.TButton' if label == '删除记录' else 'TButton')
            button.pack(fill='x', pady=4)
            self.detail_buttons[label] = button
        self.set_filter(self.record_filter)

    def set_filter(self, mode):
        self.record_filter = mode
        for key, button in self.nav_buttons.items():
            button.configure(style='Selected.Nav.TButton' if key == mode else 'Nav.TButton')
        self.page_title.configure(text={'all': '全部密钥', 'public': '仅公钥', 'private': '含私钥'}[mode])
        self.refresh()

    def refresh(self, select=None):
        if not self.vault.unlocked:
            return
        previous = select or (self.tree.selection()[0] if self.tree.selection() else None)
        records = self.vault.records(self.search.get())
        if self.record_filter == 'public':
            records = [r for r in records if not r['has_private']]
        elif self.record_filter == 'private':
            records = [r for r in records if r['has_private']]
        self.rows = {r['id']: r for r in records}
        self.tree.delete(*self.tree.get_children())
        for index, r in enumerate(records):
            row_tags = (('alternate',) if index % 2 else ()) + (('legacy',) if r['algorithm'] == 'RSA-1024' else ())
            self.tree.insert('', 'end', iid=r['id'], tags=row_tags, values=('  ' + r['name'], '  ' + r['algorithm'], '  ' + (', '.join(r['tags']) or '—'), '  ' + ('密钥对' if r['has_private'] else '仅公钥')))
        if records:
            self.empty.place_forget()
        else:
            self.empty.place(relx=.5, rely=.5, anchor='center')
        if previous in self.rows:
            self.tree.selection_set(previous)
        self.show_detail()
        self.status.configure(text=f'{len(records)} 条记录   ·   已加密保存   ·   空闲 5 分钟后锁定')

    def selected(self):
        if self.expire_if_needed() or not self.vault.unlocked:
            return None
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo('选择密钥', '请先选择一条密钥记录。', parent=self.root)
            return None
        return self.rows.get(selection[0])

    def show_detail(self):
        selection = self.tree.selection()
        r = self.rows.get(selection[0]) if selection else None
        text = '选择一条记录查看详情。\n\n还没有密钥？\n点击“生成密钥”开始，或导入已有的公钥、私钥文本。'
        if r:
            text = f"{r['name']}\n{r['algorithm']} · {'含私钥' if r['has_private'] else '仅公钥'}\n\n标签\n{', '.join(r['tags']) or '未设置'}\n\n密钥指纹\n{r['fingerprint']}\n\n创建时间（UTC）\n{r['created']}\n\n备注\n{r['notes'] or '未填写'}"
        if r and r['algorithm'] == 'RSA-1024':
            text += '\n\n兼容提醒\nRSA-1024 旧公钥，仅用于已有系统兼容。新用途请选择更高强度密钥。'
        for label, button in self.detail_buttons.items():
            allowed = r is not None and (label != '导出私钥文件' or r['has_private'])
            button.configure(state='normal' if allowed else 'disabled')
        self.detail.configure(state='normal')
        self.detail.delete('1.0', 'end')
        self.detail.insert('1.0', text)
        self.detail.configure(state='disabled')

    def meta_fields(self, pane, record=None):
        record = record or dict(name='', tags=[], notes='')
        row = ttk.Frame(pane)
        row.pack(fill='x')
        left, right = ttk.Frame(row), ttk.Frame(row)
        left.pack(side='left', fill='x', expand=True, padx=(0, 12))
        right.pack(side='left', fill='x', expand=True)
        name = self.field(left, '名称 *', record['name'])
        tags = self.field(right, '标签（逗号分隔）', ', '.join(record['tags']))
        notes = self.textfield(pane, '备注', record['notes'], 3)
        return name, tags, notes

    def convert_public_dialog(self):
        win, pane = self.dialog('公钥文本转文件', 740, 650)
        ttk.Label(pane, text='粘贴公钥，直接保存', font=(UI_FONT, 20, 'bold')).pack(anchor='w')
        ttk.Label(pane, text='自动识别 PEM、无头尾 Base64、OpenSSH 和 JWK。无需创建密钥库。',
                  foreground=MUTED, wraplength=650).pack(anchor='w', pady=(10, 16))
        text = self.textfield(pane, '公钥文本', height=7)
        row = ttk.Frame(pane)
        row.pack(fill='x', pady=(18, 10))
        ttk.Label(row, text='文件格式').pack(side='left', padx=(0, 12))
        fmt = ttk.Combobox(row, state='readonly', values=('PEM', 'DER', 'OpenSSH', 'JWK', 'PKCS1-PEM', 'PKCS1-DER'), width=18)
        fmt.set('PEM')
        fmt.pack(side='left')
        ttk.Label(pane, text='默认 PEM 会自动补上 BEGIN PUBLIC KEY / END PUBLIC KEY。', foreground=MUTED, font=(UI_FONT, 9)).pack(anchor='w')
        result = ttk.Label(pane, text='等待粘贴公钥', foreground=MUTED, wraplength=650)
        result.pack(anchor='w', pady=(20, 12))
        def inspect():
            key = keys.import_key(text.get('1.0', 'end-1c'))
            if hasattr(key, 'private_bytes'):
                raise keys.KeyError('此入口只转换公钥。私钥请通过“导入密钥”安全入库。')
            notice = keys.compatibility_notice(key)
            result.configure(text=notice or ('已识别：' + keys.algorithm(key) + ' 公钥'), foreground='#996114' if notice else '#33816d')
            return key
        def identify():
            self.attempt(inspect, win)
        def export():
            ok, key = self.attempt(inspect, win)
            if not ok:
                return
            ok, data = self.attempt(lambda: keys.export_public(key, fmt.get()), win)
            if not ok:
                return
            extension = '.pem' if 'PEM' in fmt.get() else { 'DER': '.der', 'PKCS1-DER': '.der', 'JWK': '.jwk', 'OpenSSH': '.pub'}[fmt.get()]
            ok, destination = self.attempt(lambda: self.export_defaults('public', extension), win)
            if not ok:
                return
            path = filedialog.asksaveasfilename(parent=win, title='保存公钥文件', **destination, defaultextension=extension)
            if not path:
                return
            ok, _ = self.attempt(lambda: write_new(path, data), win)
            if ok:
                text.delete('1.0', 'end')
                win.destroy()
                messagebox.showinfo('公钥已保存', '已保存为 ' + Path(path).name + '。公钥内容未改变，未上传任何数据。', parent=self.root)
        actions = ttk.Frame(win.actions)
        actions.pack(fill='x')
        ttk.Button(actions, text='识别公钥', command=identify).pack(side='left')
        ttk.Button(actions, text='导出公钥文件', style='Accent.TButton', command=export).pack(side='right')
        text.focus_set()

    def generate_dialog(self):
        win, pane = self.dialog('生成新密钥', 670, 620)
        ttk.Label(pane, text='使用系统安全随机源，在本机生成', font=(UI_FONT, 15, 'bold')).pack(anchor='w')
        ttk.Label(pane, text='Ed25519：SSH / 签名  ·  RSA：兼容性  ·  X25519：密钥交换', foreground=MUTED).pack(anchor='w', pady=12)
        algorithm = ttk.Combobox(pane, values=keys.ALGORITHMS, state='readonly')
        algorithm.set('Ed25519')
        algorithm.pack(fill='x')
        name, tags, notes = self.meta_fields(pane)
        def submit():
            from .vault import metadata
            def action():
                meta = metadata(name.get(), tags.get(), notes.get('1.0', 'end-1c'))
                return self.vault.add(keys.generate(algorithm.get(), identity=name.get()), **meta)
            ok, result = self.attempt(action, win)
            if ok:
                win.destroy()
                self.refresh(result[0])
        ttk.Button(win.actions, text='生成并加密保存', style='Accent.TButton', command=submit).pack(anchor='e', pady=(22, 0))
        name.focus_set()

    def import_dialog(self):
        win, pane = self.dialog('导入 / 密钥文本转文件', 760, 710)
        ttk.Label(pane, text='粘贴文本或选择本地文件', font=(UI_FONT, 16, 'bold')).pack(anchor='w')
        ttk.Label(pane, text='自动识别常见密钥文本，包括没有 PEM 头尾的 Base64。导入后加密保存。', foreground=MUTED).pack(anchor='w', pady=8)
        mode = ttk.Combobox(pane, state='readonly', values=('自动识别：PEM / DER / PGP / PPK / JKS / SSH / 证书 / P12', 'X25519 原始公钥', 'X25519 原始私钥'))
        mode.current(0)
        mode.pack(fill='x')
        text = self.textfield(pane, '密钥文本（只输入一把密钥；请留意旁观者）', height=5)
        file_data = [None]
        file_label = ttk.Label(pane, text='未选择文件', foreground=MUTED)
        file_label.pack(anchor='w', pady=5)
        def choose():
            path = filedialog.askopenfilename(parent=win, title='选择本地密钥文件', filetypes=[('所有文件', '*.*')])
            if path:
                ok, data = self.attempt(lambda: read_limited(path, keys.MAX_KEY_BYTES), win)
                if ok:
                    file_data[0] = data
                    text.delete('1.0', 'end')
                    file_label.configure(text='已选择：' + Path(path).name + '（如粘贴文本，将优先使用文本）')
        ttk.Button(pane, text='选择本地文件', command=choose).pack(anchor='w')
        password = self.field(pane, '输入文件口令（JKS 为存储口令；未加密留空）', secret=True)
        key_password = self.field(pane, 'JKS 条目口令（与存储口令相同时留空）', secret=True)
        name, tags, notes = self.meta_fields(pane)
        ttk.Label(pane, text='RSA-1024 仅兼容旧公钥，不接受私钥，也不能生成。', foreground=MUTED, font=(UI_FONT, 9)).pack(anchor='w', pady=(10, 0))
        def submit():
            def action():
                content = text.get('1.0', 'end-1c').strip()
                content = content if content else file_data[0]
                raw = {1: 'X25519-public', 2: 'X25519-private'}.get(mode.current())
                from .material import import_items
                items = import_items(content, password.get(), raw_kind=raw, key_password=key_password.get())
                return self.vault.add_many(items, name.get(), tags.get(), notes.get('1.0', 'end-1c'))
            ok, result = self.attempt(action, win)
            if ok:
                file_data[0] = None
                text.delete('1.0', 'end')
                password.delete(0, 'end')
                key_password.delete(0, 'end')
                win.destroy()
                self.refresh(result[0])
                if result[1]:
                    messagebox.showinfo('已更新密钥记录', '已补入私钥或证书附件，原名称与备注保留。', parent=self.root)
        ttk.Button(win.actions, text='校验并加密入库', style='Accent.TButton', command=submit).pack(anchor='e', pady=(14, 0))

    def edit_dialog(self):
        record = self.selected()
        if not record:
            return
        win, pane = self.dialog('编辑记录', 660, 520)
        name, tags, notes = self.meta_fields(pane, record)
        def submit():
            ok, _ = self.attempt(lambda: self.vault.edit(record['id'], name.get(), tags.get(), notes.get('1.0', 'end-1c')), win)
            if ok:
                win.destroy()
                self.refresh(record['id'])
        ttk.Button(win.actions, text='保存修改', style='Accent.TButton', command=submit).pack(anchor='e', pady=20)

    def export_dialog(self, private):
        record = self.selected()
        if not record:
            return
        if private and not record['has_private']:
            messagebox.showinfo('仅公钥记录', '公钥不能恢复私钥。', parent=self.root)
            return
        win, pane = self.dialog('导出私钥' if private else '导出公钥', 710, 650 if private else 420)
        ttk.Label(pane, text=record['name'], font=(UI_FONT, 16, 'bold')).pack(anchor='w')
        ttk.Label(pane, text='默认使用密钥名称；目录可在左侧“导出设置”修改。已有文件不会覆盖。', foreground=MUTED).pack(anchor='w', pady=10)
        formats = ['PEM', 'DER', 'JWK']
        alg = record['algorithm']
        if alg.startswith('RSA') or alg in ('Ed25519', 'ECDSA-P256', 'ECDSA-P384', 'ECDSA-P521'):
            formats.append('OpenSSH')
        if alg.startswith('RSA'):
            formats.extend(['PKCS1-PEM', 'PKCS1-DER'])
        if private and alg.startswith('ECDSA'):
            formats.extend(['SEC1-PEM', 'SEC1-DER'])
        if alg == 'X25519':
            formats.extend(['Raw-base64', 'Raw-base64url'])
        if private and 'OpenSSH' in formats: formats.extend(['PPK-v3', 'PPK-v2'])
        if private: formats.append('PKCS12')
        if alg == 'SM2': formats = ['PEM', 'DER']
        if alg.startswith('OpenPGP-'): formats = ['OpenPGP', 'OpenPGP-Binary']
        attachments = record.get('attachments', {})
        if attachments.get('certificates'):
            formats.append('JKS')
            if not private: formats.extend(['Certificate-PEM', 'Certificate-Chain', 'PKCS7'])
        if not private and attachments.get('ssh_certificate'): formats.append('SSH-Certificate')
        fmt = ttk.Combobox(pane, values=formats, state='readonly')
        fmt.set(formats[0])
        fmt.pack(fill='x', pady=10)
        ttk.Label(pane, text='PEM / DER：公钥为 SPKI，私钥为 PKCS#8。\nPPK v3 为默认兼容格式；v2 / JKS 的旧式保护较弱。\n证书链保留原集合，不代表信任或有效性认证。', foreground=MUTED).pack(anchor='w')
        master = self.field(pane, '再次验证当前主口令', secret=True) if private else None
        plaintext = tk.BooleanVar(value=False)
        if private:
            ttk.Checkbutton(pane, text='明确允许明文私钥导出（文件不受口令保护）', variable=plaintext).pack(anchor='w', pady=(16, 0))
        needs_password = private or 'JKS' in formats
        export_pw = self.field(pane, '导出文件口令（私钥或 JKS 至少 12 字符）', secret=True) if needs_password else None
        confirmation = self.field(pane, '再次输入导出口令', secret=True) if needs_password else None
        def submit():
            if needs_password and (not private or not plaintext.get()) and export_pw.get() != confirmation.get():
                messagebox.showerror('口令不一致', '两次导出口令必须一致。', parent=win)
                return
            if private and plaintext.get() and not messagebox.askyesno('明文私钥导出', '任何能读取该文件的人都能使用此私钥。确认导出未加密的私钥？', parent=win, default='no'):
                return
            extension = {'PEM': '.pem', 'DER': '.der', 'JWK': '.jwk', 'OpenSSH': '.key' if private else '.pub', 'PKCS12': '.p12', 'PPK-v3': '.ppk', 'PPK-v2': '.ppk', 'OpenPGP': '.asc', 'OpenPGP-Binary': '.pgp', 'JKS': '.jks', 'Certificate-Chain': '.pem', 'Certificate-PEM': '.pem', 'PKCS7': '.p7b', 'SSH-Certificate': '.pub', 'Raw-base64': '.txt', 'Raw-base64url': '.txt'}.get(fmt.get(), '.pem' if fmt.get().endswith('PEM') else '.der')
            ok, destination = self.attempt(lambda: self.export_defaults(record['name'], extension), win)
            if not ok:
                return
            path = filedialog.asksaveasfilename(parent=win, title='选择新文件名', **destination, defaultextension=extension, filetypes=[('密钥文件', '*' + extension), ('所有文件', '*.*')])
            if not path:
                return
            ok, _ = self.attempt(lambda: self.vault.export(record['id'], path, fmt.get(), private, master.get() if master else '', export_pw.get() if export_pw else '', plaintext.get()), win)
            if ok:
                for entry in (master, export_pw, confirmation):
                    if entry:
                        entry.delete(0, 'end')
                win.destroy()
                messagebox.showinfo('已导出', '文件已写入本地，并设置当前用户访问权限。', parent=self.root)
        ttk.Button(win.actions, text='验证并导出' if private else '导出文件', style='Accent.TButton', command=submit).pack(anchor='e', pady=24)

    def delete(self):
        record = self.selected()
        if not record:
            return
        if not messagebox.askyesno('删除记录', '删除“' + record['name'] + '”？\n这不会删除备份和已导出文件，也不保证擦除磁盘历史数据。', parent=self.root, default='no'):
            return
        password = simpledialog.askstring('验证主口令', '输入主口令以删除记录', show='●', parent=self.root)
        if password is not None:
            ok, _ = self.attempt(lambda: self.vault.delete(record['id'], password))
            if ok:
                self.refresh()

    def backup(self):
        path = filedialog.asksaveasfilename(parent=self.root, title='保存加密备份（请使用非同步本地目录）', initialfile='key-vault-backup-' + datetime.now().strftime('%Y%m%d-%H%M%S') + '.okv', defaultextension='.okv', filetypes=[('加密密钥库', '*.okv')])
        if path:
            ok, _ = self.attempt(lambda: self.vault.backup(path))
            if ok:
                messagebox.showinfo('备份完成', '备份可在锁定页面直接打开。备份仍使用创建备份时的主口令。', parent=self.root)

    def password_dialog(self):
        win, pane = self.dialog('更改主口令', 650, 530)
        ttk.Label(pane, text='新口令只更新当前密钥库，历史备份仍使用旧口令。', foreground=MUTED).pack(anchor='w')
        old = self.field(pane, '当前主口令', secret=True)
        new = self.field(pane, '新主口令（至少 12 字符）', secret=True)
        confirm = self.field(pane, '再次输入新口令', secret=True)
        def submit():
            if new.get() != confirm.get():
                messagebox.showerror('口令不一致', '两次输入必须一致。', parent=win)
                return
            ok, _ = self.attempt(lambda: self.vault.change_password(old.get(), new.get()), win)
            if ok:
                for entry in (old, new, confirm):
                    entry.delete(0, 'end')
                win.destroy()
                messagebox.showinfo('更新完成', '主口令已更新，请重新制作加密备份。', parent=self.root)
        ttk.Button(win.actions, text='验证并更新', style='Accent.TButton', command=submit).pack(anchor='e', pady=25)

    def export_defaults(self, name, extension):
        from .preferences import export_filename
        return {'initialfile': export_filename(name, extension), 'initialdir': self.preferences.export_directory()}

    def export_settings_dialog(self):
        from .tool_ui import show_export_settings
        show_export_settings(self)

    def pair_check_dialog(self):
        from .tool_ui import show_pair_check
        show_pair_check(self)

    def security_dialog(self):
        from .security_ui import show_settings
        show_settings(self)

    def recovery_dialog(self):
        from .security_ui import show_recovery
        show_recovery(self)

    def token_dialog(self):
        from .token_ui import show
        show(self)

    def help_dialog(self):
        win, pane = self.dialog('格式支持与安全边界', 780, 610)
        text = self.textfield(pane, '离线密钥柜 / 首版支持范围', height=24)
        text.insert('1.0', '''支持算法
RSA 2048/3072/4096；RSA-1024 仅允许兼容公钥导入/导出，不生成或导入私钥。ECDSA P-256/P-384/P-521/secp256k1，Ed25519/Ed448，X25519/X448。

输入与输出
支持没有 PEM 头尾的标准 Base64 DER 公钥/私钥文本。公钥可在锁定页直接转为文件，无需先入库。\nPEM / DER（SPKI、PKCS#8、RSA PKCS#1、EC SEC1）、OpenSSH、单个非对称 JWK、X25519 原始 base64/base64url。
X.509 PEM/DER 证书可导入并保留证书链；PKCS#12/PFX 支持导入和加密导出。支持证书链 PEM/P7B、SSH 证书与 JKS 容器。格式解析和签名校验不代表信任验证，不联网查询吊销状态。
JWK 的 kid/use/alg 等元数据不作为使用策略保留。OpenSSH 注释不保留。指纹是 SPKI DER 的 SHA-256，与 ssh-keygen 指纹编码不同。
原始 X25519 base64 用于 WireGuard 常见输入；base64url 用于需要 URL-safe 编码的场景。格式兼容不代表已经验证所有第三方配置。

扩展兼容
OpenPGP v4（身份与子密钥）、PuTTY PPK v2/v3、SM2、JKS 多条目、SSH 证书、PEM/P7B 证书链、传统 PEM 加密头、PBES1/3DES、PBKDF2/scrypt PKCS#8。硬件令牌通过本地 PKCS#11 驱动接入，PIN 不落盘，设备私钥不导出。
保留有限 KDF 预算：PBKDF2 200 万轮；scrypt 256 MiB；PPK Argon2 256 MiB 且有累计计算限制。无法安全解析的格式明确拒绝，不会改扩展名伪装转换。
OpenPGP v5/v6、JCEKS/BKS、DSA 和未知算法不作降级解析。证书签名校验不等于 CA 信任验证；不在线查询吊销状态。硬件接口尚无实物验证。

安全边界
全库 AES-256-GCM 加密，scrypt 派生密钥。私钥不显示、不复制、不记录日志。空闲 5 分钟锁定；Ctrl+L 立即锁定。
没有联网、上传或遥测功能，入口阻断 Python 网络与外部进程调用。该策略不是操作系统沙箱；高隔离要求应断网运行。
避免云同步目录；其他软件仍可能同步本地文件。主口令遗失后，仅可用预先配置的恢复口令 + 独立恢复文件重置。自毁默认关闭；启用后多次凭据校验失败会永久销毁当前库，恢复凭据同时失效。不能销毁备份、阻止文件回滚或保证擦除 SSD 历史块。锁定不能保证清除 Python/Tcl/OpenSSL 全部内存副本；系统被入侵、管理员读取、键盘记录、截屏和交换文件不受本工具完全防护。''')
        text.configure(state='disabled')
        ttk.Button(win.actions, text='关闭', command=win.destroy).pack(anchor='e', pady=12)

    def lock(self, reason='密钥库已锁定'):
        for child in list(self.root.winfo_children()):
            if isinstance(child, tk.Toplevel):
                child.destroy()
        self.vault.close()
        self.record_filter = 'all'
        self.rows.clear()
        self.show_locked(reason)

    def quit(self):
        self._closing = True
        if self._tick_id:
            self.root.after_cancel(self._tick_id)
            self._tick_id = None
        self.vault.close()
        self.root.destroy()


def main():
    if sys.platform == 'win32':
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
    root = tk.Tk()
    Application(root)
    root.mainloop()
