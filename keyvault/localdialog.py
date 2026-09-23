"""Local file chooser: no Windows shell extensions or network locations."""
import ctypes
import os
import sys
from pathlib import Path
import stat
import tkinter as tk
from tkinter import ttk, messagebox
from .safeio import local_path, pinned_path


def _choose(parent, title='', save=False, initialfile='', defaultextension='', initialdir='', directory=False, **unused):
    win = tk.Toplevel(parent)
    win.title(title or '选择本地文件')
    win.geometry('790x540')
    win.minsize(650, 480)
    win.transient(parent)
    win.grab_set()
    pane = ttk.Frame(win, padding=20)
    pane.pack(fill='both', expand=True)
    result, entries = [''], []
    current = [None]
    ttk.Label(pane, text='仅浏览本地磁盘 · 不加载系统文件选择器或云盘插件').pack(anchor='w', pady=(0, 12))
    nav = ttk.Frame(pane)
    nav.pack(fill='x')
    drives = []
    if os.name == 'nt':
        drives = [f'{letter}:\\' for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if ctypes.windll.kernel32.GetDriveTypeW(f'{letter}:\\') in (2, 3, 6)]
    else:
        drives = ['/']
    drive = ttk.Combobox(nav, values=drives, state='readonly', width=7)
    drive.pack(side='left', padx=(0, 8))
    folder = ttk.Entry(nav)
    folder.pack(side='left', fill='x', expand=True)
    listing = ttk.Frame(pane)
    listing.pack(fill='both', expand=True, pady=12)
    box = tk.Listbox(listing, font=('PingFang SC' if sys.platform == 'darwin' else 'Microsoft YaHei UI', 10), activestyle='dotbox', exportselection=False)
    scroll = ttk.Scrollbar(listing, command=box.yview)
    box.configure(yscrollcommand=scroll.set)
    scroll.pack(side='right', fill='y')
    box.pack(fill='both', expand=True)
    ttk.Label(pane, text='目录路径（留空选择当前目录）' if directory else '文件名（也可输入完整本地路径）').pack(anchor='w', pady=(0, 5))
    filename = ttk.Entry(pane)
    filename.insert(0, initialfile)
    filename.pack(fill='x')

    def browse(value):
        try:
            path = local_path(value, directory=True)
            if not path.is_dir():
                raise ValueError('目录不存在')
            items = []
            with pinned_path(path, directory=True), os.scandir(path) as it:
                for entry in it:
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                            continue
                        if stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode):
                            items.append((entry.name, stat.S_ISDIR(info.st_mode)))
                    except OSError:
                        continue
                    if len(items) >= 10000:
                        break
            items.sort(key=lambda x: (not x[1], x[0].casefold()))
            current[0] = path
            folder.delete(0, 'end'); folder.insert(0, str(path))
            drive.set(path.anchor)
            entries[:] = items
            box.delete(0, 'end')
            for name, is_dir in items:
                box.insert('end', ('[目录]  ' if is_dir else '          ') + name)
        except (ValueError, OSError) as error:
            messagebox.showerror('无法浏览', str(error), parent=win)

    def select(event=None):
        if box.curselection():
            name, is_dir = entries[box.curselection()[0]]
            if not is_dir and not directory:
                filename.delete(0, 'end'); filename.insert(0, name)

    def activate(event=None):
        if box.curselection():
            name, is_dir = entries[box.curselection()[0]]
            if is_dir:
                browse(current[0] / name)
            elif not directory:
                select()
                submit()

    def submit():
        value = filename.get()
        if not value and not directory:
            return
        try:
            if current[0] is None:
                raise ValueError('请先选择一个本地目录')
            candidate = Path(value) if value else current[0]
            if not candidate.is_absolute():
                candidate = current[0] / candidate
            if save and not directory and not candidate.suffix and defaultextension:
                candidate = candidate.with_suffix(defaultextension)
            candidate = local_path(candidate, directory=directory)
            if directory:
                if not candidate.is_dir():
                    raise ValueError('目录不存在')
                result[0] = str(candidate)
                win.destroy()
                return
            if save and candidate.exists():
                raise ValueError('文件已存在；为避免覆盖，请使用新的文件名')
            if not save and not candidate.is_file():
                raise ValueError('文件不存在')
            local_path(candidate.parent, directory=True)
            result[0] = str(candidate)
            win.destroy()
        except (ValueError, OSError) as error:
            messagebox.showerror('无法选择文件', str(error), parent=win)

    ttk.Button(nav, text='转到', command=lambda: browse(folder.get())).pack(side='left', padx=8)
    ttk.Button(nav, text='上级', command=lambda: browse(current[0].parent) if current[0] else None).pack(side='left')
    drive.bind('<<ComboboxSelected>>', lambda e: browse(drive.get()))
    folder.bind('<Return>', lambda e: browse(folder.get()))
    box.bind('<<ListboxSelect>>', select)
    box.bind('<Double-Button-1>', activate)
    box.bind('<Return>', activate)
    footer = ttk.Frame(pane)
    footer.pack(fill='x', pady=(16, 0))
    ttk.Button(footer, text='取消', command=win.destroy).pack(side='right', padx=(8, 0))
    ttk.Button(footer, text='选择此目录' if directory else ('保存到此位置' if save else '打开'), command=submit).pack(side='right')
    browse(initialdir or Path.home())
    filename.bind('<Return>', lambda e: submit())
    try:
        parent.wait_window(win)
    except tk.TclError:
        return ''
    try:
        if parent.winfo_exists() and isinstance(parent, tk.Toplevel):
            parent.grab_set()
    except tk.TclError:
        return ''
    return result[0]


def asksaveasfilename(**kwargs):
    return _choose(save=True, **kwargs)


def askopenfilename(**kwargs):
    return _choose(save=False, **kwargs)


def askdirectory(**kwargs):
    return _choose(directory=True, **kwargs)
