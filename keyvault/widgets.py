"""Local widget behavior: password visibility and pointer-targeted scrolling."""
import sys
import tkinter as tk
from tkinter import ttk


def password_entry(parent, value=''):
    row = ttk.Frame(parent, style='Password.TFrame', padding=1)
    row.pack(fill='x')
    entry = ttk.Entry(row, show='●', style='Embedded.TEntry')
    entry.insert(0, value)
    entry.pack(side='left', fill='both', expand=True)
    size = round(20 * ui_scale(parent))
    icons = [tk.PhotoImage(master=parent, data=_icon_png('eye', size, '#737b8c', revealed)) for revealed in (False, True)]
    def hide(event=None):
        if not entry.winfo_exists(): return
        entry.configure(show='●')
        button.configure(image=icons[0], text='显示密码')
    def toggle():
        if entry.instate(['disabled']) or entry.instate(['readonly']): return
        visible = bool(entry.cget('show'))
        entry.configure(show='' if visible else '●')
        button.configure(image=icons[1 if visible else 0], text='隐藏密码' if visible else '显示密码')
    button = ttk.Button(row, text='显示密码', image=icons[0], command=toggle,
                        style='Eye.TButton', takefocus=True, width=0)
    button.pack(side='right', fill='y', padx=(0, 3))
    button._icons = icons
    entry.visibility_button = button
    entry.hide_secret = hide
    pending = [None]
    def focus_in(event=None): row.state(['focus'])
    def check_focus():
        pending[0] = None
        if not row.winfo_exists(): return
        focused = row.focus_get()
        if focused not in (entry, button):
            row.state(['!focus']); hide()
    def focus_out(event=None):
        if pending[0] is not None: row.after_cancel(pending[0])
        pending[0] = row.after_idle(check_focus)
    def destroyed(event):
        if event.widget == row and pending[0] is not None:
            row.after_cancel(pending[0]); pending[0] = None
    row.bind('<Destroy>', destroyed, add='+')
    for widget in (entry, button):
        widget.bind('<FocusIn>', focus_in, add='+')
        widget.bind('<FocusOut>', focus_out, add='+')
    button.bind('<Return>', lambda e: (toggle(), 'break')[1])
    return entry


# Small antialiased local UI assets. No icon fonts, image libraries or external resources.
from functools import lru_cache
import base64
import math
import struct
import zlib


@lru_cache(maxsize=96)
def _icon_png(kind, size, color, variant=False, stroke=None):
    foreground = tuple(bytes.fromhex(color.lstrip('#')))
    edge = tuple(bytes.fromhex((stroke or color).lstrip('#')))
    data = bytearray()
    def rounded(x, y, inset):
        radius = 6 - inset
        dx = max(inset + radius - x, 0, x - (24 - inset - radius))
        dy = max(inset + radius - y, 0, y - (24 - inset - radius))
        return inset <= x <= 24 - inset and inset <= y <= 24 - inset and dx*dx + dy*dy <= radius*radius
    for py in range(size):
        data.append(0)
        for px in range(size):
            sums = [0, 0, 0]; count = 0
            for sy in range(4):
                for sx in range(4):
                    x = (px + (sx+.5)/4) * 24/size
                    y = (py + (sy+.5)/4) * 24/size
                    if kind == 'round':
                        hit = rounded(x, y, .4)
                        rgb = foreground if rounded(x, y, 1.3) else edge
                    else:
                        outline = 3 <= x <= 21 and abs(abs(y-12) - 6.5*math.sin(math.pi*(x-3)/18)) < .85
                        pupil = abs(math.hypot(x-12, y-12) - 3) < .85
                        slash = 3.5 <= x <= 20.5 and abs(y-x) < 1
                        hit = ((outline or pupil) and not (variant and abs(y-x)<2.5)) or (variant and slash)
                        rgb = foreground
                    if hit:
                        count += 1
                        for i in range(3): sums[i] += rgb[i]
            data.extend([*(round(v/count) if count else 0 for v in sums), round(count*255/16)])
    def chunk(name, payload):
        return struct.pack('!I', len(payload)) + name + payload + struct.pack('!I', zlib.crc32(name+payload)&0xffffffff)
    png = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('!2I5B',size,size,8,6,0,0,0)) + chunk(b'IDAT',zlib.compress(data)) + chunk(b'IEND',b'')
    return base64.b64encode(png)


def soft_components(root, style):
    """Rounded, restrained controls with distinct hover and keyboard-focus states."""
    size = round(24 * ui_scale(root)); border = round(8 * ui_scale(root))
    root._component_images = []
    def surface(name, normal, hover, focus, disabled):
        images = [tk.PhotoImage(master=root, data=_icon_png('round', size, fill, stroke=edge))
                  for fill, edge in (normal, hover, focus, disabled)]
        root._component_images.extend(images)
        style.element_create(name, 'image', images[0], ('disabled',images[3]), ('focus',images[2]),
                             ('pressed',images[1]), ('active',images[1]), border=border, padding=0, sticky='nsew')
    palettes = {
        'TButton': (('#f4f5f7','#e4e7ec'),('#e9edf2','#d5dbe5'),('#f4f5f7','#dc3545'),('#f7f8fa','#edf0f4')),
        'Accent.TButton': (('#dc3545','#dc3545'),('#c52d3d','#c52d3d'),('#dc3545','#962230'),('#edb7be','#edb7be')),
        'Nav.TButton': (('#f7f7f9','#f7f7f9'),('#eeeef3','#eeeef3'),('#eeeef3','#dc3545'),('#f7f7f9','#f7f7f9')),
        'Selected.Nav.TButton': (('#fff0f2','#fff0f2'),('#ffe5e9','#ffe5e9'),('#fff0f2','#dc3545'),('#f7f7f9','#f7f7f9')),
        'Danger.TButton': (('#fff4f5','#f8dce1'),('#ffe6eb','#f4c5cf'),('#fff4f5','#dc3545'),('#f7f8fa','#edf0f4')),
    }
    for name, colors in palettes.items():
        style.configure(name, background='#f7f7f9' if 'Nav.' in name else '#ffffff')
        style.map(name, background=[])
        element = name + '.surface'; surface(element, *colors)
        style.layout(name, [(element, {'sticky':'nsew','children':[('Button.padding',{'sticky':'nsew','children':[('Button.label',{'sticky':'nsew'})]})]})])
    style.layout('Danger.Compact.TButton', style.layout('Danger.TButton'))
    surface('Input.surface', ('#ffffff','#dce1e9'),('#ffffff','#c4ccd9'),('#ffffff','#dc3545'),('#f6f7f9','#e6e9ef'))
    style.layout('TEntry', [('Input.surface',{'sticky':'nsew','children':[('Entry.padding',{'sticky':'nsew','children':[('Entry.textarea',{'sticky':'nsew'})]})]})])
    style.layout('Password.TFrame', [('Input.surface',{'sticky':'nsew','children':[('Frame.padding',{'sticky':'nsew'})]})])
    style.layout('Embedded.TEntry', [('Entry.padding',{'sticky':'nsew','children':[('Entry.textarea',{'sticky':'nsew'})]})])
    style.configure('Embedded.TEntry', padding=(10,7), fieldbackground='#ffffff', borderwidth=0)
    style.layout('Eye.TButton', [('Button.padding',{'sticky':'nsew','children':[('Button.label',{'sticky':'nsew'})]})])
    style.configure('Eye.TButton', padding=(6,3), background='#ffffff', borderwidth=0)
    style.map('Eye.TButton', background=[('active','#f2f4f8'),('focus','#fff0f2')])


def install_scrolling(root, activity):
    tag = 'VaultScroll' + str(id(root))
    def attach(event):
        widget = event.widget
        if hasattr(widget, 'bindtags') and tag not in widget.bindtags():
            widget.bindtags((tag, *widget.bindtags()))
    def scroll(event):
        if activity(event) == 'break': return 'break'
        delta = getattr(event, 'delta', 0)
        number = getattr(event, 'num', None)
        if number in (4, 5): steps = -3 if number == 4 else 3
        elif delta:
            steps = -int(delta) if sys.platform == 'darwin' else -max(1, abs(int(delta)) // 120) * (1 if delta > 0 else -1) * 3
        else: return 'break'
        widget = getattr(event.widget, 'scroll_target', event.widget)
        while widget is not None:
            if isinstance(widget, (tk.Text, tk.Listbox, tk.Canvas, ttk.Treeview)):
                try:
                    first, last = widget.yview()
                    if (steps < 0 and first > 0) or (steps > 0 and last < 1):
                        widget.yview_scroll(steps * 18 if isinstance(widget, tk.Canvas) else steps, 'units')
                        return 'break'
                except tk.TclError:
                    pass
            widget = getattr(widget, 'master', None)
        return 'break'
    for sequence in ('<MouseWheel>', '<Button-4>', '<Button-5>'):
        root.bind_class(tag, sequence, scroll)
    root.bind_all('<Map>', attach, add='+')
    root.scroll_event = scroll


def ui_scale(widget):
    """Convert point-based Tk fonts to layout pixels (96 DPI is 4/3)."""
    return max(1.0, float(widget.tk.call('tk', 'scaling')) / (4 / 3))


def _padding(widget):
    try:
        values = [widget.winfo_pixels(v) for v in widget.tk.splitlist(widget.cget('padding'))]
    except tk.TclError:
        return 0
    if not values: return 0
    return values[0] * 2 if len(values) < 3 else values[0] + values[2]


def install_layout(root):
    """Wrap labels against their container, including labels changed after mapping."""
    def attach(event):
        widget = event.widget
        if not isinstance(widget, (ttk.Label, ttk.Checkbutton)) or getattr(widget, '_wrap_bound', False):
            return
        widget._wrap_bound = True
        parent = widget.master
        check = isinstance(widget, ttk.Checkbutton)
        if check:
            style = 'Wrap' + str(id(widget)) + '.TCheckbutton'
            widget.configure(style=style)
        def resize(event=None):
            if not widget.winfo_exists() or parent.winfo_width() < 2: return
            width = parent.winfo_width() - _padding(parent) - 4
            if widget.winfo_manager() == 'pack':
                info = widget.pack_info()
                value = info.get('padx', 0)
                pads = value if isinstance(value, (tuple, list)) else widget.tk.splitlist(str(value))
                width -= sum(widget.winfo_pixels(v) for v in pads) * (2 if len(pads) == 1 else 1)
            width = max(40, width - (round(14 * ui_scale(widget)) + 16 if check else 0))
            if check:
                ttk.Style(widget).configure(style, wraplength=width)
            elif int(float(widget.cget('wraplength') or 0)) != width:
                widget.configure(wraplength=width)
        binding = parent.bind('<Configure>', resize, add='+')
        def destroy(event):
            if event.widget == widget and parent.winfo_exists():
                parent.unbind('<Configure>', binding)
        widget.bind('<Destroy>', destroy, add='+')
        resize()
    root.bind_all('<Map>', attach, add='+')


class ScrollableFrame(ttk.Frame):
    """Vertical viewport with visible scrollbar and keyboard focus following."""
    def __init__(self, parent, padding=0, background='#ffffff', style='TFrame', fill_height=False, **kwargs):
        super().__init__(parent, **kwargs)
        self.canvas = tk.Canvas(self, bg=background, highlightthickness=0, yscrollincrement=1)
        self.scrollbar = ttk.Scrollbar(self, orient='vertical', command=self.canvas.yview)
        self.scrollbar.scroll_target = self.canvas
        self.scrollbar.pack(side='right', fill='y')
        self.canvas.pack(side='left', fill='both', expand=True)
        connect_scrollbar(self.canvas, self.scrollbar)
        self.content = ttk.Frame(self.canvas, padding=padding, style=style)
        item = self.canvas.create_window((0, 0), window=self.content, anchor='nw')
        def resize(event=None):
            self.canvas.itemconfigure(item, width=self.canvas.winfo_width())
            if fill_height:
                self.canvas.itemconfigure(item, height=max(self.canvas.winfo_height(), self.content.winfo_reqheight()))
            self.canvas.configure(scrollregion=self.canvas.bbox('all'))
        self.canvas.bind('<Configure>', resize)
        self.content.bind('<Configure>', resize)
        # A per-toplevel binding avoids stale global callbacks after closing dialogs.
        top = self.winfo_toplevel()
        def focus(event):
            widget = event.widget
            if not str(widget).startswith(str(self.content) + '.') or not self.winfo_exists(): return
            self.after_idle(lambda: self.reveal(widget) if self.winfo_exists() and widget.winfo_exists() else None)
        binding = top.bind('<FocusIn>', focus, add='+')
        self.bind('<Destroy>', lambda e: top.unbind('<FocusIn>', binding) if e.widget == self and top.winfo_exists() else None)
    def reveal(self, widget):
        top = widget.winfo_rooty() - self.canvas.winfo_rooty()
        bottom = top + widget.winfo_height()
        height = self.canvas.winfo_height()
        if top < 0 or bottom > height:
            offset = top - 8 if top < 0 else bottom - height + 8
            total = max(1, self.content.winfo_height())
            self.canvas.yview_moveto((self.canvas.canvasy(0) + offset) / total)


def responsive_columns(parent, left, right, minimum=340):
    """Stack two form columns when their readable width no longer fits."""
    state = [None]
    for child in (left, right): child._responsive_spacing = True
    def resize(event=None):
        zoom = getattr(parent.winfo_toplevel(), '_layout_zoom', 1.0)
        stacked = parent.winfo_width() < (2 * minimum * ui_scale(parent) + 24) * zoom
        if (stacked, zoom) == state[0]: return
        state[0] = (stacked, zoom)
        gap = round(12 * zoom)
        for child in (left, right):
            child.pack_forget(); child.grid_forget()
        parent.columnconfigure(0, weight=1, uniform='form' if not stacked else '')
        parent.columnconfigure(1, weight=0 if stacked else 1, uniform='form' if not stacked else '')
        left.grid(row=0, column=0, sticky='nsew', padx=0 if stacked else (0, gap))
        right.grid(row=1 if stacked else 0, column=0 if stacked else 1,
                   sticky='nsew', padx=0 if stacked else (gap, 0), pady=(gap, 0) if stacked else 0)
    parent.bind('<Configure>', resize, add='+')


class ActionBar(ttk.Frame):
    """Keep dialog actions outside the scroll region; stack if they do not fit."""
    def __init__(self, parent, **kwargs):
        kwargs.setdefault('style', 'Action.TFrame')
        super().__init__(parent, **kwargs)
        self._stacked = None
        self._original = {}
        self.bind('<Configure>', self._layout)
    def _layout(self, event=None):
        buttons = sorted((w for w in self.winfo_children() if isinstance(w, ttk.Button)),
                         key=lambda w: (0 if 'Accent' in str(w.cget('style')) else 2 if w.cget('text') in ('关闭', '取消') else 1))
        for w in buttons:
            if w not in self._original and w.winfo_manager() == 'pack':
                self._original[w] = dict(w.pack_info(), side='right', padx=(8, 0))
        if not buttons or len(self._original) != len(buttons): return
        needed = sum(w.winfo_reqwidth() + 16 for w in buttons)
        stacked = needed > self.winfo_width() - _padding(self)
        if stacked == self._stacked: return
        self._stacked = stacked
        for w in buttons: w.pack_forget()
        for w in buttons:
            if stacked: w.pack(fill='x', pady=3)
            else: w.pack(**self._original[w])


def connect_scrollbar(widget, scrollbar, axis='y'):
    """Show a scrollbar only on real overflow; retain its original packing order."""
    original = {}; showing = [True]
    def changed(first, last):
        scrollbar.set(first, last)
        if not widget.winfo_exists() or widget.winfo_width() <= 1 or widget.winfo_height() <= 1: return
        if not original and scrollbar.winfo_manager() == 'pack': original.update(scrollbar.pack_info())
        if not original: return
        needed = float(first) > .00001 or float(last) < .99999
        if needed == showing[0]: return
        showing[0] = needed
        if needed:
            # Pack before the expanding content, otherwise it consumes the scrollbar's space.
            info = dict(original)
            others = [w for w in scrollbar.master.pack_slaves() if w != scrollbar]
            if others: info['before'] = others[0]
            scrollbar.pack(**info)
        else: scrollbar.pack_forget()
    widget.configure(**{axis + 'scrollcommand': changed})


class WindowScale:
    """Uniform per-window zoom; never changes the OS DPI or another open window."""
    def __init__(self, window, width, height, minimum_font=8):
        from weakref import WeakKeyDictionary
        self.window = window
        self.base = (width, height)
        self.minimum_font = minimum_font
        self.records = WeakKeyDictionary()
        self.styles = {}
        self.pending = None
        self.style = ttk.Style(window)
        self.prefix = 'Window' + str(id(window))
        self.factor = 1.0
        window._layout_zoom = 1.0
        window._scaler = self
        window._stage = ttk.Frame(window)
        window._stage.place(x=0, y=0, relwidth=1, relheight=1)
        from .window_resize import CornerResize
        self.resize = CornerResize(window, self.base)
        window.bind('<Configure>', lambda e: self.schedule() if e.widget == window else None, add='+')
        window.bind('<Map>', lambda e: self.schedule(), add='+')
        window.bind('<Destroy>', self.destroy, add='+')
        self.schedule()
    def destroy(self, event):
        if event.widget == self.window and self.pending is not None:
            self.window.after_cancel(self.pending); self.pending = None
    def schedule(self):
        if self.pending is None and self.window.winfo_exists(): self.pending = self.window.after_idle(self.apply)
    def _walk(self, parent):
        for child in parent.winfo_children():
            if isinstance(child, tk.Toplevel) or getattr(child, '_fixed_grip', False): continue
            yield child
            yield from self._walk(child)
    def _pixels(self, value):
        parts = value if isinstance(value, (tuple, list)) else self.window.tk.splitlist(str(value))
        return tuple(self.window.winfo_pixels(part) for part in parts)
    def _scaled(self, values):
        return tuple(round(value * self.factor) for value in values)
    def _style(self, original):
        from tkinter import font
        name = self.prefix + '.' + original
        if original not in self.styles:
            values = {}
            for option in ('padding', 'rowheight', 'arrowsize'):
                value = self.style.lookup(original, option)
                if value != '': values[option] = self._pixels(value)
            value = self.style.lookup(original, 'font')
            if value: values['font'] = font.Font(root=self.window, font=value).actual()
            self.styles[original] = values
        values = self.styles[original]; changes = {}
        for option, value in values.items():
            if option == 'font':
                changes[option] = self._font_tuple(value)
            else:
                scaled = self._scaled(value)
                changes[option] = scaled if option == 'padding' else max(1, scaled[0])
        self.style.configure(name, **changes)
        return name
    def _font_tuple(self, actual):
        size = actual['size']
        size = max(self.minimum_font, round(abs(size) * self.factor)) * (1 if size >= 0 else -1)
        return (actual['family'], size, actual['weight'], actual['slant'])
    def apply(self):
        from tkinter import font
        self.pending = None
        win = self.window
        if not win.winfo_exists() or win.winfo_width() <= 1: return
        if not self.resize.normalize(): return
        self.factor = round(max(.8, min(win.winfo_width()/self.base[0], win.winfo_height()/self.base[1])), 2)
        win._layout_zoom = self.factor
        for widget in list(self._walk(win)):
            if not widget.winfo_exists() or isinstance(widget, (ttk.Scrollbar, ttk.Separator)): continue
            record = self.records.get(widget)
            if record is None:
                options = set(widget.keys()); record = {'options': options, 'factor': None}
                if 'font' in options:
                    value = widget.cget('font')
                    if not value and isinstance(widget, ttk.Widget):
                        value = self.style.lookup(str(widget.cget('style')) or widget.winfo_class(), 'font')
                    record['font'] = font.Font(root=win, font=value).actual()
                for option in ('padding', 'padx', 'pady'):
                    if option in options: record[option] = self._pixels(widget.cget(option))
                if isinstance(widget, ttk.Frame) and not isinstance(widget, ActionBar):
                    width = widget.cget('width')
                    if int(width) > 0: record['width'] = int(width)
                if isinstance(widget, tk.Canvas) and not isinstance(widget.master, ScrollableFrame):
                    record['canvas'] = (widget.winfo_reqwidth(), widget.winfo_reqheight())
                    record['items'] = {i:font.Font(root=win, font=widget.itemcget(i,'font')).actual() for i in widget.find_all() if widget.type(i)=='text'}
                self.records[widget] = record
            # Styles can change after filtering or validation; retain their semantic base style.
            if 'style' in record['options']:
                current = str(widget.cget('style')) or widget.winfo_class()
                if not current.startswith(self.prefix + '.'):
                    record['style'] = current
                    widget.configure(style=self._style(current))
            if record['factor'] == self.factor: continue
            previous = record['factor'] or 1.0
            if 'style' in record:
                widget.configure(style=self._style(record['style']))
                if isinstance(widget, ttk.Treeview): self._style(record['style'] + '.Heading')
            if 'font' in record: widget.configure(font=self._font_tuple(record['font']))
            for option in ('padding', 'padx', 'pady'):
                if option in record: widget.configure(**{option:self._scaled(record[option])})
            if 'width' in record: widget.configure(width=round(record['width'] * self.factor))
            manager = widget.winfo_manager()
            if manager in ('pack', 'grid') and not getattr(widget, '_responsive_spacing', False):
                info = widget.pack_info() if manager=='pack' else widget.grid_info()
                key = manager + '_spacing'
                if key not in record: record[key] = {p:self._pixels(info[p]) for p in ('padx','pady') if p in info}
                changes = {p:self._scaled(v) for p,v in record[key].items()}
                if manager=='pack': widget.pack_configure(**changes)
                else: widget.grid_configure(**changes)
            if 'canvas' in record:
                widget.configure(width=round(record['canvas'][0]*self.factor),height=round(record['canvas'][1]*self.factor))
                widget.scale('all',0,0,self.factor/previous,self.factor/previous)
                for item, actual in record['items'].items(): widget.itemconfigure(item,font=self._font_tuple(actual))
            if hasattr(widget, '_icons'):
                size = max(16, round(20 * ui_scale(win) * self.factor))
                for i, icon in enumerate(widget._icons): icon.configure(data=_icon_png('eye',size,'#737b8c',bool(i)))
            record['factor'] = self.factor
