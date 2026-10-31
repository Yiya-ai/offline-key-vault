"""Corner-only, fixed-client-aspect resizing. No global hooks or external dependencies."""
import sys
import tkinter as tk


def proportional_size(base, width, height, minimum=.8):
    factor = max(minimum, min(width / base[0], height / base[1]))
    return round(base[0] * factor), round(base[1] * factor)


def corner_rect(rect, corner, base, border=(0, 0), minimum=.8):
    """Project a proposed drag onto the aspect line, keeping the opposite corner fixed."""
    left, top, right, bottom = rect
    bw, bh = border
    width, height = right - left - bw, bottom - top - bh
    factor = max(minimum, (width * base[0] + height * base[1]) / (base[0]**2 + base[1]**2))
    width, height = round(base[0] * factor) + bw, round(base[1] * factor) + bh
    if corner in (4, 7): left = right - width
    else: right = left + width
    if corner in (4, 5): top = bottom - height
    else: bottom = top + height
    return left, top, right, bottom


class CornerResize:
    def __init__(self, window, base):
        self.window, self.base = window, base
        self.native = None
        self.grips = []
        self.last = base
        window.minsize(*proportional_size(base, 0, 0))
        window.aspect(base[0], base[1], base[0], base[1])
        window.bind('<Map>', self.install, add='+')

    def normalize(self):
        win = self.window
        size = win.winfo_width(), win.winfo_height()
        if abs(size[0] * self.base[1] - size[1] * self.base[0]) > max(self.base):
            minimum = max(.8, *(a/b for a,b in zip(win.minsize(), self.base)))
            target = proportional_size(self.base, *size, minimum=minimum)
            win.geometry(f'{target[0]}x{target[1]}')
            return False
        self.last = size
        return True

    def install(self, event):
        if event.widget != self.window or self.native is not None or self.grips: return
        if sys.platform == 'win32':
            try:
                self.native = _WindowsCorners(self.window, self.base)
                return
            except (OSError, AttributeError):
                pass
        # Tk's native side handles cannot be disabled independently on Cocoa/X11.
        # Explicit corner grips provide the same constraint without a platform extension.
        self.window.resizable(False, False)
        for corner, x, y in ((4, 0, 0), (5, 1, 0), (7, 0, 1), (8, 1, 1)):
            grip = tk.Canvas(self.window, width=12, height=12, highlightthickness=0, bg='#ffffff')
            try: grip.configure(cursor='size_nw_se' if corner in (4, 8) else 'size_ne_sw')
            except tk.TclError: grip.configure(cursor='crosshair')
            grip._fixed_grip = True
            grip.place(relx=x, rely=y, anchor={4:'nw',5:'ne',7:'sw',8:'se'}[corner])
            points = [(3, 9, 3, 3, 9, 3), (3, 3, 9, 3, 9, 9),
                      (3, 3, 3, 9, 9, 9), (3, 9, 9, 9, 9, 3)][(4,5,7,8).index(corner)]
            grip.create_line(*points, fill='#9aa2b1', width=1.5)
            grip.bind('<ButtonPress-1>', lambda e, c=corner: self.start(e, c))
            grip.bind('<B1-Motion>', self.drag)
            self.grips.append(grip)

    def start(self, event, corner):
        win = self.window
        self.drag_origin = (event.x_root, event.y_root, corner,
                            (win.winfo_x(), win.winfo_y(), win.winfo_x()+win.winfo_width(), win.winfo_y()+win.winfo_height()))

    def drag(self, event):
        x, y, corner, rect = self.drag_origin
        left, top, right, bottom = rect
        dx, dy = event.x_root-x, event.y_root-y
        if corner in (4, 7): left += dx
        else: right += dx
        if corner in (4, 5): top += dy
        else: bottom += dy
        left, top, right, bottom = corner_rect((left,top,right,bottom), corner, self.base)
        self.window.geometry(f'{right-left}x{bottom-top}{left:+d}{top:+d}')


# Keep ctypes callbacks alive until the corresponding native window is destroyed.
_hooks = {}


class _WindowsCorners:
    def __init__(self, window, base):
        import ctypes as c
        from ctypes import wintypes as w
        self.base = base
        self.c, self.w = c, w
        self.user = c.WinDLL('user32', use_last_error=True)
        self.com = c.WinDLL('comctl32', use_last_error=True)
        self.proc_type = c.WINFUNCTYPE(c.c_ssize_t, w.HWND, w.UINT, w.WPARAM, w.LPARAM, c.c_size_t, c.c_size_t)
        self.callback = self.proc_type(self.handle)
        for name, args, result in (
            ('GetAncestor', [w.HWND, w.UINT], w.HWND),
            ('GetWindowRect', [w.HWND, c.POINTER(w.RECT)], w.BOOL),
            ('GetClientRect', [w.HWND, c.POINTER(w.RECT)], w.BOOL),
            ('GetWindowLongW', [w.HWND, c.c_int], w.LONG),
            ('SetWindowLongW', [w.HWND, c.c_int, w.LONG], w.LONG),
            ('SetWindowPos', [w.HWND,w.HWND,c.c_int,c.c_int,c.c_int,c.c_int,w.UINT], w.BOOL)):
            fn = getattr(self.user, name); fn.argtypes = args; fn.restype = result
        for name, args, result in (
            ('SetWindowSubclass', [w.HWND,self.proc_type,c.c_size_t,c.c_size_t], w.BOOL),
            ('RemoveWindowSubclass', [w.HWND,self.proc_type,c.c_size_t], w.BOOL),
            ('DefSubclassProc', [w.HWND,w.UINT,w.WPARAM,w.LPARAM], c.c_ssize_t)):
            fn = getattr(self.com, name); fn.argtypes = args; fn.restype = result
        self.hwnd = self.user.GetAncestor(window.winfo_id(), 2)
        if not self.hwnd or not self.com.SetWindowSubclass(self.hwnd, self.callback, 1, 0):
            raise OSError('Cannot install per-window resize constraint')
        _hooks[self.hwnd] = self
        # Maximizing / snapping would bypass the requested corner-only aspect constraint.
        style = self.user.GetWindowLongW(self.hwnd, -16)
        self.user.SetWindowLongW(self.hwnd, -16, style & ~0x10000)
        self.user.SetWindowPos(self.hwnd, None, 0, 0, 0, 0, 0x37)

    def handle(self, hwnd, msg, wp, lp, subclass_id, data):
        if msg == 0x82:  # WM_NCDESTROY: release the callback only after the final native message.
            self.com.RemoveWindowSubclass(hwnd, self.callback, subclass_id)
            result = self.com.DefSubclassProc(hwnd, msg, wp, lp)
            _hooks.pop(hwnd, None)
            return result
        if msg == 0x84:  # WM_NCHITTEST: retain corners; neutralize all four side handles.
            hit = self.com.DefSubclassProc(hwnd, msg, wp, lp)
            return 18 if hit in (10, 11, 12, 15) else hit
        if msg == 0x112 and ((wp & 0xfff0) == 0xf030 or
                            ((wp & 0xfff0) == 0xf000 and (wp & 15) not in (4,5,7,8))):
            return 0  # SC_MAXIMIZE / keyboard or side SC_SIZE
        if msg == 0x214 and lp:  # WM_SIZING
            rect = self.c.cast(lp, self.c.POINTER(self.w.RECT)).contents
            outer, client = self.w.RECT(), self.w.RECT()
            self.user.GetWindowRect(hwnd, self.c.byref(outer))
            if wp not in (4,5,7,8):
                rect.left, rect.top, rect.right, rect.bottom = outer.left, outer.top, outer.right, outer.bottom
            else:
                self.user.GetClientRect(hwnd, self.c.byref(client))
                border = outer.right-outer.left-client.right, outer.bottom-outer.top-client.bottom
                rect.left, rect.top, rect.right, rect.bottom = corner_rect(
                    (rect.left,rect.top,rect.right,rect.bottom), wp, self.base, border)
            return 1
        return self.com.DefSubclassProc(hwnd, msg, wp, lp)
