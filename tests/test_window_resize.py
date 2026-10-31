"""Exercise the real per-window Windows message handler, using synthetic UI only."""
import sys
import tkinter as tk
from tkinter import ttk
import pytest
from keyvault.window_resize import corner_rect, _hooks
from keyvault.widgets import WindowScale


@pytest.mark.parametrize('corner', [4,5,7,8])
def test_corner_projection_keeps_opposite_corner_and_minimum(corner):
    for rect in ((100,100,800,700),(100,100,180,160),(100,100,1700,450)):
        result = corner_rect(rect, corner, (760,550), (16,39))
        left, top, right, bottom = result
        assert abs((right-left-16)*550-(bottom-top-39)*760) <= 760
        assert right-left-16 >= 608 and bottom-top-39 >= 440
        assert result[2 if corner in (4,7) else 0] == rect[2 if corner in (4,7) else 0]
        assert result[3 if corner in (4,5) else 1] == rect[3 if corner in (4,5) else 1]


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows non-client messages')
def test_native_handles_allow_only_corners_and_release_callback():
    import ctypes as c
    from ctypes import wintypes as w
    root = tk.Tk(); root.geometry('760x550+200+150')
    WindowScale(root,760,550); ttk.Label(root._stage,text='Synthetic resize test').pack()
    root.update()
    native = root._scaler.resize.native
    try:
        assert native is not None
        send = native.user.SendMessageW
        send.argtypes = [w.HWND,w.UINT,w.WPARAM,w.LPARAM]; send.restype = c.c_ssize_t
        rect, client = w.RECT(), w.RECT()
        native.user.GetWindowRect(native.hwnd,c.byref(rect))
        native.user.GetClientRect(native.hwnd,c.byref(client))
        left,top,right,bottom = rect.left,rect.top,rect.right,rect.bottom
        for x,y,expected in ((left+2,top+2,13),(right-2,top+2,14),(left+2,bottom-2,16),(right-2,bottom-2,17),
                             (left+2,(top+bottom)//2,18),(right-2,(top+bottom)//2,18),
                             ((left+right)//2,top+2,18),((left+right)//2,bottom-2,18)):
            assert send(native.hwnd,0x84,0,((y&0xffff)<<16)|(x&0xffff)) == expected
        assert not native.user.GetWindowLongW(native.hwnd,-16) & 0x10000
        bw,bh = right-left-client.right,bottom-top-client.bottom
        for corner in (4,5,7,8):
            drag = w.RECT(left,top,right+220,bottom+20)
            assert send(native.hwnd,0x214,corner,c.addressof(drag)) == 1
            assert abs((drag.right-drag.left-bw)*550-(drag.bottom-drag.top-bh)*760) <= 760
        for edge in (1,2,3,6):
            drag = w.RECT(left,top,right+220,bottom+20)
            send(native.hwnd,0x214,edge,c.addressof(drag))
            assert (drag.left,drag.top,drag.right,drag.bottom) == (left,top,right,bottom)
    finally: root.destroy()
    assert native.hwnd not in _hooks


def test_portable_grips_preserve_ratio_and_anchor():
    from unittest.mock import patch
    root = tk.Tk(); root.geometry('760x550+100+100')
    try:
        with patch('keyvault.window_resize.sys.platform','darwin'):
            WindowScale(root,760,550); root.update()
        resize = root._scaler.resize
        assert len(resize.grips) == 4 and not any(root.resizable())
        from types import SimpleNamespace
        for corner in (4,5,7,8):
            root.geometry('760x550+100+100'); root.update()
            resize.start(SimpleNamespace(x_root=100,y_root=100),corner)
            resize.drag(SimpleNamespace(x_root=150,y_root=125)); root.update()
            assert abs(root.winfo_width()*550-root.winfo_height()*760) <= 760
            assert root._stage.winfo_width() == root.winfo_width()
    finally: root.destroy()
