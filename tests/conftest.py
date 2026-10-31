"""Prevent unattended native Mac GUI checks from hanging behind modal errors."""
import sys
import pytest


@pytest.fixture(autouse=True)
def no_unexpected_macos_messagebox(monkeypatch):
    if sys.platform != 'darwin': return
    from tkinter import messagebox
    def unexpected(*args, **kwargs):
        raise AssertionError('Unexpected modal message during synthetic macOS UI test')
    for name in ('showerror', 'showwarning', 'showinfo', 'askyesno', 'askokcancel'):
        monkeypatch.setattr(messagebox, name, unexpected)
