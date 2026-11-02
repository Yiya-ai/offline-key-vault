"""Exercise native image decoders, including transparent high-DPI artwork."""
import os
import subprocess
import tkinter as tk
from pathlib import Path

import pytest

from keyvault.branding import png, write_ico, install_window_icon


def test_tk_icon_images_and_window_default():
    root = tk.Tk()
    root.withdraw()
    try:
        for size in (16, 32, 48, 128, 256, 512, 1024):
            image = tk.PhotoImage(master=root, data=png(size))
            assert (image.width(), image.height()) == (size, size)
            assert image.transparency_get(0, 0)
            assert image.get(size // 2, size // 5) == (220, 53, 69)
        install_window_icon(root)
        assert len(root._application_icons) == 4
        child = tk.Toplevel(root)
        child.update_idletasks()
        child.destroy()
    finally:
        root.destroy()


@pytest.mark.skipif(os.name != 'nt', reason='Native Windows resource decoder')
def test_compiled_executable_has_extractable_icon(tmp_path):
    from build_portable import verify_executable_icon
    icon = tmp_path / 'app.ico'
    write_ico(icon)
    source = tmp_path / 'App.cs'
    source.write_text('class App { static void Main() {} }', encoding='utf-8')
    exe = tmp_path / 'App.exe'
    compiler = Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    subprocess.run([str(compiler), '/nologo', '/target:winexe', '/win32icon:' + str(icon),
                    '/out:' + str(exe), str(source)], check=True, capture_output=True)
    verify_executable_icon(exe)
    without = tmp_path / 'NoIcon.exe'
    subprocess.run([str(compiler), '/nologo', '/target:winexe', '/out:' + str(without), str(source)],
                   check=True, capture_output=True)
    with pytest.raises(RuntimeError, match='missing'):
        verify_executable_icon(without)
