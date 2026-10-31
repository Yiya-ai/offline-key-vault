"""Native macOS checks use only synthetic files, keys and temporary ACLs."""
import os
from pathlib import Path
import stat
import subprocess
import sys
import tkinter as tk
import pytest

pytestmark = pytest.mark.skipif(sys.platform != 'darwin', reason='native macOS checks')


def test_local_volume_and_fail_closed(tmp_path, monkeypatch):
    from keyvault import macos_storage
    from keyvault.safeio import write_new
    assert macos_storage.api().okv_local_path(os.fsencode(tmp_path)) == 1
    class Remote:
        def okv_local_path(self, path): return 0
    monkeypatch.setattr(macos_storage, 'api', lambda: Remote())
    with pytest.raises(ValueError, match='本地卷'):
        write_new(tmp_path / 'never.key', b'synthetic')
    assert not (tmp_path / 'never.key').exists()


def test_private_output_removes_inherited_acl(tmp_path):
    from keyvault.safeio import write_new, read_limited
    folder = tmp_path / 'acl'; folder.mkdir()
    subprocess.run(['/bin/chmod', '+a', 'everyone allow read,write,file_inherit,directory_inherit', str(folder)], check=True)
    try:
        path = folder / 'synthetic.key'
        write_new(path, b'synthetic content')
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert read_limited(path, 100) == b'synthetic content'
        acl = subprocess.run(['/bin/ls', '-le', str(path)], check=True, capture_output=True, text=True).stdout
        assert 'everyone' not in acl and 'inherited' not in acl
    finally:
        subprocess.run(['/bin/chmod', '-N', str(folder)], check=True)


def test_symlink_and_hardlink_rejected(tmp_path):
    from keyvault.safeio import write_new, read_limited
    original = tmp_path / 'original'; write_new(original, b'synthetic')
    link = tmp_path / 'link'; link.symlink_to(original)
    with pytest.raises(ValueError): read_limited(link, 100)
    hard = tmp_path / 'hard'; os.link(original, hard)
    with pytest.raises(ValueError): read_limited(hard, 100)


def test_command_lock_and_password_eye(tmp_path):
    from keyvault.app import Application
    from test_ui import descendants
    from tkinter import ttk
    root = tk.Tk(); root.withdraw()
    app = Application(root, preferences_path=tmp_path / 'prefs.json')
    try:
        assert root.bind_all('<Command-l>')
        win, pane = app.dialog('synthetic', 600, 440)
        entry = app.field(pane, 'synthetic password', secret=True)
        entry.insert(0, 'synthetic password')
        assert entry.cget('show')
        app.lock()
        assert not win.winfo_exists()
    finally:
        app.quit()
