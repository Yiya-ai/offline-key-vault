"""Adversarial gate checks; only synthetic material and isolated directories."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import types
from unittest.mock import patch

import pytest
from keyvault import keys
from keyvault.vault import Vault

PASSWORD = 'synthetic gate test password'
ROOT = Path(__file__).resolve().parents[1]


def test_documented_counter_reset_does_not_decrypt_vault(tmp_path):
    """An editable offline counter is a limitation, not an anti-rollback gate."""
    import json
    from keyvault import protection
    vault = Vault(); path = tmp_path / 'counter.okv'
    try:
        vault.create(path, PASSWORD)
        vault.configure_security(PASSWORD, 5, confirmation=protection.DESTROY_CONFIRMATION)
        vault.close()
        with pytest.raises(protection.AuthenticationError):
            vault.open(path, 'synthetic wrong password')
        doc = json.loads(path.read_bytes())
        assert doc['failures'] == 1
        doc['failures'] = 0
        path.write_bytes(protection.pack(doc))
        assert Vault.inspect_security(path)['failures'] == 0
        with pytest.raises(protection.AuthenticationError):
            vault.open(path, 'synthetic wrong password')
        assert not vault.unlocked
        assert Vault.inspect_security(path)['failures'] == 1
    finally:
        vault.close()


def test_recomputed_checksum_cannot_authenticate_changed_policy(tmp_path):
    import json
    from keyvault import protection
    vault = Vault(); path = tmp_path / 'policy.okv'
    try:
        vault.create(path, PASSWORD)
        vault.configure_security(PASSWORD, 5, confirmation=protection.DESTROY_CONFIRMATION)
        vault.close()
        doc = json.loads(path.read_bytes()); doc['max_failures'] = 0
        path.write_bytes(protection.pack(doc))
        with pytest.raises(protection.VaultError):
            vault.open(path, PASSWORD)
        assert not vault.unlocked
    finally:
        vault.close()


@pytest.mark.parametrize('operation', ['verify', 'original', 'private_export', 'public_export'])
def test_changed_v1_file_invalidates_sensitive_operations(tmp_path, operation):
    vault = Vault()
    path = tmp_path / 'synthetic.okv'
    output = tmp_path / 'output.pem'
    try:
        vault.create(path, PASSWORD)
        key = keys.generate('Ed25519')
        source = keys.export_private(key, 'PEM', plaintext=True)
        rid, _ = vault.add_many([key], 'synthetic', source=source)
        path.write_bytes(b'externally replaced synthetic vault')
        actions = {
            'verify': lambda: vault.verify(PASSWORD),
            'original': lambda: vault.export_original(rid, output, PASSWORD),
            'private_export': lambda: vault.export(rid, output, 'PEM', private=True, password=PASSWORD, plaintext=True),
            'public_export': lambda: vault.export(rid, output, 'PEM'),
        }
        with pytest.raises(ValueError, match='磁盘文件'):
            actions[operation]()
        assert not output.exists()
    finally:
        vault.close()


@pytest.mark.parametrize('interrupt', ['lock', 'reopen', 'password_change', 'idle', 'none'])
def test_original_export_cannot_reuse_authorization_after_modal(tmp_path, interrupt):
    import tkinter as tk
    from tkinter import ttk
    from keyvault.app import Application
    from keyvault.content_ui import show_original_export
    from test_ui import descendants, dialog, press
    root = tk.Tk(); root.withdraw()
    app = Application(root, preferences_path=tmp_path / 'prefs.json')
    errors = []
    root.report_callback_exception = lambda *args: errors.append(args[1])
    path = tmp_path / 'synthetic.okv'
    output = tmp_path / 'output.pem'
    try:
        app.vault.create(path, PASSWORD)
        key = keys.generate('Ed25519')
        source = keys.export_private(key, 'PEM', plaintext=True)
        rid, _ = app.vault.add_many([key], 'synthetic', source=source)
        app.show_manager(); app.tree.selection_set(rid)
        show_original_export(app); win = dialog(root)
        next(w for w in descendants(win) if type(w) == ttk.Entry).insert(0, PASSWORD)
        def choose(**kwargs):
            if interrupt == 'password_change':
                app.vault.change_password(PASSWORD, PASSWORD + ' changed')
            elif interrupt == 'idle':
                import time
                from keyvault.app import IDLE_SECONDS
                app.last_activity = time.monotonic() - IDLE_SECONDS - 1
            elif interrupt != 'none':
                app.lock()
                if interrupt == 'reopen':
                    app.vault.open(path, PASSWORD)
            return str(output)
        with patch('keyvault.content_ui.messagebox.askyesno', return_value=True), \
             patch('keyvault.content_ui.filedialog.asksaveasfilename', side_effect=choose), \
             patch('keyvault.content_ui.messagebox.showinfo'), \
             patch('keyvault.app.messagebox.showerror'):
            press(win, '验证并导出原文')
        if interrupt == 'none':
            assert output.read_bytes() == source
        else:
            assert not output.exists(), 'stale authorization wrote original private material'
        assert not errors
    finally:
        app.quit()


@pytest.mark.skipif(os.name != 'nt', reason='Windows mandatory file sharing guarantee')
def test_driver_cannot_be_modified_between_digest_and_load(tmp_path, monkeypatch):
    from keyvault.token import PKCS11Token
    module = tmp_path / 'synthetic-driver.dll'
    original = b'not a real executable; no native code is loaded'
    module.write_bytes(original)
    blocked = []
    class Library:
        def load(self, path):
            for mutate in (lambda: module.write_bytes(b'replaced'),
                           lambda: module.rename(module.with_suffix('.moved'))):
                try:
                    mutate()
                except OSError:
                    blocked.append(True)
            assert module.read_bytes() == original
    monkeypatch.setitem(sys.modules, 'PyKCS11', types.SimpleNamespace(PyKCS11Lib=Library))
    PKCS11Token(module, hashlib.sha256(original).hexdigest())
    assert len(blocked) == 2


@pytest.mark.skipif(os.name != 'nt', reason='Windows C# launcher')
@pytest.mark.parametrize('attack', ['rewrite_manifest', 'remove_entry', 'extra_module'])
def test_launcher_integrity_gate(tmp_path, attack):
    files = ['runtime/python.exe', 'runtime/pythonw.exe', 'runtime/python312._pth',
             'app/launch.py', 'app/keyvault/offline.py']
    for name in files:
        p = tmp_path / name; p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b'synthetic fixture; never executed')
    manifest = tmp_path / 'manifest.sha256'
    def make_manifest(names):
        return ''.join(hashlib.sha256((tmp_path / n).read_bytes()).hexdigest() + '  ' + n + '\n' for n in names)
    manifest.write_text(make_manifest(files), encoding='utf-8', newline='\n')
    source = (ROOT / 'packaging/Launcher.cs').read_text(encoding='utf-8')
    source = source.replace('__MANIFEST_SHA256__', hashlib.sha256(manifest.read_bytes()).hexdigest())
    # Invoke the compiled verifier directly; this fixture is not a runnable app.
    source = source.replace('internal static class Launcher', 'public static class Launcher')
    source = source.replace('    static void Verify(', '    public static void Verify(')
    # Keep compiler inputs outside the immutable payload under test.
    code = tmp_path.parent / (tmp_path.name + '.cs'); code.write_text(source, encoding='utf-8')
    compiler = Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    assembly = code.with_suffix('.dll')
    subprocess.run([str(compiler), '/nologo', '/target:library', '/r:System.Windows.Forms.dll',
                    '/out:' + str(assembly), str(code)], check=True, capture_output=True)
    harness = code.with_suffix('.ps1')
    harness.write_text("param($Assembly, $Root)\n$ErrorActionPreference='Stop'\nAdd-Type -Path $Assembly\n[Launcher]::Verify($Root)\n", encoding='utf-8')
    def verify():
        return subprocess.run(['powershell.exe', '-NoProfile', '-File', str(harness),
                               str(assembly), str(tmp_path)], capture_output=True, timeout=30).returncode
    assert verify() == 0
    if attack == 'rewrite_manifest':
        (tmp_path / files[-1]).write_bytes(b'harmless corruption')
        manifest.write_text(make_manifest(files), encoding='utf-8')
    elif attack == 'remove_entry':
        manifest.write_text(make_manifest(files[:-1]), encoding='utf-8')
    else:
        (tmp_path / 'app/unlisted.py').write_bytes(b'# extra importable module')
    assert verify() != 0, 'integrity gate accepted tampered payload'
