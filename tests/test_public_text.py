import base64
from unittest.mock import patch
import pytest
from cryptography.hazmat.primitives import serialization as S
from cryptography.hazmat.primitives.asymmetric import rsa
from keyvault import keys
from keyvault.vault import Vault


@pytest.fixture(scope='module')
def legacy():
    # Synthetic fixture only. Never embed user-supplied key material in tests.
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def encoded(key):
    return base64.b64encode(key.public_bytes(S.Encoding.DER, S.PublicFormat.SubjectPublicKeyInfo)).decode()


@pytest.mark.parametrize('form', ['bare', 'wrapped', 'unpadded'])
def test_legacy_public_base64_to_pem(legacy, form):
    text = encoded(legacy.public_key())
    if form == 'wrapped':
        text = ' \n' + '\r\n'.join(text[i:i+48] for i in range(0, len(text), 48)) + '\t'
    elif form == 'unpadded':
        text = text.rstrip('=')
    output = keys.convert_public_text(text)
    public = S.load_pem_public_key(output)
    assert public.public_numbers() == legacy.public_key().public_numbers()
    assert output.startswith(b'-----BEGIN PUBLIC KEY-----')
    assert keys.algorithm(public) == 'RSA-1024'
    assert keys.compatibility_notice(public)


@pytest.mark.parametrize('fmt', ['PEM', 'DER', 'OpenSSH', 'JWK', 'PKCS1-PEM', 'PKCS1-DER'])
def test_legacy_public_vault_export_reopen(legacy, tmp_path, fmt):
    vault = Vault()
    password = 'synthetic vault password 123'
    try:
        path = tmp_path / 'legacy.okv'
        vault.create(path, password)
        rid, _ = vault.add(keys.import_key(encoded(legacy.public_key())), 'Legacy public', 'compatibility', 'synthetic')
        assert not vault.records()[0]['has_private']
        vault.close()
        vault.open(path, password)
        output = tmp_path / 'converted.pub'
        vault.export(rid, output, fmt)
        assert keys.import_key(output.read_bytes()).public_numbers() == legacy.public_key().public_numbers()
        with pytest.raises(ValueError):
            vault.export(rid, tmp_path / 'private.key', 'PEM', True, password, 'synthetic export password')
        assert not (tmp_path / 'private.key').exists()
    finally:
        vault.close()


def test_legacy_private_stays_rejected(legacy):
    from keyvault.jwk import to_jwk
    for data in (legacy.private_bytes(S.Encoding.PEM, S.PrivateFormat.PKCS8, S.NoEncryption()),
                 base64.b64encode(legacy.private_bytes(S.Encoding.DER, S.PrivateFormat.PKCS8, S.NoEncryption())),
                 to_jwk(legacy, private=True)):
        with pytest.raises(ValueError): keys.import_key(data)
    with pytest.raises(ValueError): keys.generate('RSA-1024')
    with pytest.raises(ValueError): keys.export_private(legacy, 'PEM', plaintext=True)


def test_raw_mode_recommends_auto_for_structured_key(legacy):
    with pytest.raises(ValueError, match='自动识别'):
        keys.import_key(encoded(legacy.public_key()), raw_kind='X25519-public')
    # A legitimate raw key beginning with ASCII zero must not be mistaken for DER.
    raw = base64.b64encode(bytes.fromhex('d0' * 32))
    assert raw.startswith(b'0')
    assert keys.algorithm(keys.import_key(raw, raw_kind='X25519-public')) == 'X25519'
    with pytest.raises(ValueError): keys.import_key(raw)


def test_reject_base64_trailing_objects_and_garbage(legacy):
    public = legacy.public_key().public_bytes(S.Encoding.DER, S.PublicFormat.SubjectPublicKeyInfo)
    for text in (base64.b64encode(public + b'junk'), base64.b64encode(public + public),
                 encoded(legacy.public_key()) + '===', encoded(legacy.public_key()) + '$'):
        with pytest.raises(ValueError): keys.import_key(text)


def test_base64_private_keeps_kdf_limits():
    from asn1crypto.keys import EncryptedPrivateKeyInfo
    password = 'synthetic export password'
    key = keys.generate('Ed25519')
    data = keys.export_private(key, 'DER', password)
    assert keys.normalized(keys.import_key(base64.b64encode(data), password)) == keys.normalized(key)
    info = EncryptedPrivateKeyInfo.load(data)
    info['encryption_algorithm']['parameters']['key_derivation_func']['parameters']['iteration_count'] = 2_000_001
    with patch('keyvault.keys.S.load_der_private_key') as native:
        with pytest.raises(ValueError): keys.import_key(base64.b64encode(info.dump()), password)
        native.assert_not_called()


def test_public_converter_does_not_accept_private():
    key = keys.generate('Ed25519')
    with pytest.raises(ValueError, match='只转换公钥'):
        keys.convert_public_text(keys.export_private(key, 'PEM', plaintext=True))


def test_public_converter_ui_works_while_locked(legacy, tmp_path):
    import tkinter as tk
    from keyvault.app import Application
    from test_ui import descendants, dialog, press
    root = tk.Tk()
    root.withdraw()
    app = Application(root)
    errors = []
    try:
        assert not app.vault.unlocked
        app.convert_public_dialog()
        win = dialog(root)
        next(w for w in descendants(win) if isinstance(w, tk.Text)).insert('1.0', encoded(legacy.public_key()))
        output = tmp_path / 'direct-public.pem'
        with patch('keyvault.app.filedialog.asksaveasfilename', return_value=str(output)), \
             patch('keyvault.app.messagebox.showinfo'), \
             patch('keyvault.app.messagebox.showerror', side_effect=lambda *a, **k: errors.append(a)):
            press(win, '导出公钥文件')
        assert not errors
        assert not app.vault.unlocked
        assert S.load_pem_public_key(output.read_bytes()).public_numbers() == legacy.public_key().public_numbers()
    finally:
        app.quit()


def test_manager_public_private_filter(tmp_path):
    import tkinter as tk
    from keyvault.app import Application
    root = tk.Tk()
    root.withdraw()
    app = Application(root)
    try:
        app.vault.create(tmp_path / 'filters.okv', 'synthetic filter password')
        app.vault.add(keys.generate('Ed25519'), 'Private')
        app.vault.add(keys.generate('X25519').public_key(), 'Public')
        app.show_manager()
        app.set_filter('public')
        assert len(app.rows) == 1 and not next(iter(app.rows.values()))['has_private']
        app.set_filter('private')
        assert len(app.rows) == 1 and next(iter(app.rows.values()))['has_private']
        app.set_filter('all')
        assert len(app.rows) == 2
    finally:
        app.quit()


def test_import_actions_stay_visible_on_short_dialog():
    import tkinter as tk
    from tkinter import ttk
    from keyvault.app import Application
    from test_ui import descendants, dialog
    root = tk.Tk()
    app = Application(root)
    try:
        app.import_dialog()
        win = dialog(root)
        win.geometry('760x500')
        root.update()
        button = next(w for w in descendants(win) if isinstance(w, ttk.Button) and w.cget('text') == '校验并加密入库')
        assert button.winfo_ismapped()
        assert button.winfo_rooty() + button.winfo_height() <= win.winfo_rooty() + win.winfo_height()
    finally:
        app.quit()
