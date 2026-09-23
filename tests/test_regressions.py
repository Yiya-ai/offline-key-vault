import base64
import os
import stat
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as S
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone
from keyvault import keys
from keyvault.safeio import local_path

@pytest.mark.skipif(os.name != 'nt', reason='Windows paths')
@pytest.mark.parametrize('name', ['NUL', 'CON.txt', 'COM1', 'LPT9.pem', 'trailing.', 'trailing ', 'bad?.pem'])
def test_reject_device_and_ambiguous_paths_before_io(tmp_path, name):
    with patch('keyvault.safeio.Path.lstat', side_effect=AssertionError('filesystem must not be touched')) as probe:
        with pytest.raises(ValueError): local_path(tmp_path / name)
        probe.assert_not_called()


def test_parent_reparse_rejected_before_child_stat(tmp_path):
    unsafe = tmp_path / 'junction'
    unsafe.mkdir()
    child = unsafe / 'key.pem'
    real_stat = Path.lstat
    probes = []
    def fake_stat(p, *args, **kwargs):
        probes.append(p)
        if p == unsafe:
            return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
        if p == child:
            raise AssertionError('followed an unchecked parent')
        return real_stat(p, *args, **kwargs)
    with patch.object(Path, 'lstat', fake_stat):
        with pytest.raises(ValueError): local_path(child)
    assert child not in probes


def certificate(key):
    name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'regression only')])
    return x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(42).not_valid_before(datetime.now(timezone.utc)).not_valid_after(datetime.now(timezone.utc)+timedelta(days=1)).sign(key,hashes.SHA256())


def test_certificate_only_pfx():
    key=keys.generate('RSA-2048')
    cert=certificate(key)
    data=pkcs12.serialize_key_and_certificates(b'test',None,cert,None,S.BestAvailableEncryption(b'temporary pfx password'))
    restored=keys.import_key(data,'temporary pfx password')
    assert keys.fingerprint(restored)==keys.fingerprint(key)
    assert not hasattr(restored,'private_bytes')


def test_expired_attempt_never_runs(tmp_path):
    import tkinter as tk
    from keyvault.app import Application
    root=tk.Tk(); root.withdraw(); app=Application(root)
    try:
        app.vault.create(tmp_path/'expired.okv','regression password only')
        app.show_manager()
        app.last_activity=time.monotonic()-301
        invoked=[]
        ok,_=app.attempt(lambda: invoked.append(True))
        assert not ok and not invoked
        assert not app.vault.unlocked
    finally: app.quit()


def test_lock_shortcut_is_global():
    import tkinter as tk
    from keyvault.app import Application
    root=tk.Tk(); root.withdraw(); app=Application(root)
    try: assert root.bind_all('<Control-l>')
    finally: app.quit()


def test_low_order_x25519_is_rejected():
    with pytest.raises(ValueError): keys.import_key(base64.b64encode(bytes(32)),raw_kind='X25519-public')

@pytest.mark.skipif(os.name != 'nt', reason='Windows handles')
def test_directory_cannot_be_swapped_during_io(tmp_path):
    from keyvault.safeio import pinned_path, write_new, read_limited
    folder=tmp_path/'original'; folder.mkdir()
    path=folder/'file.pem'
    write_new(path,b'no secret test data')
    with pinned_path(path):
        with pytest.raises(OSError): folder.rename(tmp_path/'replacement')
        assert read_limited(path,100)==b'no secret test data'
    folder.rename(tmp_path/'replacement')


def test_hardlink_rejected(tmp_path):
    from keyvault.safeio import read_limited, write_new
    path=tmp_path/'file.pem'
    write_new(path,b'no secret test data')
    os.link(path,tmp_path/'alias.pem')
    with pytest.raises(ValueError): read_limited(path,100)


def test_acl_failure_creates_no_file(tmp_path):
    from keyvault.safeio import write_new, StorageError
    path=tmp_path/'private.pem'
    with patch('keyvault.safeio._require_acl_volume',side_effect=StorageError('filesystem has no ACL')):
        with pytest.raises(StorageError): write_new(path,b'never write this')
    assert not path.exists()


def test_pfx_multiple_private_keys_rejected():
    from asn1crypto import pkcs12 as ap, keys as ak
    bags=[]
    for _ in range(2):
        key=keys.generate('Ed25519')
        der=key.private_bytes(S.Encoding.DER,S.PrivateFormat.PKCS8,S.NoEncryption())
        bags.append(ap.SafeBag({'bag_id':'key_bag','bag_value':ak.PrivateKeyInfo.load(der)}))
    safe=ap.AuthenticatedSafe([{'content_type':'data','content':ap.SafeContents(bags).dump()}])
    pfx=ap.Pfx({'version':3,'auth_safe':{'content_type':'data','content':safe.dump()}})
    with patch('keyvault.keys.pkcs12.load_key_and_certificates') as native:
        with pytest.raises(ValueError): keys.import_key(pfx.dump())
        native.assert_not_called()


def test_p12_export_strong_mac_and_reauthentication(tmp_path):
    from keyvault.vault import Vault
    v=Vault(); password='temporary regression password'
    try:
        v.create(tmp_path/'p12.okv',password)
        rid,_=v.add(keys.generate('Ed25519'),'temporary')
        with pytest.raises(ValueError):
            v.export(rid,tmp_path/'denied.p12','PKCS12',True,'wrong password','temporary export password')
        assert not (tmp_path/'denied.p12').exists()
        v.export(rid,tmp_path/'allowed.p12','PKCS12',True,password,'temporary export password')
        from asn1crypto import pkcs12 as ap
        pfx=ap.Pfx.load((tmp_path/'allowed.p12').read_bytes())
        assert pfx['mac_data']['iterations'].native == 600000
    finally: v.close()


def test_noncanonical_raw_base64_rejected():
    # A base64 decoder alone ignores nonzero padding bits; the tool must not.
    key=keys.generate('X25519')
    encoded=keys.export_public(key,'Raw-base64').strip()
    alphabet=b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    changed=encoded[:-2]+bytes([alphabet[alphabet.index(encoded[-2])+1]])+b'='
    with pytest.raises(ValueError): keys.import_key(changed,raw_kind='X25519-public')

@pytest.mark.skipif(os.name != 'nt', reason='Windows aliases')
def test_short_path_cannot_bypass_vault_lock(tmp_path):
    import ctypes
    from keyvault.vault import Vault
    from keyvault.safeio import FileLock
    path=tmp_path/'long-vault-file-name-for-alias-test.okv'
    v=Vault(); other=Vault()
    try:
        v.create(path,'only alias test password')
        buffer=ctypes.create_unicode_buffer(32768)
        size=ctypes.windll.kernel32.GetShortPathNameW(str(path),buffer,len(buffer))
        if not size or buffer.value.casefold()==str(path).casefold():
            pytest.skip('Volume does not generate 8.3 names')
        with pytest.raises(ValueError): FileLock(buffer.value)
        with pytest.raises(ValueError): other.open(buffer.value,'only alias test password')
    finally: other.close();v.close()


def test_expired_generate_callback_cannot_save(tmp_path):
    import tkinter as tk
    from tkinter import ttk
    from keyvault.app import Application
    from test_ui import descendants, dialog, press
    root=tk.Tk();root.withdraw();app=Application(root)
    try:
        path=tmp_path/'expire-dialog.okv'
        app.vault.create(path,'only regression password')
        before=path.read_bytes()
        app.show_manager();app.generate_dialog()
        win=dialog(root)
        next(w for w in descendants(win) if type(w)==ttk.Entry).insert(0,'must not be saved')
        app.last_activity=time.monotonic()-301
        press(win,'生成并加密保存')
        assert not app.vault.unlocked
        assert path.read_bytes()==before
    finally: app.quit()


def test_lock_during_nested_file_dialog_is_clean(tmp_path):
    import tkinter as tk
    from keyvault.app import Application
    from keyvault.localdialog import askopenfilename
    root=tk.Tk();root.withdraw();app=Application(root)
    errors=[]
    root.report_callback_exception=lambda *args: errors.append(args)
    try:
        app.vault.create(tmp_path/'nested.okv','only regression password')
        app.show_manager()
        win,_=app.dialog('sensitive test')
        root.after(50,app.lock)
        assert askopenfilename(parent=win)==''
        assert not app.vault.unlocked and not errors
    finally: app.quit()

def test_ctrl_l_from_entry_locks_and_closes_dialog(tmp_path):
    import tkinter as tk
    from tkinter import ttk
    from keyvault.app import Application
    from test_ui import descendants,dialog
    root=tk.Tk();app=Application(root)
    errors=[]
    root.report_callback_exception=lambda *args: errors.append(args)
    try:
        app.vault.create(tmp_path/'shortcut.okv','only regression password')
        app.show_manager();app.generate_dialog()
        win=dialog(root)
        root.update()
        entry=next(w for w in descendants(win) if type(w)==ttk.Entry)
        entry.focus_force();root.update()
        entry.event_generate('<Control-l>');root.update()
        assert not app.vault.unlocked
        assert not any(isinstance(w,tk.Toplevel) for w in root.winfo_children())
        assert not errors
    finally: app.quit()


@pytest.mark.skipif(os.name != 'nt', reason='Windows sharing semantics')
def test_replace_recovers_when_real_reader_releases_file(tmp_path):
    import threading
    from keyvault.safeio import write_new, atomic_replace
    path = tmp_path / 'replace.okv'
    write_new(path, b'old synthetic content')
    reader = path.open('rb')  # Windows CRT does not share delete access.
    timer = threading.Timer(0.10, reader.close)
    timer.start()
    try:
        atomic_replace(path, b'new synthetic content')
    finally:
        timer.join()
        reader.close()
    assert path.read_bytes() == b'new synthetic content'


@pytest.mark.skipif(os.name != 'nt', reason='Windows sharing semantics')
def test_replace_persistent_sharing_failure_preserves_file(tmp_path):
    from keyvault.safeio import write_new, atomic_replace
    path = tmp_path / 'replace.okv'
    write_new(path, b'old synthetic content')
    with path.open('rb') as reader, patch('keyvault.safeio.time.sleep'):
        with pytest.raises(PermissionError):
            atomic_replace(path, b'new synthetic content')
        assert reader.read() == b'old synthetic content'
    assert not list(tmp_path.glob('*.tmp'))


@pytest.mark.skipif(os.name != 'nt', reason='Windows retry policy')
def test_replace_retry_rejects_external_changes(tmp_path):
    from keyvault.safeio import write_new, atomic_replace, StorageError
    path = tmp_path / 'replace.okv'
    write_new(path, b'old synthetic content')
    def busy_then_changed(*args):
        path.write_bytes(b'externally changed synthetic content')
        error = PermissionError('synthetic sharing failure')
        error.winerror = 5
        raise error
    with patch('keyvault.safeio.os.replace', side_effect=busy_then_changed) as replace, patch('keyvault.safeio.time.sleep'):
        with pytest.raises(StorageError):
            atomic_replace(path, b'new synthetic content')
    assert replace.call_count == 1
    assert path.read_bytes() == b'externally changed synthetic content'
    assert not list(tmp_path.glob('*.tmp'))


def test_replace_rejects_stale_expected_digest(tmp_path):
    import hashlib
    from keyvault.safeio import write_new, atomic_replace, StorageError
    path = tmp_path / 'replace.okv'
    write_new(path, b'newer synthetic content')
    with pytest.raises(StorageError):
        atomic_replace(path, b'overwrite', expected_digest=hashlib.sha256(b'older content').digest())
    assert path.read_bytes() == b'newer synthetic content'
