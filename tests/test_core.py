import base64, json, os, subprocess, sys
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as S
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa, padding
from cryptography.hazmat.primitives.serialization import pkcs12
from keyvault import keys
from keyvault.vault import Vault, VaultError
from keyvault.safeio import local_path, write_new, FileLock
P = 'test only master password 492!'
Q = 'changed testing password 981!'
E = 'temporary export password 765!'

@pytest.fixture
def vault(tmp_path):
    v = Vault()
    v.create(tmp_path / 'test.okv', P)
    yield v
    v.close()

@pytest.mark.parametrize('name', [n for n in keys.ALGORITHMS if n not in ('SM2', 'OpenPGP-RSA3072')])
def test_algorithms(name):
    key = keys.generate(name)
    assert keys.algorithm(key) == name
    pub, msg = key.public_key(), b'offline verification'
    if isinstance(key, rsa.RSAPrivateKey):
        p = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
        pub.verify(key.sign(msg, p, hashes.SHA256()), msg, p, hashes.SHA256())
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        pub.verify(key.sign(msg, ec.ECDSA(hashes.SHA256())), msg, ec.ECDSA(hashes.SHA256()))
    elif isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        pub.verify(key.sign(msg), msg)
    else:
        peer = keys.generate(name)
        assert key.exchange(peer.public_key()) == peer.exchange(pub)
    for fmt in ('PEM', 'DER', 'JWK'):
        assert keys.fingerprint(keys.import_key(keys.export_public(key, fmt))) == keys.fingerprint(key)
        data = keys.export_private(key, fmt, E, plaintext=fmt == 'JWK')
        assert keys.normalized(keys.import_key(data, '' if fmt == 'JWK' else E)) == keys.normalized(key)

@pytest.mark.parametrize('name', ['Ed25519', 'RSA-2048', 'ECDSA-P256', 'ECDSA-P384', 'ECDSA-P521'])
def test_ssh(name):
    key = keys.generate(name)
    assert keys.fingerprint(keys.import_key(keys.export_public(key, 'OpenSSH'))) == keys.fingerprint(key)
    assert keys.normalized(keys.import_key(keys.export_private(key, 'OpenSSH', E), E)) == keys.normalized(key)

@pytest.mark.parametrize('name,prefix', [('RSA-2048', 'PKCS1'), ('ECDSA-P256', 'SEC1')])
def test_traditional(name, prefix):
    key = keys.generate(name)
    for fmt in (prefix + '-PEM', prefix + '-DER'):
        assert keys.normalized(keys.import_key(keys.export_private(key, fmt, plaintext=True))) == keys.normalized(key)
        with pytest.raises(ValueError): keys.export_private(key, fmt, E)

def test_raw():
    key = keys.generate('X25519')
    for fmt in ('Raw-base64', 'Raw-base64url'):
        pub = keys.import_key(keys.export_public(key, fmt), raw_kind='X25519-public')
        private = keys.import_key(keys.export_private(key, fmt, plaintext=True), raw_kind='X25519-private')
        assert keys.fingerprint(pub) == keys.fingerprint(private) == keys.fingerprint(key)
        with pytest.raises(ValueError): keys.export_private(key, fmt, E)
    with pytest.raises(ValueError): keys.import_key(b'A' * 42, raw_kind='X25519-private')

def test_certificate_p12():
    key = keys.generate('RSA-2048')
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'offline-test')])
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(datetime.now(timezone.utc)).not_valid_after(datetime.now(timezone.utc) + timedelta(days=1)).sign(key, hashes.SHA256())
    for encoding in (S.Encoding.PEM, S.Encoding.DER):
        assert keys.fingerprint(keys.import_key(cert.public_bytes(encoding))) == keys.fingerprint(key)
    blob = pkcs12.serialize_key_and_certificates(b'test', key, cert, None, S.BestAvailableEncryption(E.encode()))
    assert keys.normalized(keys.import_key(blob, E)) == keys.normalized(key)
    exported = keys.export_private(key, 'PKCS12', E)
    from asn1crypto import pkcs12 as ap
    assert ap.Pfx.load(exported)['mac_data']['iterations'].native == 600000
    assert keys.fingerprint(keys.import_key(exported, E)) == keys.fingerprint(key)

def test_bad_imports():
    key = keys.generate('Ed25519')
    pub, private = keys.normalized(key)
    for data in ('', 'hello', pub + private, pub + 'extra', keys.export_public(key, 'DER') + b'extra', b'x' * (keys.MAX_KEY_BYTES + 1)):
        with pytest.raises(ValueError): keys.import_key(data)
    with pytest.raises(ValueError): keys.import_key(keys.export_private(key, 'PEM', E), 'wrong')
    with pytest.raises(ValueError): keys.normalized(rsa.generate_private_key(public_exponent=65537, key_size=1024))
    jwk = json.loads(keys.export_private(key, 'JWK', plaintext=True))
    jwk['x'] = json.loads(keys.export_public(keys.generate('Ed25519'), 'JWK'))['x']
    with pytest.raises(ValueError): keys.import_key(json.dumps(jwk))
    with pytest.raises(ValueError): keys.import_key('{"kty":"RSA","kty":"EC"}')

def test_storage(vault):
    rid, _ = vault.add(keys.generate('Ed25519'), 'secret-name-492', 'prod, 签名', 'private note 765')
    raw = vault.path.read_bytes()
    assert all(x not in raw for x in (b'secret-name-492', b'private note 765', b'PRIVATE KEY', P.encode()))
    assert len(vault.records('签名')) == 1
    assert 'private' not in vault.records()[0]
    vault.edit(rid, 'renamed', 'new-tag', 'new note')
    path = vault.path
    vault.close()
    with pytest.raises(VaultError): vault.open(path, 'wrong')
    vault.open(path, P)
    assert vault.records()[0]['name'] == 'renamed'
    vault.delete(rid, P)
    assert vault.records() == []

def test_upgrade(vault):
    key = keys.generate('Ed25519')
    rid, _ = vault.add(key.public_key(), 'original')
    assert vault.add(key, 'ignored') == (rid, True)
    assert vault.records()[0]['has_private']
    assert vault.records()[0]['name'] == 'original'
    with pytest.raises(VaultError): vault.add(key, 'duplicate')

def test_tamper(vault):
    path = vault.path
    raw = path.read_bytes()
    vault.close()
    for field in ('data', 'nonce', 'salt', 'kdf'):
        obj = json.loads(raw)
        if field == 'kdf': obj[field] = 'scrypt-999999999-8-1'
        else:
            val = bytearray(base64.b64decode(obj[field])); val[0] ^= 1
            obj[field] = base64.b64encode(val).decode()
        path.write_text(json.dumps(obj))
        with pytest.raises(VaultError): vault.open(path, P)
        assert not vault.unlocked
    path.write_bytes(raw)
    vault.open(path, P)

def test_backup_password_export(vault, tmp_path):
    rid, _ = vault.add(keys.generate('Ed25519'), 'test')
    backup = tmp_path / 'backup.okv'
    vault.backup(backup)
    with pytest.raises(VaultError): vault.export(rid, tmp_path / 'wrong.pem', 'PEM', True, 'wrong', E)
    assert not (tmp_path / 'wrong.pem').exists()
    out = tmp_path / 'export.pem'
    vault.export(rid, out, 'PEM', True, P, E)
    assert out.read_bytes().startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----')
    assert keys.fingerprint(keys.import_key(out.read_bytes(), E)) == vault.records()[0]['fingerprint']
    with pytest.raises(FileExistsError): vault.export(rid, out, 'PEM')
    vault.change_password(P, Q)
    path = vault.path
    vault.close()
    with pytest.raises(VaultError): vault.open(path, P)
    vault.open(path, Q)
    other = Vault()
    try:
        other.open(backup, P)
        assert len(other.records()) == 1
    finally: other.close()

def test_save_failure_conflict(vault):
    old = vault.path.read_bytes()
    with patch('keyvault.safeio.os.replace', side_effect=OSError('simulated disk failure')):
        with pytest.raises(OSError): vault.add(keys.generate('Ed25519'), 'failed')
    assert vault.path.read_bytes() == old
    assert vault.records() == []
    assert not list(vault.path.parent.glob('*.tmp'))
    vault.path.write_bytes(old + b' ')
    with pytest.raises(VaultError, match='外部修改'): vault.add(keys.generate('Ed25519'), 'conflict')
    assert vault.path.read_bytes() == old + b' '

def test_lock(vault):
    with pytest.raises(ValueError): FileLock(vault.path)
    code = 'import sys\nfrom keyvault.safeio import FileLock, StorageError\ntry: FileLock(sys.argv[1])\nexcept StorageError: sys.exit(7)'
    p = subprocess.run([sys.executable, '-c', code, str(vault.path)], capture_output=True)
    assert p.returncode == 7, p.stderr

def test_wipe(vault):
    buf = vault._key
    vault.close()
    assert not any(buf)
    with pytest.raises(VaultError): vault.records()

def test_paths_permissions(tmp_path):
    with pytest.raises(ValueError): local_path(r'\\example\share\key.pem')
    if os.name == 'nt':
        with pytest.raises(ValueError): local_path(str(tmp_path / 'file') + ':stream')
    path = tmp_path / 'private.pem'
    write_new(path, b'test')
    with pytest.raises(FileExistsError): write_new(path, b'overwrite')
    assert path.read_bytes() == b'test'
    if os.name != 'nt': assert path.stat().st_mode & 0o777 == 0o600
    else:
        import ctypes
        from ctypes import wintypes as w
        adv = ctypes.WinDLL('advapi32', use_last_error=True)
        kernel = ctypes.WinDLL('kernel32')
        adv.GetNamedSecurityInfoW.argtypes = [w.LPWSTR, ctypes.c_int, w.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [ctypes.c_void_p, w.DWORD, w.DWORD, ctypes.POINTER(w.LPWSTR), ctypes.c_void_p]
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        sd, text = ctypes.c_void_p(), w.LPWSTR()
        assert adv.GetNamedSecurityInfoW(str(path), 1, 4, None, None, None, None, ctypes.byref(sd)) == 0
        try:
            assert adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, 4, ctypes.byref(text), None)
            assert text.value.startswith('D:P') and text.value.count('(A;') == 1, text.value
        finally:
            if text: kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
            kernel.LocalFree(sd)


def test_offline():
    code = '''
from keyvault.offline import install
install()
import socket, subprocess, sys, os
blocked = 0
for fn in [lambda: socket.socket(), lambda: socket.getaddrinfo('localhost', 80), lambda: subprocess.run([sys.executable, '-V']), lambda: os.system('echo forbidden')]:
    try: fn()
    except PermissionError: blocked += 1
assert blocked == 4, blocked
from keyvault import keys
assert keys.algorithm(keys.generate('Ed25519')) == 'Ed25519'
'''
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr

def test_password_policy(tmp_path):
    with pytest.raises(ValueError): Vault().create(tmp_path / 'bad.okv', 'short')
    assert not (tmp_path / 'bad.okv').exists()

def test_import_kdf_limits():
    from asn1crypto import keys as ak, pkcs12 as ap
    key = keys.generate('Ed25519')
    blob = keys.export_private(key, 'DER', E)
    info = ak.EncryptedPrivateKeyInfo.load(blob)
    params = info['encryption_algorithm']['parameters']['key_derivation_func']['parameters']
    assert params['iteration_count'].native == 600000
    assert len(params['salt'].native) == 16
    params['iteration_count'] = 2_000_001
    with patch('keyvault.pbes2.PBKDF2HMAC') as derive:
        with pytest.raises(ValueError): keys.import_key(info.dump(), E)
        derive.assert_not_called()
    blob = pkcs12.serialize_key_and_certificates(b'test', key, None, None, S.BestAvailableEncryption(E.encode()))
    pfx = ap.Pfx.load(blob)
    pfx['mac_data']['iterations'] = 2_000_001
    with patch('keyvault.pbes2.PBKDF2HMAC') as derive:
        with pytest.raises(ValueError): keys.import_key(pfx.dump(), E)
        derive.assert_not_called()
    data = keys.export_private(key, 'OpenSSH', E)
    raw = bytearray(base64.b64decode(b''.join(data.splitlines()[1:-1])))
    import struct
    offset = 15
    for _ in range(2): offset += 4 + struct.unpack_from('>I', raw, offset)[0]
    option_size = struct.unpack_from('>I', raw, offset)[0]
    struct.pack_into('>I', raw, offset + option_size, 201)
    bad = b'-----BEGIN OPENSSH PRIVATE KEY-----\n' + base64.b64encode(raw) + b'\n-----END OPENSSH PRIVATE KEY-----'
    with patch('keyvault.keys.S.load_ssh_private_key') as native_load:
        with pytest.raises(ValueError): keys.import_key(bad, E)
        native_load.assert_not_called()

@pytest.mark.parametrize('name', ['Ed25519', 'Ed448', 'ECDSA-P256'])
def test_p12_other_keys(name):
    key = keys.generate(name)
    blob = pkcs12.serialize_key_and_certificates(b'test', key, None, None, S.BestAvailableEncryption(E.encode()))
    assert keys.normalized(keys.import_key(blob, E)) == keys.normalized(key)
