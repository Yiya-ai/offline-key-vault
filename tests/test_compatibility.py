import base64
import copy
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import pytest
from asn1crypto import keys as ak, pkcs12 as ap
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as S
from cryptography.hazmat.primitives.serialization import pkcs12
from keyvault import keys
from keyvault.material import import_items, cert_bundle, export_attachment
from keyvault.vault import Vault

PASSWORD = 'synthetic test passphrase 9482'


def certificate(key, issuer=None, signer=None, serial=1):
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'synthetic-' + str(serial))])
    now = datetime.now(timezone.utc)
    return x509.CertificateBuilder().subject_name(name).issuer_name(issuer or name).public_key(key.public_key()).serial_number(serial).not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(signer or key, hashes.SHA256())


@pytest.mark.parametrize('algorithm', ['RSA-2048', 'Ed25519', 'ECDSA-P256', 'ECDSA-P384', 'ECDSA-P521'])
@pytest.mark.parametrize('version', [2, 3])
@pytest.mark.parametrize('encrypted', [False, True])
def test_ppk_roundtrip_and_integrity(algorithm, version, encrypted):
    key = keys.generate(algorithm)
    blob = keys.export_private(key, 'PPK-v' + str(version), PASSWORD, plaintext=not encrypted)
    assert keys.normalized(keys.import_key(blob, PASSWORD if encrypted else '')) == keys.normalized(key)
    changed = blob.replace(b'Comment: ', b'Comment: altered', 1)
    with pytest.raises(ValueError): keys.import_key(changed, PASSWORD)
    if encrypted:
        with pytest.raises(ValueError): keys.import_key(blob, 'incorrect')


def test_ppk_limits_precede_kdf():
    from keyvault.ppk import load
    blob = keys.export_private(keys.generate('Ed25519'), 'PPK-v3', PASSWORD)
    for bad in (b'0', b'-1', b'999999999'):
        with patch('argon2.low_level.hash_secret_raw') as derive:
            with pytest.raises(ValueError): load(blob.replace(b'Argon2-Memory: 65536', b'Argon2-Memory: ' + bad), PASSWORD.encode())
            derive.assert_not_called()


def test_sm2_encrypted_and_public_roundtrip():
    key = keys.generate('SM2')
    assert keys.algorithm(key) == 'SM2'
    for fmt in ('PEM', 'DER'):
        assert keys.fingerprint(keys.import_key(keys.export_public(key, fmt))) == keys.fingerprint(key)
        blob = keys.export_private(key, fmt, PASSWORD)
        assert keys.normalized(keys.import_key(blob, PASSWORD)) == keys.normalized(key)
        with pytest.raises(ValueError): keys.import_key(blob, 'wrong')


def test_openpgp_retains_identity_subkey_and_encryption():
    key = keys.generate('OpenPGP-RSA3072')
    assert len(key.key.userids) == 1 and len(key.key.subkeys) == 1
    for fmt in ('OpenPGP', 'OpenPGP-Binary'):
        pub = keys.import_key(keys.export_public(key, fmt))
        assert not hasattr(pub, 'private_bytes')
        blob = keys.export_private(key, fmt, PASSWORD)
        restored = keys.import_key(blob, PASSWORD)
        assert keys.fingerprint(restored) == keys.fingerprint(key)
        assert list(restored.key.subkeys) == list(key.key.subkeys)
        assert [u.name for u in restored.key.userids] == [u.name for u in key.key.userids]
        with pytest.raises(ValueError): keys.import_key(blob, 'wrong')
    # No message or compressed packets are sent to PGPy's parser.
    from keyvault.openpgp import load
    with patch('pgpy.PGPKey.from_blob') as parser:
        with pytest.raises(ValueError): load(b'\xc8\x01\x01')
        parser.assert_not_called()


def test_legacy_pem_headers_and_no_trailing_data():
    key = keys.generate('RSA-2048')
    legacy = key.private_bytes(S.Encoding.PEM, S.PrivateFormat.TraditionalOpenSSL, S.BestAvailableEncryption(PASSWORD.encode()))
    assert b'Proc-Type:' in legacy
    assert keys.normalized(keys.import_key(legacy, PASSWORD)) == keys.normalized(key)
    with pytest.raises(ValueError): keys.import_key(legacy + b'extra', PASSWORD)
    with pytest.raises(ValueError): keys.import_key(legacy + legacy, PASSWORD)


def test_scrypt_pkcs8_and_resource_bound():
    from Cryptodome.IO import PKCS8
    key = keys.generate('RSA-2048')
    raw = key.private_bytes(S.Encoding.DER, S.PrivateFormat.TraditionalOpenSSL, S.NoEncryption())
    blob = PKCS8.wrap(raw, '1.2.840.113549.1.1.1', PASSWORD, protection='scryptAndAES256-CBC', prot_params={'iteration_count': 16384, 'block_size': 8, 'parallelization': 1})
    assert keys.normalized(keys.import_key(blob, PASSWORD)) == keys.normalized(key)
    info = ak.EncryptedPrivateKeyInfo.load(blob)
    info['encryption_algorithm']['parameters']['key_derivation_func']['parameters']['cost'] = 2 ** 30
    with patch('cryptography.hazmat.primitives.kdf.scrypt.Scrypt.derive') as derive:
        with pytest.raises(ValueError): keys.import_key(info.dump(), PASSWORD)
        derive.assert_not_called()


def test_pkcs12_legacy_tripledes_and_strong_export():
    key = keys.generate('RSA-2048'); cert = certificate(key)
    legacy = S.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(10000).key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).hmac_hash(hashes.SHA1()).build(PASSWORD.encode())
    blob = pkcs12.serialize_key_and_certificates(b'test', key, cert, None, legacy)
    restored = keys.import_key(blob, PASSWORD)
    assert keys.fingerprint(restored) == keys.fingerprint(key)
    assert len(restored.attachments['certificates']) == 1
    output = keys.export_private(key, 'PKCS12', PASSWORD)
    pfx = ap.Pfx.load(output)
    assert pfx['mac_data']['iterations'].native == 600000
    assert pfx['mac_data']['mac']['digest_algorithm']['algorithm'].native == 'sha256'
    assert keys.normalized(keys.import_key(output, PASSWORD)) == keys.normalized(key)


def test_certificates_jks_vault_preservation(tmp_path):
    key = keys.generate('RSA-2048'); ca = keys.generate('RSA-2048')
    ca_cert = certificate(ca, serial=2)
    leaf = certificate(key, issuer=ca_cert.subject, signer=ca)
    bundle = cert_bundle(key, [leaf, ca_cert])
    vault = Vault(); path = tmp_path / 'certificates.okv'
    try:
        vault.create(path, PASSWORD)
        rid, _ = vault.add(bundle, 'certificate bundle')
        vault.close(); vault.open(path, PASSWORD)
        assert 'private' not in vault.records()[0]
        assert len(vault.records()[0]['attachments']['certificates']) == 2
        vault.export(rid, tmp_path / 'chain.pem', 'Certificate-Chain')
        assert len(x509.load_pem_x509_certificates((tmp_path / 'chain.pem').read_bytes())) == 2
        vault.export(rid, tmp_path / 'key.jks', 'JKS', True, PASSWORD, PASSWORD)
        items = import_items((tmp_path / 'key.jks').read_bytes(), PASSWORD)
        assert len(items) == 1 and len(items[0].attachments['certificates']) == 2
        assert keys.normalized(items[0]) == keys.normalized(key)
        vault.export(rid, tmp_path / 'key.p12', 'PKCS12', True, PASSWORD, PASSWORD)
        restored = keys.import_key((tmp_path / 'key.p12').read_bytes(), PASSWORD)
        assert len(restored.attachments['certificates']) == 2
    finally: vault.close()


def test_atomic_batch_import_rollback(tmp_path):
    v = Vault()
    try:
        v.create(tmp_path / 'atomic.okv', PASSWORD)
        key = keys.generate('Ed25519')
        before = v.path.read_bytes()
        with pytest.raises(ValueError): v.add_many([key, key], 'duplicate')
        assert v.records() == [] and v.path.read_bytes() == before
    finally: v.close()


def test_ssh_certificate_signature_and_preservation(tmp_path):
    ca, key = keys.generate('Ed25519'), keys.generate('RSA-2048')
    cert = S.SSHCertificateBuilder().public_key(key.public_key()).serial(17).type(S.SSHCertificateType.USER).key_id(b'synthetic').valid_principals([b'user']).valid_after(1).valid_before(2 ** 32).sign(ca)
    bundle = keys.import_key(cert.public_bytes())
    assert keys.fingerprint(bundle) == keys.fingerprint(key)
    bundle.attachments['ssh_certificate'] = cert.public_bytes().decode()
    v = Vault()
    try:
        v.create(tmp_path / 'sshcert.okv', PASSWORD); rid, _ = v.add(bundle, 'certificate')
        v.export(rid, tmp_path / 'cert.pub', 'SSH-Certificate')
        restored = S.load_ssh_public_identity((tmp_path / 'cert.pub').read_bytes())
        restored.verify_cert_signature()
        assert restored.serial == 17 and restored.valid_principals == [b'user']
    finally: v.close()


def test_ppk_ed25519_uses_unsigned_fixed_width_seed():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    seed = bytes([255]) * 32
    key = Ed25519PrivateKey.from_private_bytes(seed)
    blob = keys.export_private(key, 'PPK-v3', plaintext=True)
    lines = blob.splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith(b'Private-Lines:'))
    count = int(lines[index].split(b':')[1])
    assert base64.b64decode(b''.join(lines[index + 1:index + 1 + count])) == b'\x00\x00\x00\x20' + seed
    assert keys.normalized(keys.import_key(blob)) == keys.normalized(key)


def test_pbes1_md5_des_import():
    from Cryptodome.Protocol.KDF import PBKDF1
    from Cryptodome.Hash import MD5
    from Cryptodome.Cipher import DES
    from Cryptodome.Util.Padding import pad
    key = keys.generate('RSA-2048')
    clear = key.private_bytes(S.Encoding.DER, S.PrivateFormat.PKCS8, S.NoEncryption())
    salt = b'12345678'
    derived = PBKDF1(PASSWORD.encode(), salt, 16, count=1000, hashAlgo=MD5)
    encrypted = DES.new(derived[:8], DES.MODE_CBC, derived[8:]).encrypt(pad(clear, 8))
    blob = ak.EncryptedPrivateKeyInfo({'encryption_algorithm': {'algorithm': 'pbes1_md5_des', 'parameters': {'salt': salt, 'iterations': 1000}}, 'encrypted_data': encrypted}).dump()
    assert keys.normalized(keys.import_key(blob, PASSWORD)) == keys.normalized(key)


@pytest.mark.parametrize('algorithm,fmt', [('SM2', 'PEM'), ('OpenPGP-RSA3072', 'OpenPGP')])
def test_new_algorithms_vault_reopen_and_export(tmp_path, algorithm, fmt):
    v = Vault(); path = tmp_path / 'new-algorithm.okv'
    key = keys.generate(algorithm)
    try:
        v.create(path, PASSWORD)
        rid, _ = v.add(key, 'synthetic new algorithm', 'test', 'encrypted metadata')
        v.close(); v.open(path, PASSWORD)
        assert v.records()[0]['has_private'] and 'private' not in v.records()[0]
        v.export(rid, tmp_path / 'protected.key', fmt, True, PASSWORD, PASSWORD)
        assert keys.fingerprint(keys.import_key((tmp_path / 'protected.key').read_bytes(), PASSWORD)) == keys.fingerprint(key)
    finally: v.close()
