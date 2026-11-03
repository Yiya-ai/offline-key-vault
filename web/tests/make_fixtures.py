"""Generate disposable test inputs; never read a user's key or vault."""
import base64
import json
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'vendor')]
from keyvault import keys
from keyvault.material import cert_bundle, export_attachment
from cryptography import x509
from cryptography.hazmat.primitives import serialization as S, hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from asn1crypto import keys as ak, pkcs12 as ap
from Cryptodome.IO import PKCS8
from Cryptodome.Protocol.KDF import PBKDF1
from Cryptodome.Hash import MD5
from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad

PASSWORD = 'Synthetic browser phrase 7314'
key = keys.generate('RSA-2048')
ca = keys.generate('RSA-2048')
now = datetime.now(timezone.utc)


def cert(key, serial, signer=None, issuer=None):
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'synthetic-' + str(serial))])
    return x509.CertificateBuilder().subject_name(subject).issuer_name(issuer or subject).public_key(key.public_key()).serial_number(serial).not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(signer or key, hashes.SHA256())


root = cert(ca, 2)
leaf = cert(key, 1, ca, root.subject)
bundle = cert_bundle(key, [leaf, root])
record = {'name': 'synthetic', 'attachments': bundle.attachments}
rows = []


def add(name, data, password='', expected=True, fingerprint=None):
    rows.append({'name': name, 'data': base64.b64encode(data).decode(), 'password': password,
                 'expected': expected, 'fingerprint': fingerprint or keys.fingerprint(key)})


add('bare-base64', base64.b64encode(keys.export_public(key, 'DER')))
add('legacy-pem', key.private_bytes(S.Encoding.PEM, S.PrivateFormat.TraditionalOpenSSL, S.BestAvailableEncryption(PASSWORD.encode())), PASSWORD)
raw = key.private_bytes(S.Encoding.DER, S.PrivateFormat.TraditionalOpenSSL, S.NoEncryption())
blob = PKCS8.wrap(raw, '1.2.840.113549.1.1.1', PASSWORD, protection='scryptAndAES256-CBC', prot_params={'iteration_count': 16384, 'block_size': 8, 'parallelization': 1})
add('scrypt', blob, PASSWORD)
from keyvault.pbes2 import decrypt_checked
info = ak.EncryptedPrivateKeyInfo.load(blob)
decrypt_checked(info)
info['encryption_algorithm']['parameters']['key_derivation_func']['parameters']['cost'] = 2 ** 30
add('scrypt-limit', info.dump(), PASSWORD, False)
clear = key.private_bytes(S.Encoding.DER, S.PrivateFormat.PKCS8, S.NoEncryption())
salt = b'12345678'
derived = PBKDF1(PASSWORD.encode(), salt, 16, count=1000, hashAlgo=MD5)
ciphertext = DES.new(derived[:8], DES.MODE_CBC, derived[8:]).encrypt(pad(clear, 8))
add('pbes1', ak.EncryptedPrivateKeyInfo({'encryption_algorithm': {'algorithm': 'pbes1_md5_des', 'parameters': {'salt': salt, 'iterations': 1000}}, 'encrypted_data': ciphertext}).dump(), PASSWORD)
legacy = S.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(10000).key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).hmac_hash(hashes.SHA1()).build(PASSWORD.encode())
add('legacy-p12', pkcs12.serialize_key_and_certificates(b'synthetic', key, leaf, [root], legacy), PASSWORD)
normal_pfx = pkcs12.serialize_key_and_certificates(b'synthetic', key, leaf, [root], legacy)
for mutation in ('missing', 'pbmac1', 'short-digest', 'empty-salt', 'huge-salt', 'iterations'):
    pfx = ap.Pfx.load(normal_pfx)
    if mutation == 'missing':
        del pfx['mac_data']
    elif mutation == 'pbmac1':
        pfx['mac_data']['mac']['digest_algorithm']['algorithm'] = '1.2.840.113549.1.5.14'
    elif mutation == 'short-digest':
        pfx['mac_data']['mac']['digest'] = b'x'
    elif mutation == 'empty-salt':
        pfx['mac_data']['mac_salt'] = b''
    elif mutation == 'huge-salt':
        pfx['mac_data']['mac_salt'] = b'x' * 1025
    else:
        pfx['mac_data']['iterations'] = 2000001
    add('pfx-reject-' + mutation, pfx.dump(), PASSWORD, False)
pgp = keys.generate('OpenPGP-RSA3072').key
mixed = pgp.pubkey
mixed._children = pgp._children
add('pgp-public-with-private-child', bytes(mixed), expected=False)
add('jks', export_attachment(record, 'JKS', key, PASSWORD), PASSWORD)
add('chain', export_attachment(record, 'Certificate-Chain'))
ssh = S.SSHCertificateBuilder().public_key(key.public_key()).serial(17).type(S.SSHCertificateType.USER).key_id(b'synthetic').valid_principals([b'user']).valid_after(1).valid_before(2 ** 32).sign(keys.generate('Ed25519'))
add('ssh-cert', ssh.public_bytes())
for algorithm in ('SM2', 'Ed25519'):
    sample = keys.generate(algorithm)
    add(algorithm + '-native', keys.export_private(sample, 'PEM', PASSWORD), PASSWORD, fingerprint=keys.fingerprint(sample))
    if algorithm == 'Ed25519':
        add('ppk-v3-native', keys.export_private(sample, 'PPK-v3', PASSWORD), PASSWORD, fingerprint=keys.fingerprint(sample))
target = ROOT / 'web/.vendor/test-fixtures.json'
target.write_text(json.dumps(rows), encoding='utf-8')
print('Generated', len(rows), 'synthetic fixtures in ignored build cache')
