"""Dispatch formats requiring explicit preflight before library parsing."""
import base64
import re
from asn1crypto import keys as ak, core, pem
from cryptography.hazmat.primitives import serialization as S


def load(data, password):
    stripped = data.strip()
    if stripped.startswith(b'PuTTY-User-Key-File-'):
        from .ppk import load as load_ppk
        return load_ppk(stripped, password.encode('utf-8'))
    if stripped.startswith(b'-----BEGIN PGP ') or (data and data[0] & 128 and data[:4] not in (b'\xfe\xed\xfe\xed', b'\xce\xce\xce\xce')):
        from .openpgp import load as load_pgp
        return load_pgp(stripped if stripped.startswith(b'-----') else data, password)
    from .material import try_load
    bundle = try_load(data, password)
    if bundle is not None: return bundle
    label = None
    der = data
    if stripped.startswith(b'-----BEGIN '):
        if stripped.count(b'-----BEGIN ') != 1 or not re.fullmatch(rb'-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*-----END \1-----', stripped):
            raise ValueError('请提供单个完整 PEM 对象')
        label, headers, der = pem.unarmor(stripped)
        if headers:
            if label not in ('RSA PRIVATE KEY', 'EC PRIVATE KEY') or set(headers) != {'Proc-Type', 'DEK-Info'} or headers['Proc-Type'] != '4,ENCRYPTED':
                raise ValueError('传统 PEM 加密头无效')
            cipher = headers['DEK-Info'].split(',')[0]
            if cipher not in ('AES-128-CBC', 'AES-192-CBC', 'AES-256-CBC', 'DES-EDE3-CBC', 'DES-CBC'):
                raise ValueError('传统 PEM 加密算法不支持')
            from Cryptodome.IO import PEM
            der, marker, encrypted = PEM.decode(stripped.decode('ascii'), passphrase=password.encode('utf-8'))
            from .import_guard import check_der
            check_der(der)
            return S.load_der_private_key(der, None)
    if not der.startswith(b'0'): return None
    seq = core.Sequence.load(der, strict=True)
    if len(seq) == 2 and isinstance(seq[0], core.Sequence) and isinstance(seq[1], core.OctetString):
        from .pbes2 import decrypt_checked
        decrypt, _ = decrypt_checked(ak.EncryptedPrivateKeyInfo.load(der, strict=True))
        clear = decrypt(password.encode('utf-8'))
        from .keys import import_key
        return import_key(clear)
    private = label in ('PRIVATE KEY', 'EC PRIVATE KEY') or (len(seq) >= 3 and isinstance(seq[0], core.Integer))
    try:
        info = ak.PrivateKeyInfo.load(der, strict=True) if private else ak.PublicKeyInfo.load(der, strict=True)
        curve = info['private_key_algorithm' if private else 'algorithm']['parameters'].native
    except (ValueError, TypeError, KeyError): return None
    if curve == '1.2.156.10197.1.301':
        from .native_crypto import load_sm2
        return load_sm2(pem.armor('PRIVATE KEY' if private else 'PUBLIC KEY', der), private)
    return None
