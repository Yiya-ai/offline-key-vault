"""Browser adapter: standard libraries, no native driver or filesystem access."""
import base64
import hashlib
import hmac
import os
from asn1crypto import keys as ak, pem, pkcs12 as ap, cms, x509 as ax
from cryptography.hazmat.primitives import serialization as S
from browser_crypto import sm2Public, sm2Validate, pkcs12Kdf

OID = '1.2.156.10197.1.301'
ak.NamedCurve.register(OID, OID, 32)
ORDER = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123


class SM2Public:
    def __init__(self, der):
        self.der = der

    def public_bytes(self, encoding, format):
        if format != S.PublicFormat.SubjectPublicKeyInfo or encoding not in (S.Encoding.PEM, S.Encoding.DER):
            raise ValueError('SM2 公钥使用 SPKI PEM / DER')
        return pem.armor('PUBLIC KEY', self.der) if encoding == S.Encoding.PEM else self.der


class SM2Private:
    def __init__(self, der, public):
        self.der, self.public = der, public

    def public_key(self):
        return self.public

    def private_bytes(self, encoding, format, encryption):
        if format != S.PrivateFormat.PKCS8 or not isinstance(encryption, S.NoEncryption) or encoding not in (S.Encoding.PEM, S.Encoding.DER):
            raise ValueError('SM2 私钥使用 PKCS#8 PEM / DER')
        return pem.armor('PRIVATE KEY', self.der) if encoding == S.Encoding.PEM else self.der


def _public(point):
    point = bytes.fromhex(sm2Validate(point.hex()))
    return SM2Public(ak.PublicKeyInfo({'algorithm': {'algorithm': 'ec', 'parameters': ak.ECDomainParameters(name='named', value=OID)}, 'public_key': point}).dump())


def _private(number):
    if not 1 <= number < ORDER:
        raise ValueError('SM2 私钥参数无效')
    point = bytes.fromhex(sm2Public(number.to_bytes(32, 'big').hex()))
    scalar = ak.ECPrivateKey({'version': 'ecPrivkeyVer1', 'private_key': number, 'public_key': point})
    scalar.set_key_size(32)
    info = ak.PrivateKeyInfo({'version': 0, 'private_key_algorithm': {'algorithm': 'ec', 'parameters': ak.ECDomainParameters(name='named', value=OID)}, 'private_key': scalar})
    return SM2Private(info.dump(), _public(point))


def generate_sm2():
    while True:
        number = int.from_bytes(os.urandom(32), 'big')
        if 1 <= number < ORDER:
            return _private(number)


def load_sm2(data, private):
    _, _, der = pem.unarmor(data)
    info = (ak.PrivateKeyInfo if private else ak.PublicKeyInfo).load(der, strict=True)
    params = info['private_key_algorithm' if private else 'algorithm']
    if params['algorithm'].native != 'ec' or params['parameters'].native != OID:
        raise ValueError('不是 SM2 密钥')
    if not private:
        return _public(info['public_key'].native)
    inner = info['private_key'].parsed
    key = _private(inner['private_key'].native)
    if inner['parameters'].native not in (None, OID):
        raise ValueError('SM2 内外曲线参数不一致')
    if inner['public_key'].native is not None:
        supplied = _public(inner['public_key'].native)
        if not hmac.compare_digest(supplied.der, key.public.der):
            raise ValueError('SM2 公私钥参数不匹配')
    return key


def _kdf(password, salt, purpose, count, size, digest='sha1'):
    return bytes.fromhex(pkcs12Kdf(password.decode('utf-8'), salt.hex(), purpose, count, size, digest))


def decrypt_legacy(algorithm_der, ciphertext, password):
    from asn1crypto import algos
    from Crypto.Cipher import DES3, ARC2
    from Crypto.Util.Padding import unpad
    algorithm = algos.EncryptionAlgorithm.load(algorithm_der, strict=True)
    kind = algorithm['algorithm'].native
    sizes = {'pkcs12_sha1_tripledes_3key': 24, 'pkcs12_sha1_tripledes_2key': 16,
             'pkcs12_sha1_rc2_128': 16, 'pkcs12_sha1_rc2_40': 5}
    if kind not in sizes:
        raise ValueError('旧容器算法不支持')
    params = algorithm['parameters'].native
    salt, count = params['salt'], params['iterations']
    if not isinstance(count, int) or not 1 <= count <= 2000000 or not 1 <= len(salt) <= 1024 or not 0 < len(ciphertext) <= 131072 or len(ciphertext) % 8:
        raise ValueError('旧容器资源限制')
    key = _kdf(password, salt, 1, count, sizes[kind])
    iv = _kdf(password, salt, 2, count, 8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv) if 'tripledes' in kind else ARC2.new(key, ARC2.MODE_CBC, iv, effective_keylen=sizes[kind] * 8)
    return unpad(cipher.decrypt(ciphertext), 8)


def export_p12(key_pem, password, certificates=()):
    # Standard ASN.1 container assembly; all KDFs/ciphers are library calls.
    from .pbes2 import encrypt_pkcs8
    if b'\0' in password or len(password) > 1024:
        raise ValueError('PKCS#12 口令无效')
    _, _, der = pem.unarmor(key_pem)
    encrypted = ak.EncryptedPrivateKeyInfo.load(encrypt_pkcs8(der, password), strict=True)
    bags = [ap.SafeBag({'bag_id': 'pkcs8_shrouded_key_bag', 'bag_value': encrypted})]
    for cert in certificates:
        bags.append(ap.SafeBag({'bag_id': 'cert_bag', 'bag_value': ap.CertBag({'cert_id': 'x509', 'cert_value': ax.Certificate.load(cert, strict=True)})}))
    safe = ap.AuthenticatedSafe([cms.ContentInfo({'content_type': 'data', 'content': ap.SafeContents(bags).dump()})]).dump()
    salt = os.urandom(16)
    mac = hmac.new(_kdf(password, salt, 3, 600000, 32, 'sha256'), safe, hashlib.sha256).digest()
    return ap.Pfx({'version': 'v3', 'auth_safe': {'content_type': 'data', 'content': safe},
                   'mac_data': {'mac': {'digest_algorithm': {'algorithm': 'sha256'}, 'digest': mac}, 'mac_salt': salt, 'iterations': 600000}}).dump()


def load_sm2_p12(data, password):
    """Fallback for key-only SM2 PFX; cryptography does not expose SM2 keys."""
    from .import_guard import check_der
    from .pbes2 import decrypt_checked
    from .keys import import_key
    pfx = ap.Pfx.load(data, strict=True)
    mac = pfx['mac_data']
    if pfx['version'].native != 'v3' or pfx['auth_safe']['content_type'].native != 'data' or mac.native is None:
        raise ValueError('SM2 PFX 需要口令 MAC')
    digest = mac['mac']['digest_algorithm']['algorithm'].native
    if digest not in ('sha1', 'sha256', 'sha384', 'sha512'):
        raise ValueError('PFX MAC 算法不支持')
    count, salt = mac['iterations'].native, mac['mac_salt'].native
    if not 1 <= count <= 2000000 or not 1 <= len(salt) <= 1024:
        raise ValueError('PFX MAC 参数超限')
    payload = pfx['auth_safe']['content'].native
    derived = _kdf(password, salt, 3, count, hashlib.new(digest).digest_size, digest)
    if not hmac.compare_digest(hmac.digest(derived, payload, digest), mac['mac']['digest'].native):
        raise ValueError('PFX 口令或完整性校验失败')
    check_der(data, password)
    safes = ap.AuthenticatedSafe.load(payload, strict=True)
    if len(safes) != 1 or safes[0]['content_type'].native != 'data':
        raise ValueError('SM2 PFX 仅支持单密钥容器')
    bags = ap.SafeContents.load(safes[0]['content'].native, strict=True)
    if len(bags) != 1 or bags[0]['bag_id'].native not in ('pkcs8_shrouded_key_bag', 'key_bag'):
        raise ValueError('SM2 PFX 仅支持单密钥容器')
    bag = bags[0]
    if bag['bag_id'].native == 'pkcs8_shrouded_key_bag':
        decrypt, _ = decrypt_checked(bag['bag_value'])
        key = import_key(decrypt(password))
    else:
        key = import_key(bag['bag_value'].untag().dump())
    if not isinstance(key, SM2Private):
        raise ValueError('不是 SM2 容器')
    return key
