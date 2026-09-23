"""OpenPGP v4 key documents with identity/subkey retention and bounded S2K."""
import copy
from cryptography.hazmat.primitives import serialization as S


def _preflight(data):
    from pgpy.types import Armorable
    raw = bytes(Armorable.ascii_unarmor(data)['body']) if data.lstrip().startswith(b'-----') else data
    pos = count = 0
    while pos < len(raw):
        head = raw[pos]; pos += 1
        if not head & 128: raise ValueError('OpenPGP 数据包头错误')
        if head & 64:
            tag = head & 63
            if pos >= len(raw): raise ValueError('OpenPGP 长度缺失')
            first = raw[pos]; pos += 1
            if first < 192: size = first
            elif first < 224:
                if pos >= len(raw): raise ValueError('OpenPGP 长度缺失')
                size = ((first - 192) << 8) + raw[pos] + 192; pos += 1
            elif first == 255:
                if pos + 4 > len(raw): raise ValueError('OpenPGP 长度缺失')
                size = int.from_bytes(raw[pos:pos + 4], 'big'); pos += 4
            else: raise ValueError('密钥文档不接受分段数据包')
        else:
            tag = (head >> 2) & 15; length = head & 3
            if length == 3: raise ValueError('密钥文档不接受无限长度数据包')
            width = 1 << length
            if pos + width > len(raw): raise ValueError('OpenPGP 长度缺失')
            size = int.from_bytes(raw[pos:pos + width], 'big'); pos += width
        count += 1
        if tag not in (2, 5, 6, 7, 13, 14, 17) or count > 256 or size > 131072 or pos + size > len(raw):
            raise ValueError('OpenPGP 仅接受有界密钥文档，不接受消息、压缩包或未知数据包')
        if tag in (5, 6, 7, 14) and (size == 0 or raw[pos] != 4):
            raise ValueError('当前 OpenPGP 解析器支持 v4 密钥；v5/v6 不会降级解析')
        pos += size


class PGPPublic:
    def __init__(self, key): self.key = key
    def public_bytes(self, encoding, format):
        return bytes(self.key) if encoding == S.Encoding.DER else str(self.key).encode('ascii')


class PGPPrivate(PGPPublic):
    def public_key(self): return PGPPublic(self.key.pubkey)
    def private_bytes(self, encoding, format, encryption):
        if not isinstance(encryption, S.NoEncryption): raise ValueError('请使用 OpenPGP 专用加密导出')
        return bytes(self.key) if encoding == S.Encoding.DER else str(self.key).encode('ascii')


def load(data, password=''):
    from pgpy import PGPKey
    _preflight(data)
    key, others = PGPKey.from_blob(data)
    if any(str(k.fingerprint) != str(key.fingerprint) for k in others.values()):
        raise ValueError('请分别导入多把 OpenPGP 主密钥')
    items = [key, *key.subkeys.values()]
    if len(items) > 17: raise ValueError('OpenPGP 子密钥超过 16 把')
    work = 0
    for item in items:
        if not item.is_public:
            s2k = item._key.keymaterial.s2k
            if s2k:
                if int(s2k.specifier) not in (0, 1, 3): raise ValueError('不支持 OpenPGP 智能卡占位符或此 S2K')
                work += s2k.count if int(s2k.specifier) == 3 else 1024
    if work > 268435456: raise ValueError('OpenPGP 累计 S2K 超过 256 MiB 哈希预算')
    for item in items:
        material = item._key.keymaterial
        if not item.is_public and material.s2k:
            item._key.unprotect(password)
            material.s2k.usage = 0
            material.encbytes.clear()
            material._compute_chksum()
            item._key.update_hlen()
        # Validate all embedded public/private keys through the normal key policy.
        from .keys import algorithm
        public = material.__pubkey__()
        algorithm(public if item.is_public else material.__privkey__())
        if not item.is_public:
            derived = material.__privkey__().public_key()
            if derived.public_bytes(S.Encoding.DER, S.PublicFormat.SubjectPublicKeyInfo) != public.public_bytes(S.Encoding.DER, S.PublicFormat.SubjectPublicKeyInfo):
                raise ValueError('OpenPGP 公私钥不匹配')
    return PGPPublic(key) if key.is_public else PGPPrivate(key)


def generate(name='Local OpenPGP key'):
    from pgpy import PGPKey, PGPUID
    from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
    primary = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 3072)
    primary.add_uid(PGPUID.new(name), usage={KeyFlags.Sign, KeyFlags.Certify}, hashes=[HashAlgorithm.SHA256], ciphers=[SymmetricKeyAlgorithm.AES256], compression=[CompressionAlgorithm.Uncompressed])
    primary.add_subkey(PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 3072), usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage})
    return PGPPrivate(primary)


def export(key, private=False, password='', binary=False):
    from pgpy.constants import SymmetricKeyAlgorithm, HashAlgorithm
    value = copy.copy(key.key if private else key.key.pubkey)
    if private and password:
        value.protect(password, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    return bytes(value) if binary else str(value).encode('ascii')
