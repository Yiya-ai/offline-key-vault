"""Bound password KDF costs before calling native key parsers."""
import base64
import struct
from asn1crypto import keys as ak, pkcs12 as ap, core
from .pbes2 import decrypt_checked

MAX_ITERATIONS = 2_000_000


def _bounded(value, maximum=MAX_ITERATIONS):
    if not isinstance(value, int) or not 1 <= value <= maximum:
        raise ValueError('密钥导入口令派生参数超过安全资源限制')


def _rsa_size(private):
    if private['version'].native != 'two-prime':
        raise ValueError('不接受多素数 RSA 私钥')
    if private['modulus'].native.bit_length() not in (2048, 3072, 4096) or private['public_exponent'].native != 65537:
        raise ValueError('RSA 大小或公钥指数不符合策略')
    for name in ('private_exponent', 'prime1', 'prime2', 'exponent1', 'exponent2', 'coefficient'):
        if private[name].native.bit_length() > 4096:
            raise ValueError('RSA 参数过大')


def _plain_der(data):
    seq = core.Sequence.load(data, strict=True)
    if len(seq) >= 9 and isinstance(seq[1], core.Integer):
        _rsa_size(ak.RSAPrivateKey.load(data, strict=True))
    elif len(seq) >= 3 and isinstance(seq[0], core.Integer) and isinstance(seq[1], core.Sequence) and isinstance(seq[2], core.OctetString):
        info = ak.PrivateKeyInfo.load(data, strict=True)
        if info['private_key_algorithm']['algorithm'].native == 'rsa':
            _rsa_size(info['private_key'].parsed)


def _decrypt(info, password, budget):
    decrypt, count = decrypt_checked(info)
    budget[0] += count
    if budget[0] > 4_000_000:
        raise ValueError('容器累计口令派生成本过高')
    return decrypt(password)


def check_der(data, password=b''):
    budget = [0]
    seq = core.Sequence.load(data, strict=True)
    if len(seq) == 2 and isinstance(seq[0], core.Sequence) and isinstance(seq[1], core.OctetString):
        info = ak.EncryptedPrivateKeyInfo.load(data, strict=True)
        _plain_der(_decrypt(info, password, budget))
    elif len(seq) >= 2 and isinstance(seq[0], core.Integer) and seq[0].native == 3 and isinstance(seq[1], core.Sequence):
        pfx = ap.Pfx.load(data, strict=True)
        mac = pfx['mac_data']
        if mac.native is None:
            raise ValueError('PKCS#12 必须包含可验证的口令 MAC')
        # Reject PBMAC1 before OpenSSL (CVE-2026-34181), and bound all MAC work.
        sizes = {'sha1': 20, 'sha224': 28, 'sha256': 32, 'sha384': 48, 'sha512': 64}
        digest_size = sizes.get(mac['mac']['digest_algorithm']['algorithm'].native)
        if (not digest_size or len(mac['mac']['digest'].native) != digest_size
                or mac['mac']['digest_algorithm']['parameters'].native is not None
                or not 1 <= len(mac['mac_salt'].native) <= 1024):
            raise ValueError('PKCS#12 MAC 算法或参数不支持')
        _bounded(mac['iterations'].native)
        budget[0] += mac['iterations'].native
        if pfx['auth_safe']['content_type'].native != 'data':
            raise ValueError('不支持签名式 PFX 容器')
        key_count = 0
        bag_count = 0
        safe = ap.AuthenticatedSafe.load(pfx['auth_safe']['content'].native, strict=True)
        if len(safe) > 20:
            raise ValueError('PFX 包含过多安全容器')
        for content in safe:
            kind = content['content_type'].native
            if kind == 'data':
                inner = content['content'].native
            elif kind == 'encrypted_data':
                encrypted = content['content']['encrypted_content_info']
                info = ak.EncryptedPrivateKeyInfo({'encryption_algorithm': encrypted['content_encryption_algorithm'], 'encrypted_data': encrypted['encrypted_content'].native})
                inner = _decrypt(info, password, budget)
            else:
                raise ValueError('不支持此 PFX 安全容器类型')
            bags = ap.SafeContents.load(inner, strict=True)
            bag_count += len(bags)
            if bag_count > 50:
                raise ValueError('PFX 包含过多条目')
            for bag in bags:
                kind = bag['bag_id'].native
                if kind in ('pkcs8_shrouded_key_bag', 'key_bag'):
                    key_count += 1
                    if key_count > 1:
                        raise ValueError('PKCS#12 含多把私钥；为避免静默丢失，请先离线拆分')
                if kind == 'pkcs8_shrouded_key_bag':
                    _plain_der(_decrypt(bag['bag_value'], password, budget))
                elif kind == 'key_bag':
                    _plain_der(bag['bag_value'].untag().dump())
                elif kind != 'cert_bag':
                    raise ValueError('PFX 仅接受私钥与证书，不支持嵌套容器')
    else:
        _plain_der(data)


def check_ssh(data):
    blob = base64.b64decode(b''.join(data.strip().splitlines()[1:-1]), validate=True)
    if not blob.startswith(b'openssh-key-v1\0'):
        raise ValueError('OpenSSH 头无效')
    offset = 15
    def read_string():
        nonlocal offset
        if offset + 4 > len(blob):
            raise ValueError('OpenSSH 数据不完整')
        size = struct.unpack_from('>I', blob, offset)[0]
        offset += 4
        if offset + size > len(blob):
            raise ValueError('OpenSSH 字段长度异常')
        value = blob[offset:offset + size]
        offset += size
        return value
    cipher, kdf, options = read_string(), read_string(), read_string()
    if kdf == b'bcrypt':
        if len(options) < 8:
            raise ValueError('bcrypt 参数无效')
        salt_len = struct.unpack_from('>I', options)[0]
        if salt_len > 64 or len(options) != salt_len + 8:
            raise ValueError('bcrypt 盐长度异常')
        _bounded(struct.unpack_from('>I', options, 4 + salt_len)[0], 200)
    elif kdf != b'none' or cipher != b'none' or options:
        raise ValueError('OpenSSH KDF 不支持')
    if offset + 4 > len(blob) or struct.unpack_from('>I', blob, offset)[0] != 1:
        raise ValueError('只支持单把 OpenSSH 密钥')
    offset += 4
    public = read_string()
    # The public RSA modulus is visible even when the private key is encrypted.
    pos = 0
    parts = []
    while pos + 4 <= len(public) and len(parts) < 3:
        n = struct.unpack_from('>I', public, pos)[0]
        pos += 4
        if pos + n > len(public):
            raise ValueError('SSH 公钥字段无效')
        parts.append(public[pos:pos + n]); pos += n
    if parts and parts[0] == b'ssh-rsa':
        if len(parts) != 3 or int.from_bytes(parts[1], 'big') != 65537 or int.from_bytes(parts[2], 'big').bit_length() not in (2048, 3072, 4096):
            raise ValueError('RSA 密钥大小不符合策略')
