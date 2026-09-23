"""Strict PuTTY v2/v3 serialization; primitives supplied by audited libraries."""
import base64
import hashlib
import hmac
import os
import struct
import textwrap
from cryptography.hazmat.primitives import serialization as S
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def string(value):
    return struct.pack('>I', len(value)) + value


def mpint(value):
    return string(value.to_bytes((value.bit_length() + 8) // 8, 'big'))


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def integer(self):
        if self.pos + 4 > len(self.data):
            raise ValueError('PPK 私钥字段不完整')
        size = struct.unpack_from('>I', self.data, self.pos)[0]
        self.pos += 4
        if size > 513 or self.pos + size > len(self.data):
            raise ValueError('PPK 整数字段超过限制')
        value = self.data[self.pos:self.pos + size]
        self.pos += size
        if value and value[0] & 128:
            raise ValueError('PPK 不允许负整数')
        return int.from_bytes(value, 'big')


def derive(version, password, encrypted, params):
    if version == 2:
        pw = password if encrypted else b''
        return (hashlib.sha1(b'\0\0\0\0' + pw).digest() + hashlib.sha1(b'\0\0\0\1' + pw).digest())[:32], b'\0' * 16, hashlib.sha1(b'putty-private-key-file-mac-key' + pw).digest()
    if not encrypted:
        return b'', b'', b''
    from argon2.low_level import hash_secret_raw, Type
    variant, memory, passes, lanes, salt = params
    kinds = {'Argon2d': Type.D, 'Argon2i': Type.I, 'Argon2id': Type.ID}
    if variant not in kinds or not 1 <= lanes <= 16 or not 8 * lanes <= memory <= 262144 or not 1 <= passes <= 32 or memory * passes > 1048576 or not 8 <= len(salt) <= 64:
        raise ValueError('PPK Argon2 参数超出资源限制（256 MiB / 32 次 / 总量 1 GiB）')
    raw = hash_secret_raw(password, salt, passes, memory, lanes, 80, kinds[variant], version=19)
    return raw[:32], raw[32:48], raw[48:]


def load(data, password):
    lines = data.splitlines()
    if len(lines) > 4096:
        raise ValueError('PPK 行数过多')
    pos = 0
    def field(name):
        nonlocal pos
        if pos >= len(lines) or not lines[pos].startswith(name + b': '):
            raise ValueError('PPK 字段顺序或名称错误')
        value = lines[pos][len(name) + 2:]
        pos += 1
        return value
    def block(name):
        nonlocal pos
        count = int(field(name))
        if not 1 <= count <= 2048 or pos + count > len(lines):
            raise ValueError('PPK 数据行数错误')
        value = base64.b64decode(b''.join(lines[pos:pos + count]), validate=True)
        pos += count
        return value
    if data.startswith(b'PuTTY-User-Key-File-3: '):
        version = 3
    elif data.startswith(b'PuTTY-User-Key-File-2: '):
        version = 2
    else:
        raise ValueError('仅支持已发布的 PPK v2 / v3')
    kind = field(('PuTTY-User-Key-File-' + str(version)).encode())
    encryption, comment = field(b'Encryption'), field(b'Comment')
    if encryption not in (b'none', b'aes256-cbc') or len(comment) > 4096:
        raise ValueError('PPK 加密方式或注释无效')
    public_blob = block(b'Public-Lines')
    public = S.load_ssh_public_key(kind + b' ' + base64.b64encode(public_blob))
    from .keys import algorithm
    algorithm(public)
    if isinstance(public, rsa.RSAPublicKey) and public.key_size < 2048:
        raise ValueError('PPK RSA 私钥至少 2048 位')
    encrypted = encryption != b'none'
    params = None
    if version == 3 and encrypted:
        params = (field(b'Key-Derivation').decode('ascii'), int(field(b'Argon2-Memory')), int(field(b'Argon2-Passes')), int(field(b'Argon2-Parallelism')), bytes.fromhex(field(b'Argon2-Salt').decode('ascii')))
    private = block(b'Private-Lines')
    mac = bytes.fromhex(field(b'Private-MAC').decode('ascii'))
    if pos != len(lines) or len(mac) != (20 if version == 2 else 32):
        raise ValueError('PPK 尾部或 MAC 无效')
    cipher_key, iv, mac_key = derive(version, password, encrypted, params)
    if encrypted:
        if not private or len(private) % 16:
            raise ValueError('PPK 密文长度错误')
        decryptor = Cipher(algorithms.AES(cipher_key), modes.CBC(iv)).decryptor()
        private = decryptor.update(private) + decryptor.finalize()
    preimage = b''.join(map(string, (kind, encryption, comment, public_blob, private)))
    expected = hmac.digest(mac_key, preimage, 'sha1' if version == 2 else 'sha256')
    if not hmac.compare_digest(mac, expected):
        raise ValueError('PPK 口令错误或完整性校验失败')
    reader = Reader(private)
    if isinstance(public, rsa.RSAPublicKey):
        d, p, q, iqmp = [reader.integer() for _ in range(4)]
        key = rsa.RSAPrivateNumbers(p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q), iqmp, public.public_numbers()).private_key()
    elif isinstance(public, ec.EllipticCurvePublicKey):
        key = ec.derive_private_key(reader.integer(), public.curve)
    elif isinstance(public, ed25519.Ed25519PublicKey):
        # PuTTY stores the 32-byte Ed25519 seed as an unsigned byte string,
        # not an SSH signed mpint (see official crypto/ecc-ssh.c).
        if private[:4] != b'\x00\x00\x00\x20' or len(private) < 36:
            raise ValueError('PPK Ed25519 seed 长度必须为 32 字节')
        key = ed25519.Ed25519PrivateKey.from_private_bytes(private[4:36])
        reader.pos = 36
    else:
        raise ValueError('PPK 算法不支持')
    trailing = len(private) - reader.pos
    if trailing < 0 or trailing > (15 if encrypted else 0):
        raise ValueError('PPK 私钥尾部数据异常')
    if key.public_key().public_bytes(S.Encoding.OpenSSH, S.PublicFormat.OpenSSH).split()[1] != base64.b64encode(public_blob):
        raise ValueError('PPK 公私钥不匹配')
    return key


def dump(key, password=b'', version=3):
    if version not in (2, 3):
        raise ValueError('PPK 版本错误')
    public = key.public_key().public_bytes(S.Encoding.OpenSSH, S.PublicFormat.OpenSSH)
    kind, blob = public.split()[:2]
    public_blob = base64.b64decode(blob)
    if isinstance(key, rsa.RSAPrivateKey):
        n = key.private_numbers()
        private = b''.join(mpint(x) for x in (n.d, n.p, n.q, n.iqmp))
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        private = mpint(key.private_numbers().private_value)
    elif isinstance(key, ed25519.Ed25519PrivateKey):
        private = string(key.private_bytes(S.Encoding.Raw, S.PrivateFormat.Raw, S.NoEncryption()))
    else:
        raise ValueError('PPK 仅支持 RSA、NIST ECDSA、Ed25519')
    encrypted = bool(password)
    encryption = b'aes256-cbc' if encrypted else b'none'
    params = ('Argon2id', 65536, 3, 2, os.urandom(16))
    cipher_key, iv, mac_key = derive(version, password, encrypted, params)
    if encrypted:
        private += os.urandom(-len(private) % 16)
    mac = hmac.digest(mac_key, b''.join(map(string, (kind, encryption, b'', public_blob, private))), 'sha1' if version == 2 else 'sha256')
    if encrypted:
        encryptor = Cipher(algorithms.AES(cipher_key), modes.CBC(iv)).encryptor()
        private = encryptor.update(private) + encryptor.finalize()
    def block(name, data):
        rows = textwrap.wrap(base64.b64encode(data).decode('ascii'), 64)
        return name + ': ' + str(len(rows)) + '\n' + '\n'.join(rows) + '\n'
    result = f'PuTTY-User-Key-File-{version}: {kind.decode()}\nEncryption: {encryption.decode()}\nComment: \n' + block('Public-Lines', public_blob)
    if version == 3 and encrypted:
        result += f'Key-Derivation: Argon2id\nArgon2-Memory: 65536\nArgon2-Passes: 3\nArgon2-Parallelism: 2\nArgon2-Salt: {params[-1].hex()}\n'
    return (result + block('Private-Lines', private) + 'Private-MAC: ' + mac.hex() + '\n').encode('ascii')
