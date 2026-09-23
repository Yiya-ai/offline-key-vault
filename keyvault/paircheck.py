"""Compare validated public key material without signing or exporting private keys."""
import hashlib
import base64
import hmac
import re
from cryptography.hazmat.primitives import serialization as S
from . import keys
from .material import import_items
from .openpgp import PGPPublic


def _material(key):
    public = keys.public_of(key)
    if isinstance(public, PGPPublic):
        native = public.key._key.keymaterial.__pubkey__()
        primary = native.public_bytes(S.Encoding.DER, S.PublicFormat.SubjectPublicKeyInfo)
        subkeys = sorted(item._key.keymaterial.__pubkey__().public_bytes(S.Encoding.DER, S.PublicFormat.SubjectPublicKeyInfo) for item in public.key.subkeys.values())
        return primary, subkeys, True
    return public.public_bytes(S.Encoding.DER, S.PublicFormat.SubjectPublicKeyInfo), [], False


class PairCheckError(ValueError):
    """Role-specific, fixed diagnostic text; never includes supplied key material."""
    def __init__(self, side, reason, detail):
        self.side, self.reason = side, reason
        super().__init__(('公钥' if side == 'public' else '私钥') + '：' + detail)


def _normalize(data, side):
    if isinstance(data, str):
        try:
            data = data.encode('utf-8')
        except UnicodeError:
            raise PairCheckError(side, 'format', '文本编码无效，请重新复制完整文本或选择原始文件。') from None
    if not isinstance(data, bytes) or not 0 < len(data) <= keys.MAX_KEY_BYTES:
        raise PairCheckError(side, 'size', '输入为空或超过 128 KiB 限制。')
    # Preserve arbitrary binary DER bytes, including meaningful leading/trailing bytes.
    if data.startswith(b'\xef\xbb\xbf'):
        data = data[3:]
    stripped = data.strip()
    if not stripped.startswith(b'-----BEGIN '):
        return data
    # Support pasted literal escape sequences only within explicit PEM armor.
    stripped = stripped.replace(b'\\r\\n', b'\n').replace(b'\\n', b'\n').replace(b'\\r', b'\n').strip()
    if stripped.count(b'-----BEGIN ') > 1:
        if side == 'public' and stripped.count(b'-----BEGIN CERTIFICATE-----') == stripped.count(b'-----BEGIN '):
            return stripped
        raise PairCheckError(side, 'multiple', '请只提供一把密钥，不要拼接公钥、私钥或其他内容。')
    match = re.fullmatch(rb'-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----', stripped)
    if not match:
        raise PairCheckError(side, 'incomplete', 'PEM 不完整或头尾不一致，请包含完整的 BEGIN 和 END 行；也可直接选择原始文件。')
    label, body = match.groups()
    if label.startswith(b'PGP ') or b'Proc-Type:' in body or b'DEK-Info:' in body:
        return stripped
    # Fold ASCII whitespace, without fixing missing bytes, padding, or invalid characters.
    if re.fullmatch(rb'[A-Za-z0-9+/= \t\r\n]+', body):
        token = re.sub(rb'[ \t\r\n]+', b'', body)
        body = b'\n'.join(token[i:i + 64] for i in range(0, len(token), 64))
        return b'-----BEGIN ' + label + b'-----\n' + body + b'\n-----END ' + label + b'-----\n'
    return stripped


def _read_one(data, password, side, raw_kind=None, entry_password=''):
    clean = _normalize(data, side)
    try:
        items = import_items(clean, password, raw_kind=raw_kind, key_password=entry_password)
    except Exception:
        if side == 'private':
            encrypted = b'-----BEGIN ENCRYPTED PRIVATE KEY-----' in clean or b'Proc-Type: 4,ENCRYPTED' in clean
            if encrypted and not password:
                raise PairCheckError(side, 'password_required', '这是加密私钥，请填写导出文件时设置的解密口令；不是密钥库主口令。尚未判断是否匹配。') from None
            if password and clean.strip().startswith((b'-----BEGIN PRIVATE KEY-----', b'-----BEGIN RSA PRIVATE KEY-----', b'-----BEGIN EC PRIVATE KEY-----')) and b'Proc-Type:' not in clean:
                raise PairCheckError(side, 'parse', '无法读取。若为未加密私钥，请将解密口令留空；同时检查文本是否完整。尚未判断是否匹配。') from None
            raise PairCheckError(side, 'parse', '读取失败，可能是格式不支持、内容损坏或文件解密口令错误。加密文件请填写导出时设置的口令，或直接选择原始文件。尚未判断是否匹配。') from None
        raise PairCheckError(side, 'parse', '读取失败，请检查是否复制了完整公钥 / 证书，格式是否受支持；JKS 公钥容器还需要存储口令。尚未判断是否匹配。') from None
    if len(items) != 1:
        raise PairCheckError(side, 'multiple', '配对校验每侧只接受一把密钥；多条目容器请先分别导出待校验条目。')
    key = items[0]
    if side == 'public' and hasattr(key, 'private_bytes'):
        raise PairCheckError(side, 'role', '公钥输入中包含私钥，请提供只含公钥的文件或文本。')
    if side == 'private' and not hasattr(key, 'private_bytes'):
        raise PairCheckError(side, 'role', '私钥输入只有公钥，无法进行公私钥配对校验。')
    return key


def compare(public_data, private_data, private_password='', *, public_password='', raw=False, private_entry_password=''):
    public = _read_one(public_data, public_password, 'public', 'X25519-public' if raw else None)
    private = _read_one(private_data, private_password, 'private', 'X25519-private' if raw else None, private_entry_password)
    left, left_subkeys, left_pgp = _material(public)
    right, right_subkeys, right_pgp = _material(private)
    matched = hmac.compare_digest(left, right)
    scope = '公钥参数'
    if left_pgp and right_pgp:
        matched = matched and left_subkeys == right_subkeys
        scope = 'OpenPGP 主密钥及完整子密钥集合'
    elif left_pgp or right_pgp:
        scope = 'OpenPGP 主密钥的公钥参数（不含子密钥集合）'
    return {'matched': matched, 'scope': scope,
            'public_algorithm': keys.algorithm(public), 'private_algorithm': keys.algorithm(private),
            'public_fingerprint': 'SHA256:' + base64.b64encode(hashlib.sha256(left).digest()).decode().rstrip('='),
            'derived_fingerprint': 'SHA256:' + base64.b64encode(hashlib.sha256(right).digest()).decode().rstrip('=')}
