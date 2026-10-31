"""Validated standalone conversion; no vault, files, clipboard or network access."""
from . import keys
from .material import import_items


def inspect(data, password='', raw_kind=None, key_password=''):
    raw = data.encode('utf-8') if isinstance(data, str) else data
    if not isinstance(raw, bytes) or not 0 < len(raw) <= keys.MAX_KEY_BYTES:
        raise ValueError('输入为空或超过 128 KiB')
    clean = raw
    if raw.lstrip(b'\xef\xbb\xbf \t\r\n').startswith(b'-----BEGIN '):
        from .paircheck import _normalize
        clean = _normalize(raw, 'public')
    items = import_items(clean, password, raw_kind=raw_kind, key_password=key_password)
    if len(items) != 1:
        raise ValueError('独立转换一次只接受一条记录；多条目容器请先导入密钥库')
    key = items[0]
    return raw, key


def convert(data, fmt='PEM', password='', export_password='', plaintext=False, raw_kind=None, key_password=''):
    raw, key = inspect(data, password, raw_kind, key_password)
    private = keys.normalized(key)[1] is not None
    if fmt == 'Original':
        if private and not plaintext:
            raise ValueError('保留私钥原文可能输出未加密内容，必须明确允许原文导出')
        output = raw
    elif private:
        output = keys.export_private(key, fmt, export_password, plaintext)
    else:
        output = keys.export_public(key, fmt)
    return output, {'private': private, 'algorithm': keys.algorithm(key), 'fingerprint': keys.fingerprint(key)}


def original_extension(data):
    raw = data.encode('utf-8') if isinstance(data, str) else data
    clean = raw.removeprefix(b'\xef\xbb\xbf').lstrip()
    if clean.startswith(b'-----BEGIN PGP '): return '.asc'
    if clean.startswith(b'-----BEGIN '): return '.pem'
    if clean.startswith(b'PuTTY-User-Key-File-'): return '.ppk'
    if clean.startswith((b'ssh-', b'ecdsa-')): return '.pub'
    if clean.startswith(b'{'): return '.jwk'
    if raw.startswith(b'\xfe\xed\xfe\xed'): return '.jks'
    if raw.startswith(b'0'): return '.der'
    return '.txt'
