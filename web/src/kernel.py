"""One ephemeral browser session. No vault, preferences, files or user history."""
import base64
import gc
import json
import sys
import warnings
# PGPy 0.6 references the old location of these legacy cipher classes.
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.decrepit.ciphers import algorithms as legacy_algorithms
for _name in ('IDEA', 'TripleDES', 'CAST5', 'Blowfish'):
    if not hasattr(algorithms, _name):
        setattr(algorithms, _name, getattr(legacy_algorithms, _name))
warnings.filterwarnings('ignore', category=DeprecationWarning)
from keyvault import keys, material, paircheck, conversion
import argon2.low_level
from argon_adapter import hash_secret_raw
argon2.low_level.hash_secret_raw = hash_secret_raw
_original_try_load = material.try_load


def _browser_try_load(data, password=''):
    try:
        return _original_try_load(data, password)
    except Exception:
        # Narrow fallback; validates PFX type, MAC, budgets and SM2 key before return.
        if data.startswith(b'0'):
            from keyvault.native_crypto import load_sm2_p12
            return load_sm2_p12(data, password.encode('utf-8'))
        raise


material.try_load = _browser_try_load

_entries = []
_original = None


def _data(value):
    if not isinstance(value, str) or len(value) > 180000:
        raise ValueError('输入为空或超过 128 KiB 限制')
    raw = base64.b64decode(value, validate=True)
    if not 0 < len(raw) <= 131072:
        raise ValueError('输入为空或超过 128 KiB 限制')
    return raw


def _password(value):
    keys.password_bytes(value)
    return value


def _formats(key):
    algo = keys.algorithm(key)
    private = hasattr(key, 'private_bytes')
    if algo.startswith('OpenPGP'):
        pub = ['OpenPGP', 'OpenPGP-Binary']
        secret = list(pub) if private else []
    else:
        pub = ['PEM', 'DER']
        secret = ['PEM', 'DER', 'PKCS12'] if private else []
        if algo != 'SM2':
            pub += ['JWK']
            if private:
                secret += ['JWK']
        if algo.startswith('RSA'):
            pub += ['PKCS1-PEM', 'PKCS1-DER']
            if private:
                secret += ['PKCS1-PEM', 'PKCS1-DER']
        if algo in ('Ed25519', 'ECDSA-P256', 'ECDSA-P384', 'ECDSA-P521') or algo.startswith('RSA'):
            pub += ['OpenSSH']
            if private:
                secret += ['OpenSSH', 'PPK-v3', 'PPK-v2']
        if algo.startswith('ECDSA') and private:
            secret += ['SEC1-PEM', 'SEC1-DER']
        if algo == 'X25519':
            pub += ['Raw-base64', 'Raw-base64url']
            if private:
                secret += ['Raw-base64', 'Raw-base64url']
    attachments = getattr(key, 'attachments', {})
    if attachments.get('certificates'):
        pub += ['Certificate-PEM', 'Certificate-Chain', 'PKCS7']
        (secret if private else pub).append('JKS')
    if attachments.get('ssh_certificate'):
        pub += ['SSH-Certificate']
    return pub, secret


def _metadata():
    result = []
    for index, key in enumerate(_entries):
        public, private = _formats(key)
        result.append({'id': index, 'alias': getattr(key, 'alias', '')[:80], 'algorithm': keys.algorithm(key),
                       'private': bool(private), 'fingerprint': keys.fingerprint(key),
                       'publicFormats': public, 'privateFormats': private,
                       'original': _original is not None and len(_entries) == 1})
    return result


def _output(data, fmt, private):
    if len(data) > 131072:
        raise ValueError('输出超过 128 KiB 限制')
    suffix = {'PEM': '.pem' if private else '.pub', 'DER': '.der', 'JWK': '.jwk', 'PKCS12': '.p12',
              'PKCS1-PEM': '.pem', 'PKCS1-DER': '.der', 'SEC1-PEM': '.pem', 'SEC1-DER': '.der',
              'OpenSSH': '.key' if private else '.pub', 'PPK-v2': '.ppk', 'PPK-v3': '.ppk',
              'OpenPGP': '.asc', 'OpenPGP-Binary': '.pgp', 'JKS': '.jks', 'PKCS7': '.p7b',
              'Certificate-PEM': '.crt', 'Certificate-Chain': '.pem', 'SSH-Certificate': '-cert.pub',
              'Raw-base64': '.txt', 'Raw-base64url': '.txt', 'Original': conversion.original_extension(data)}[fmt]
    return {'data': base64.b64encode(data).decode(), 'extension': suffix, 'private': private, 'bytes': len(data)}


def dispatch(message):
    global _entries, _original
    action = message.get('action')
    if action == 'runtime':
        import cryptography
        from cryptography.hazmat.backends.openssl.backend import backend
        return {'cryptography': cryptography.__version__, 'openssl': backend.openssl_version_text()}
    if action == 'discard':
        _entries = []
        _original = None
        return {'cleared': True}
    if action == 'generate':
        _entries = []
        _original = None
        name = message.get('identity', 'Browser key')
        if not isinstance(name, str) or len(name) > 80 or any(ord(c) < 32 for c in name):
            raise ValueError('名称最多 80 字符，不接受控制字符')
        _entries = [keys.generate(message['algorithm'], name or 'Browser key')]
        return {'items': _metadata()}
    if action == 'inspect':
        _entries = []
        _original = None
        raw = _data(message['data'])
        clean = paircheck._normalize(raw, 'public') if b'-----BEGIN ' in raw[:80] else raw
        _entries = material.import_items(clean, _password(message.get('password', '')),
                                         message.get('rawKind') or None, _password(message.get('entryPassword', '')))
        _original = raw
        return {'items': _metadata()}
    if action == 'compare':
        return paircheck.compare(_data(message['publicData']), _data(message['privateData']),
                                 _password(message.get('privatePassword', '')),
                                 public_password=_password(message.get('publicPassword', '')),
                                 private_entry_password=_password(message.get('entryPassword', '')),
                                 raw=message.get('raw') is True)
    if action not in ('export', 'preview'):
        raise ValueError('未知操作')
    index = message.get('id')
    if type(index) is not int or not 0 <= index < len(_entries):
        raise ValueError('当前没有可操作的密钥，请重新生成或读取')
    key = _entries[index]
    private = message.get('private') is True
    pub, secret = _formats(key)
    fmt = message.get('format', 'PEM')
    if action == 'preview':
        fmt = 'OpenPGP' if keys.algorithm(key).startswith('OpenPGP') else 'PEM'
        if private and message.get('confirmed') is not True:
            raise ValueError('请先确认显示私钥')
        data = keys.export_private(key, fmt, plaintext=True) if private else keys.export_public(key, fmt)
        return {'text': data.decode('ascii'), 'private': private}
    plaintext = message.get('plaintext') is True
    if fmt == 'Original':
        if _original is None or len(_entries) != 1:
            raise ValueError('当前没有可原样导出的单条输入')
        private = hasattr(key, 'private_bytes')
        if private and not plaintext:
            raise ValueError('原文可能包含未加密私钥，请明确允许原文导出')
        return _output(_original, fmt, private)
    if fmt not in (secret if private else pub):
        raise ValueError('当前密钥不支持这个导出格式')
    password = _password(message.get('password', ''))
    if fmt in ('JKS', 'PKCS12') or (private and not plaintext):
        keys.password_bytes(password, new=True)
    if fmt in ('JKS', 'Certificate-PEM', 'Certificate-Chain', 'PKCS7', 'SSH-Certificate') or (fmt == 'PKCS12' and getattr(key, 'attachments', {}).get('certificates')):
        record = {'name': 'key', 'attachments': getattr(key, 'attachments', {})}
        data = material.export_attachment(record, fmt, key if private else None, password)
    else:
        data = keys.export_private(key, fmt, password, plaintext) if private else keys.export_public(key, fmt)
    return _output(data, fmt, private)


def handle(raw):
    try:
        message = json.loads(raw)
        if not isinstance(message, dict):
            raise ValueError('操作参数无效')
        return json.dumps({'ok': True, 'result': dispatch(message)}, ensure_ascii=False)
    except (keys.KeyError, paircheck.PairCheckError) as error:
        # These application exceptions contain fixed descriptions, not parser input.
        return json.dumps({'ok': False, 'error': str(error)}, ensure_ascii=False)
    except Exception:
        return json.dumps({'ok': False, 'error': '无法处理：请检查格式、完整内容、口令及算法兼容性。尚未输出文件。'}, ensure_ascii=False)
    finally:
        gc.collect()
