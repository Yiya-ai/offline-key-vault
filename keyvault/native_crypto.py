"""Small in-process OpenSSL bridge for SM2 and legacy PKCS#12 algorithms.
Only explicit application/runtime library locations are considered.
"""
import ctypes as C
import os
from pathlib import Path
import sys
from functools import lru_cache
from cryptography.hazmat.primitives import serialization as S


@lru_cache(maxsize=1)
def lib():
    base = Path(sys.base_prefix)
    if getattr(sys, 'frozen', False):
        candidates = [Path(sys._MEIPASS) / 'libcrypto.3.dylib']
    elif sys.platform == 'win32':
        candidates = [base / 'DLLs/libcrypto-3.dll']
    else:
        candidates = [Path(getattr(sys, '_MEIPASS', base)) / 'libcrypto.3.dylib', base / 'lib/libcrypto.3.dylib', Path('/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib'), Path('/usr/local/opt/openssl@3/lib/libcrypto.3.dylib')]
    path = next((p for p in candidates if p.is_file()), None)
    if path is None:
        raise ValueError('缺少本地 OpenSSL 3 库；请使用包含该库的离线安装包')
    library = C.CDLL(str(path))
    P, I, L = C.c_void_p, C.c_int, C.c_long
    signatures = {
        'BIO_new_mem_buf': (P, [P, I]), 'BIO_s_mem': (P, []), 'BIO_new': (P, [P]), 'BIO_free': (I, [P]),
        'BIO_ctrl': (L, [P, I, L, P]), 'BIO_read': (I, [P, P, I]),
        'PEM_read_bio_PrivateKey': (P, [P, P, P, P]), 'PEM_read_bio_PUBKEY': (P, [P, P, P, P]),
        'PEM_write_bio_PKCS8PrivateKey': (I, [P, P, P, P, I, P, P]), 'PEM_write_bio_PUBKEY': (I, [P, P]),
        'EVP_PKEY_is_a': (I, [P, C.c_char_p]), 'EVP_PKEY_free': (None, [P]),
        'EVP_PKEY_CTX_new_from_name': (P, [P, C.c_char_p, C.c_char_p]), 'EVP_PKEY_CTX_new': (P, [P, P]),
        'EVP_PKEY_CTX_free': (None, [P]), 'EVP_PKEY_keygen_init': (I, [P]), 'EVP_PKEY_generate': (I, [P, P]),
        'EVP_PKEY_pairwise_check': (I, [P]), 'EVP_PKEY_private_check': (I, [P]), 'EVP_PKEY_public_check': (I, [P]),
        'd2i_X509': (P, [P, P, L]), 'X509_free': (None, [P]),
        'd2i_X509_ALGOR': (P, [P, P, L]), 'X509_ALGOR_free': (None, [P]),
        'PKCS12_pbe_crypt': (P, [P, C.c_char_p, I, P, I, P, P, I]),
        'CRYPTO_free': (None, [P, C.c_char_p, I]), 'OSSL_PROVIDER_load': (P, [P, C.c_char_p]),
        'OPENSSL_init_crypto': (I, [C.c_uint64, P]),
        'OSSL_PROVIDER_set_default_search_path': (I, [P, C.c_char_p]),
        'PKCS12_create': (P, [C.c_char_p, C.c_char_p, P, P, P, I, I, I, I, I]),
        'PKCS12_set_mac': (I, [P, C.c_char_p, I, P, I, I, P]), 'PKCS12_free': (None, [P]),
        'i2d_PKCS12': (I, [P, P]), 'EVP_sha256': (P, []),
        'OPENSSL_sk_new_null': (P, []), 'OPENSSL_sk_push': (I, [P, P]), 'OPENSSL_sk_free': (None, [P]),
    }
    for name, (restype, argtypes) in signatures.items():
        fn = getattr(library, name); fn.restype = restype; fn.argtypes = argtypes
    if getattr(sys, 'frozen', False):
        # Do not load machine-local configuration or providers from the build machine.
        if library.OPENSSL_init_crypto(0x80, None) != 1:  # OPENSSL_INIT_NO_LOAD_CONFIG
            raise ValueError('OpenSSL 离线初始化失败')
        if library.OSSL_PROVIDER_set_default_search_path(None, os.fsencode(sys._MEIPASS)) != 1:
            raise ValueError('OpenSSL 本地算法路径设置失败')
    # These providers are resolved by the bundled OpenSSL.
    if not library.OSSL_PROVIDER_load(None, b'default'):
        raise ValueError('OpenSSL 默认算法提供程序不可用')
    return library


def _read(data, private):
    api = lib(); buf = C.create_string_buffer(data); bio = api.BIO_new_mem_buf(buf, len(data))
    try:
        key = (api.PEM_read_bio_PrivateKey if private else api.PEM_read_bio_PUBKEY)(bio, None, None, None)
        if not key:
            raise ValueError('OpenSSL 无法解析密钥')
        return key
    finally:
        api.BIO_free(bio)


def _write(key, private):
    api = lib(); bio = api.BIO_new(api.BIO_s_mem())
    try:
        ok = api.PEM_write_bio_PKCS8PrivateKey(bio, key, None, None, 0, None, None) if private else api.PEM_write_bio_PUBKEY(bio, key)
        if ok != 1:
            raise ValueError('OpenSSL 密钥序列化失败')
        size = api.BIO_ctrl(bio, 10, 0, None)
        if not 0 < size <= 131072:
            raise ValueError('OpenSSL 输出长度错误')
        buf = C.create_string_buffer(size)
        if api.BIO_read(bio, buf, size) != size:
            raise ValueError('OpenSSL 输出不完整')
        return buf.raw
    finally:
        api.BIO_free(bio)


def _der(pem):
    import base64
    return base64.b64decode(b''.join(pem.splitlines()[1:-1]), validate=True)


class SM2Public:
    def __init__(self, pem):
        self.pem = pem

    def public_bytes(self, encoding, format):
        if format != S.PublicFormat.SubjectPublicKeyInfo or encoding not in (S.Encoding.PEM, S.Encoding.DER):
            raise ValueError('SM2 公钥仅支持 SPKI PEM / DER')
        return self.pem if encoding == S.Encoding.PEM else _der(self.pem)


class SM2Private:
    def __init__(self, pem, public):
        self.pem, self.public = pem, public

    def public_key(self):
        return self.public

    def private_bytes(self, encoding, format, encryption):
        if format != S.PrivateFormat.PKCS8 or not isinstance(encryption, S.NoEncryption) or encoding not in (S.Encoding.PEM, S.Encoding.DER):
            raise ValueError('SM2 私钥使用 PKCS#8 PEM / DER')
        return self.pem if encoding == S.Encoding.PEM else _der(self.pem)


def load_sm2(pem, private):
    api = lib(); key = _read(pem, private)
    try:
        if api.EVP_PKEY_is_a(key, b'SM2') != 1:
            raise ValueError('不是 SM2 密钥')
        ctx = api.EVP_PKEY_CTX_new(key, None)
        if not ctx:
            raise ValueError('SM2 上下文创建失败')
        try:
            if api.EVP_PKEY_public_check(ctx) != 1 or (private and (api.EVP_PKEY_private_check(ctx) != 1 or api.EVP_PKEY_pairwise_check(ctx) != 1)):
                raise ValueError('SM2 参数校验失败')
        finally:
            api.EVP_PKEY_CTX_free(ctx)
        public = SM2Public(_write(key, False))
        return SM2Private(_write(key, True), public) if private else public
    finally:
        api.EVP_PKEY_free(key)


def generate_sm2():
    api = lib(); ctx = api.EVP_PKEY_CTX_new_from_name(None, b'SM2', None); key = C.c_void_p()
    if not ctx:
        raise ValueError('本地 OpenSSL 不支持 SM2')
    try:
        if api.EVP_PKEY_keygen_init(ctx) != 1 or api.EVP_PKEY_generate(ctx, C.byref(key)) != 1:
            raise ValueError('SM2 生成失败')
        return SM2Private(_write(key, True), SM2Public(_write(key, False)))
    finally:
        api.EVP_PKEY_free(key); api.EVP_PKEY_CTX_free(ctx)


def _decode(fn, data):
    buf = C.create_string_buffer(data); cursor = C.c_void_p(C.addressof(buf))
    result = fn(None, C.byref(cursor), len(data))
    if not result:
        raise ValueError('OpenSSL ASN.1 解析失败')
    return result


def decrypt_legacy(algorithm_der, ciphertext, password):
    api = lib()
    api.OSSL_PROVIDER_load(None, b'legacy')
    alg = _decode(api.d2i_X509_ALGOR, algorithm_der)
    output = C.c_void_p(); length = C.c_int()
    try:
        buf = C.create_string_buffer(ciphertext)
        if not api.PKCS12_pbe_crypt(alg, password, len(password), buf, len(ciphertext), C.byref(output), C.byref(length), 0):
            raise ValueError('旧容器解密失败：口令或数据错误')
        if not 0 < length.value <= 131072:
            raise ValueError('旧容器解密长度异常')
        return C.string_at(output, length.value)
    finally:
        if output: api.CRYPTO_free(output, None, 0)
        api.X509_ALGOR_free(alg)


def export_p12(key_pem, password, certificates=()):
    if b'\0' in password:
        raise ValueError('PKCS#12 口令不能包含 NUL')
    api = lib(); key = _read(key_pem, True); certs = []; stack = None; p12 = None
    try:
        for der in certificates: certs.append(_decode(api.d2i_X509, der))
        stack = api.OPENSSL_sk_new_null()
        if not stack: raise ValueError('证书栈创建失败')
        for cert in certs[1:]:
            if api.OPENSSL_sk_push(stack, cert) <= 0: raise ValueError('证书栈写入失败')
        # AES-256-CBC NID = 427; independently strengthen encryption and MAC.
        p12 = api.PKCS12_create(password, b'key', key, certs[0] if certs else None, stack, 427, 427, 600000, 600000, 0)
        if not p12 or api.PKCS12_set_mac(p12, password, len(password), None, 16, 600000, api.EVP_sha256()) != 1:
            raise ValueError('PKCS#12 导出失败')
        size = api.i2d_PKCS12(p12, None)
        if not 0 < size <= 131072: raise ValueError('PKCS#12 输出过大')
        buf = C.create_string_buffer(size); cursor = C.c_void_p(C.addressof(buf))
        if api.i2d_PKCS12(p12, C.byref(cursor)) != size: raise ValueError('PKCS#12 输出失败')
        return buf.raw
    finally:
        if p12: api.PKCS12_free(p12)
        if stack: api.OPENSSL_sk_free(stack)
        for cert in certs: api.X509_free(cert)
        api.EVP_PKEY_free(key)
