"""PBES2 container encoding; all cryptographic operations use OpenSSL."""
import os
from asn1crypto import core, keys as ak
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HASHES = {'sha1': hashes.SHA1, 'sha224': hashes.SHA224, 'sha256': hashes.SHA256, 'sha384': hashes.SHA384, 'sha512': hashes.SHA512}
CIPHERS = {'aes128_cbc': 16, 'aes192_cbc': 24, 'aes256_cbc': 32}


def encrypt_pkcs8(clear_der, password):
    salt, iv = os.urandom(16), os.urandom(16)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000).derive(password)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(clear_der) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = cipher.update(padded) + cipher.finalize()
    return ak.EncryptedPrivateKeyInfo({
        'encryption_algorithm': {'algorithm': 'pbes2', 'parameters': {
            'key_derivation_func': {'algorithm': 'pbkdf2', 'parameters': {
                'salt': core.OctetString(salt), 'iteration_count': 600000, 'prf': {'algorithm': 'sha256'},
            }},
            'encryption_scheme': {'algorithm': 'aes256_cbc', 'parameters': iv},
        }},
        'encrypted_data': ciphertext,
    }).dump()


class ScryptParams(core.Sequence):
    _fields = [('salt', core.OctetString), ('cost', core.Integer), ('block_size', core.Integer), ('parallelism', core.Integer), ('key_length', core.Integer, {'optional': True})]


def decrypt_checked(info):
    """Validate work factors before entering any KDF or native parser."""
    from asn1crypto import algos
    algos.KdfAlgorithmId._map['1.3.6.1.4.1.11591.4.11'] = 'scrypt'
    algos.KdfAlgorithm._oid_specs['scrypt'] = ScryptParams
    algorithm = info['encryption_algorithm']
    kind = algorithm['algorithm'].native
    ciphertext = info['encrypted_data'].native
    if not ciphertext or len(ciphertext) > 131072:
        raise ValueError('加密容器长度异常')
    if kind != 'pbes2':
        allowed = {'pbes1_md5_des', 'pbes1_md5_rc2', 'pbes1_sha1_des', 'pbes1_sha1_rc2', 'pkcs12_sha1_tripledes_3key', 'pkcs12_sha1_tripledes_2key', 'pkcs12_sha1_rc2_128', 'pkcs12_sha1_rc2_40'}
        if kind not in allowed:
            raise ValueError('不支持该旧式加密算法')
        settings = algorithm['parameters'].native
        count, salt = settings['iterations'], settings['salt']
        if not isinstance(count, int) or not 1 <= count <= 2000000 or not isinstance(salt, bytes) or not 1 <= len(salt) <= 1024 or len(ciphertext) % 8:
            raise ValueError('旧式加密参数超出资源限制')
        if kind.startswith('pbes1_'):
            from Cryptodome.IO._PBES import PBES1
            return lambda password: PBES1.decrypt(info.dump(), password), count
        from .native_crypto import decrypt_legacy
        return lambda password: decrypt_legacy(algorithm.dump(), ciphertext, password), count
    params = algorithm['parameters']
    kdf = params['key_derivation_func']
    settings = kdf['parameters'].native
    scheme = params['encryption_scheme']
    cipher_name = scheme['algorithm'].native
    size = {'aes128_cbc': 16, 'aes192_cbc': 24, 'aes256_cbc': 32, 'tripledes_3key': 24}.get(cipher_name)
    block = 8 if cipher_name == 'tripledes_3key' else 16
    iv = scheme['parameters'].native
    salt = settings.get('salt')
    if not size or not isinstance(iv, bytes) or len(iv) != block or len(ciphertext) % block or not isinstance(salt, bytes) or not 1 <= len(salt) <= 1024 or settings.get('key_length') not in (None, size):
        raise ValueError('不支持此 PBES2 算法组合')
    if kdf['algorithm'].native == 'pbkdf2':
        count = settings['iteration_count']
        hash_cls = HASHES.get(settings['prf']['algorithm'])
        if not isinstance(count, int) or not 1 <= count <= 2000000 or hash_cls is None:
            raise ValueError('PBKDF2 参数超出资源限制')
        derive = lambda password: PBKDF2HMAC(algorithm=hash_cls(), length=size, salt=salt, iterations=count).derive(password)
    elif kdf['algorithm'].native == 'scrypt':
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        n, r, p = settings['cost'], settings['block_size'], settings['parallelism']
        if not all(isinstance(v, int) for v in (n, r, p)) or n < 2 or n & (n - 1) or not 1 <= r <= 32 or not 1 <= p <= 16 or 128 * n * r > 268435456 or n * r * p > 4194304:
            raise ValueError('scrypt 超出 256 MiB 内存或计算预算')
        count = max(1, n * r * p)
        derive = lambda password: Scrypt(salt=salt, length=size, n=n, r=r, p=p).derive(password)
    else:
        raise ValueError('不支持此密码派生函数')
    def decrypt(password):
        key = derive(password)
        if block == 8:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
            cipher_algorithm = TripleDES(key)
        else:
            cipher_algorithm = algorithms.AES(key)
        cipher = Cipher(cipher_algorithm, modes.CBC(iv)).decryptor()
        padded = cipher.update(ciphertext) + cipher.finalize()
        unpadder = padding.PKCS7(block * 8).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    return decrypt, count
