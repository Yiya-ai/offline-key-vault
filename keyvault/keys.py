"""Key generation and format conversion using cryptography/OpenSSL."""
import base64
import hashlib
import re
import textwrap
from .pbes2 import encrypt_pkcs8
from .import_guard import check_der, check_ssh
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization as S
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, x25519, x448

MAX_KEY_BYTES = 128 * 1024
ALGORITHMS = ('SM2', 'OpenPGP-RSA3072', 'Ed25519', 'RSA-3072', 'RSA-4096', 'RSA-2048', 'ECDSA-P256', 'ECDSA-P384', 'ECDSA-P521', 'ECDSA-secp256k1', 'Ed448', 'X25519', 'X448')
CURVES = {'ECDSA-P256': ec.SECP256R1, 'ECDSA-P384': ec.SECP384R1, 'ECDSA-P521': ec.SECP521R1, 'ECDSA-secp256k1': ec.SECP256K1}


class KeyError(ValueError):
    pass


def password_bytes(password, new=False):
    if not isinstance(password, str) or len(password.encode('utf-8')) > 1024:
        raise KeyError('口令过长（最多 1024 UTF-8 字节）')
    if new and (len(password) < 12 or not password.strip()):
        raise KeyError('口令至少 12 个字符，建议使用多个随机词组成的长口令')
    return password.encode('utf-8')


def public_of(key):
    from .material import Bundle
    if isinstance(key, Bundle): key = key.key
    return key.public_key() if hasattr(key, 'private_bytes') else key


def algorithm(key):
    from .native_crypto import SM2Public
    from .openpgp import PGPPublic
    pub = public_of(key)
    if isinstance(pub, SM2Public): return 'SM2'
    if isinstance(pub, PGPPublic): return 'OpenPGP-RSA3072' if pub.key.key_algorithm.name == 'RSAEncryptOrSign' and pub.key.key_size == 3072 else 'OpenPGP-' + pub.key.key_algorithm.name + '-' + str(pub.key.key_size)
    if isinstance(pub, rsa.RSAPublicKey):
        allowed = (1024, 2048, 3072, 4096) if not hasattr(key, 'private_bytes') else (2048, 3072, 4096)
        if pub.key_size not in allowed:
            raise KeyError('RSA 私钥至少 2048 位；1024 位仅允许旧公钥的兼容导入与转换')
        if pub.public_numbers().e != 65537:
            raise KeyError('RSA 公钥指数必须为 65537')
        return 'RSA-' + str(pub.key_size)
    if isinstance(pub, ec.EllipticCurvePublicKey):
        for name, curve in CURVES.items():
            if pub.curve.name == curve().name:
                return name
        raise KeyError('不支持该椭圆曲线')
    for cls, name in ((ed25519.Ed25519PublicKey, 'Ed25519'), (ed448.Ed448PublicKey, 'Ed448'), (x25519.X25519PublicKey, 'X25519'), (x448.X448PublicKey, 'X448')):
        if isinstance(pub, cls):
            if name in ('X25519', 'X448'):
                # Reject low-order points using the library's null-secret check.
                probe = x25519.X25519PrivateKey.generate() if name == 'X25519' else x448.X448PrivateKey.generate()
                try:
                    probe.exchange(pub)
                except ValueError:
                    raise KeyError('无效的低阶密钥交换公钥') from None
            return name
    raise KeyError('不支持该密钥算法；已拒绝 DSA 和未知算法')


def generate(name, identity='Local OpenPGP key'):
    if name not in ALGORITHMS:
        raise KeyError('未知算法')
    if name == 'SM2':
        from .native_crypto import generate_sm2
        return generate_sm2()
    if name == 'OpenPGP-RSA3072':
        from .openpgp import generate as generate_pgp
        return generate_pgp(identity)
    if name.startswith('RSA-'):
        return rsa.generate_private_key(public_exponent=65537, key_size=int(name[4:]))
    if name in CURVES:
        return ec.generate_private_key(CURVES[name]())
    return {'Ed25519': ed25519.Ed25519PrivateKey, 'Ed448': ed448.Ed448PrivateKey, 'X25519': x25519.X25519PrivateKey, 'X448': x448.X448PrivateKey}[name].generate()


def fingerprint(key):
    from .openpgp import PGPPublic
    pub = public_of(key)
    if isinstance(pub, PGPPublic): return 'OpenPGP:' + str(pub.key.fingerprint)
    der = public_of(key).public_bytes(S.Encoding.DER, S.PublicFormat.SubjectPublicKeyInfo)
    return 'SHA256:' + base64.b64encode(hashlib.sha256(der).digest()).decode().rstrip('=')


def normalized(key):
    algorithm(key)
    pub = public_of(key).public_bytes(S.Encoding.PEM, S.PublicFormat.SubjectPublicKeyInfo).decode('ascii')
    private = key.private_bytes(S.Encoding.PEM, S.PrivateFormat.PKCS8, S.NoEncryption()).decode('ascii') if hasattr(key, 'private_bytes') else None
    return pub, private


def _one_der(data):
    if len(data) < 2 or data[0] != 0x30:
        raise ValueError()
    n = data[1]
    offset = 2
    if n & 0x80:
        size = n & 0x7f
        if size == 0 or size > 4 or len(data) < 2 + size:
            raise ValueError()
        n = int.from_bytes(data[2:2 + size], 'big')
        offset += size
    if offset + n != len(data):
        raise ValueError()


def _base64_der(data):
    """Decode a single canonical base64 DER object, allowing ASCII wrapping."""
    token = re.sub(rb'[ \t\r\n]+', b'', data)
    if not token or not re.fullmatch(rb'[A-Za-z0-9+/]+={0,2}', token):
        return None
    try:
        decoded = base64.b64decode(token + b'=' * (-len(token) % 4), validate=True)
        canonical = base64.b64encode(decoded)
        if token not in (canonical, canonical.rstrip(b'=')):
            return None
        _one_der(decoded)
        return decoded
    except (ValueError, TypeError):
        return None


def compatibility_notice(key):
    if isinstance(key, rsa.RSAPublicKey) and key.key_size == 1024:
        return 'RSA-1024 旧公钥 · 仅供已有系统兼容，不建议用于新的加密或签名方案'
    return ''


def convert_public_text(data, fmt='PEM'):
    key = import_key(data)
    if hasattr(key, 'private_bytes'):
        raise KeyError('此入口只转换公钥。私钥请通过“导入密钥”安全入库。')
    return export_public(key, fmt)


def import_key(data, password='', raw_kind=None):
    if isinstance(data, str):
        if len(data) > MAX_KEY_BYTES:
            raise KeyError('密钥文本超过 128 KiB 限制')
        data = data.strip().encode('utf-8')
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_KEY_BYTES:
        raise KeyError('密钥为空或超过 128 KiB 限制')
    if data.startswith(b'\xef\xbb\xbf') and data[3:].lstrip().startswith((b'-----BEGIN ', b'{', b'ssh-', b'ecdsa-', b'PuTTY-User-Key-File-')):
        data = data[3:]
    if raw_kind:
        if data.strip().startswith((b'-----BEGIN ', b'{', b'ssh-', b'ecdsa-')) or _base64_der(data) is not None:
            raise KeyError('检测到带结构的密钥，不是 X25519 原始 32 字节数据。请选择“自动识别”后重试。')
        if raw_kind not in ('X25519-public', 'X25519-private'):
            raise KeyError('未知原始密钥类型')
        try:
            token = data.strip()
            if not re.fullmatch(rb'[A-Za-z0-9_+/\-]{43}=?', token):
                raise ValueError()
            if (b'+' in token or b'/' in token) and (b'-' in token or b'_' in token):
                raise ValueError()
            decoded = base64.b64decode(token.rstrip(b'=') + b'=', altchars=b'-_', validate=True)
            if base64.urlsafe_b64encode(decoded).rstrip(b'=') != token.rstrip(b'=').replace(b'+', b'-').replace(b'/', b'_'):
                raise ValueError()
            if len(decoded) != 32:
                raise ValueError()
            cls = x25519.X25519PrivateKey if raw_kind.endswith('private') else x25519.X25519PublicKey
            key = cls.from_private_bytes(decoded) if raw_kind.endswith('private') else cls.from_public_bytes(decoded)
            algorithm(key)
            return key
        except (ValueError, TypeError):
            raise KeyError('X25519 原始密钥必须为 32 字节 base64 / base64url') from None
    try:
        pw = password_bytes(password) if password else None
        from .compat_import import load as load_special
        special_data = _base64_der(data) if not data.startswith(b'0') else None
        special = load_special(special_data or data, password)
        if special is not None:
            algorithm(special)
            return special
        stripped = data.strip()
        if stripped.startswith(b'{'):
            from .jwk import from_jwk
            return from_jwk(stripped)
        if stripped.startswith(b'-----BEGIN '):
            match = re.fullmatch(rb'-----BEGIN ([A-Z0-9 ]+)-----\s+[A-Za-z0-9+/=\r\n]+-----END \1-----', stripped)
            if not match:
                raise ValueError()
            label = match.group(1)
            if label == b'OPENSSH PRIVATE KEY':
                check_ssh(stripped)
                key = S.load_ssh_private_key(stripped, pw)
            elif label in (b'PRIVATE KEY', b'ENCRYPTED PRIVATE KEY', b'RSA PRIVATE KEY', b'EC PRIVATE KEY'):
                check_der(base64.b64decode(b''.join(stripped.splitlines()[1:-1]), validate=True), pw or b'')
                key = S.load_pem_private_key(stripped, pw)
            elif label == b'CERTIFICATE':
                key = x509.load_pem_x509_certificate(stripped).public_key()
            elif label in (b'PUBLIC KEY', b'RSA PUBLIC KEY'):
                key = S.load_pem_public_key(stripped)
            else:
                raise ValueError()
        elif stripped.startswith((b'ssh-', b'ecdsa-')):
            if b'\n' in stripped or b'\r' in stripped:
                raise ValueError()
            key = S.load_ssh_public_key(stripped)
        else:
            if not data.startswith(b'0'):
                decoded = _base64_der(data)
                if decoded is not None:
                    data = decoded
            _one_der(data)
            check_der(data, pw or b'')
            try:
                key = S.load_der_private_key(data, pw)
            except (ValueError, TypeError):
                try:
                    key = S.load_der_public_key(data)
                except (ValueError, TypeError):
                    try:
                        key = x509.load_der_x509_certificate(data).public_key()
                    except ValueError:
                        private, cert, extra = pkcs12.load_key_and_certificates(data, pw)
                        # Certificates and chain metadata are deliberately not retained.
                        if private is not None:
                            key = private
                        else:
                            certs = ([cert] if cert is not None else []) + list(extra)
                            if len(certs) != 1:
                                raise KeyError('仅证书 PFX 必须包含且只包含一张证书')
                            key = certs[0].public_key()
                        if private is not None and cert is not None and fingerprint(private) != fingerprint(cert.public_key()):
                            raise KeyError('PKCS#12 的证书与私钥不匹配')
        algorithm(key)
        return key
    except KeyError:
        raise
    except Exception:
        raise KeyError('无法读取密钥：格式不支持、内容损坏或解密口令错误。请只输入一把密钥。') from None


def export_public(key, fmt):
    from .openpgp import PGPPublic
    if isinstance(public_of(key), PGPPublic) and fmt not in ('OpenPGP', 'OpenPGP-Binary'):
        raise KeyError('OpenPGP 身份与子密钥必须使用 OpenPGP 格式导出')
    algorithm(key)
    pub = public_of(key)
    try:
        if fmt in ('OpenPGP', 'OpenPGP-Binary'):
            from .openpgp import export as export_pgp
            return export_pgp(pub, binary=fmt.endswith('Binary'))
        if fmt == 'JWK':
            from .jwk import to_jwk
            return to_jwk(pub)
        if fmt in ('PKCS1-PEM', 'PKCS1-DER') and isinstance(pub, rsa.RSAPublicKey):
            return pub.public_bytes(S.Encoding.PEM if fmt.endswith('PEM') else S.Encoding.DER, S.PublicFormat.PKCS1)
        if fmt == 'PEM':
            return pub.public_bytes(S.Encoding.PEM, S.PublicFormat.SubjectPublicKeyInfo)
        if fmt == 'DER':
            return pub.public_bytes(S.Encoding.DER, S.PublicFormat.SubjectPublicKeyInfo)
        if fmt == 'OpenSSH':
            return pub.public_bytes(S.Encoding.OpenSSH, S.PublicFormat.OpenSSH) + b'\n'
        if fmt in ('Raw-base64', 'Raw-base64url') and isinstance(pub, x25519.X25519PublicKey):
            raw = pub.public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)
            return (base64.urlsafe_b64encode(raw).rstrip(b'=') if fmt.endswith('url') else base64.b64encode(raw)) + b'\n'
    except (ValueError, TypeError):
        pass
    raise KeyError('此算法不支持所选公钥格式')


def export_private(key, fmt, password='', plaintext=False):
    from .material import Bundle
    if isinstance(key, Bundle): key = key.key
    from .openpgp import PGPPublic
    if isinstance(public_of(key), PGPPublic) and fmt not in ('OpenPGP', 'OpenPGP-Binary'):
        raise KeyError('OpenPGP 身份与子密钥必须使用 OpenPGP 格式导出')
    algorithm(key)
    if not hasattr(key, 'private_bytes'):
        raise KeyError('此记录只有公钥，无法导出私钥')
    encryption = S.NoEncryption() if plaintext else S.BestAvailableEncryption(password_bytes(password, new=True))
    try:
        if fmt == 'JWK':
            if not plaintext:
                raise KeyError('JWK 私钥没有口令保护，请选择加密 PKCS#8 或显式允许明文')
            from .jwk import to_jwk
            return to_jwk(key, private=True)
        if fmt in ('OpenPGP', 'OpenPGP-Binary'):
            from .openpgp import export as export_pgp
            return export_pgp(key, private=True, password='' if plaintext else password, binary=fmt.endswith('Binary'))
        if fmt in ('PPK-v3', 'PPK-v2'):
            from .ppk import dump
            return dump(key, b'' if plaintext else password_bytes(password, new=True), 3 if fmt.endswith('3') else 2)
        if fmt == 'PKCS12':
            if plaintext: raise KeyError('PKCS#12 导出必须设置口令')
            from .native_crypto import export_p12
            return export_p12(key.private_bytes(S.Encoding.PEM, S.PrivateFormat.PKCS8, S.NoEncryption()), password_bytes(password, new=True))
        if fmt in ('PKCS1-PEM', 'PKCS1-DER', 'SEC1-PEM', 'SEC1-DER'):
            if not plaintext:
                raise KeyError('传统私钥导出只支持显式明文；加密请使用 PKCS#8 PEM / DER')
            if (fmt.startswith('PKCS1') and isinstance(key, rsa.RSAPrivateKey)) or (fmt.startswith('SEC1') and isinstance(key, ec.EllipticCurvePrivateKey)):
                return key.private_bytes(S.Encoding.PEM if fmt.endswith('PEM') else S.Encoding.DER, S.PrivateFormat.TraditionalOpenSSL, encryption)
            raise KeyError('PKCS#1 仅适用 RSA；SEC1 仅适用 ECDSA')
        if fmt in ('PEM', 'DER') and not plaintext:
            clear = key.private_bytes(S.Encoding.DER, S.PrivateFormat.PKCS8, S.NoEncryption())
            der = encrypt_pkcs8(clear, password_bytes(password, new=True))
            if fmt == 'DER':
                return der
            return ('-----BEGIN ENCRYPTED PRIVATE KEY-----\n' + '\n'.join(textwrap.wrap(base64.b64encode(der).decode('ascii'), 64)) + '\n-----END ENCRYPTED PRIVATE KEY-----\n').encode('ascii')
        if fmt in ('PEM', 'DER'):
            return key.private_bytes(S.Encoding.PEM if fmt == 'PEM' else S.Encoding.DER, S.PrivateFormat.PKCS8, encryption)
        if fmt == 'OpenSSH':
            if not plaintext:
                encryption = S.PrivateFormat.OpenSSH.encryption_builder().kdf_rounds(100).build(password_bytes(password, new=True))
            return key.private_bytes(S.Encoding.PEM, S.PrivateFormat.OpenSSH, encryption)
        if fmt in ('Raw-base64', 'Raw-base64url') and isinstance(key, x25519.X25519PrivateKey):
            if not plaintext:
                raise KeyError('原始私钥格式无法加密，必须显式允许明文导出')
            raw = key.private_bytes(S.Encoding.Raw, S.PrivateFormat.Raw, S.NoEncryption())
            return (base64.urlsafe_b64encode(raw).rstrip(b'=') if fmt.endswith('url') else base64.b64encode(raw)) + b'\n'
    except KeyError:
        raise
    except (ValueError, TypeError):
        pass
    raise KeyError('此算法不支持所选私钥格式')
