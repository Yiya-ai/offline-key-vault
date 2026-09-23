"""Standards-based JWK import/export using library key validation."""
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, x25519, x448
from cryptography.hazmat.primitives import serialization as S
from .keys import KeyError, algorithm, public_of

CURVES = {'P-256': ec.SECP256R1, 'P-384': ec.SECP384R1, 'P-521': ec.SECP521R1, 'secp256k1': ec.SECP256K1}
OKP = {'Ed25519': (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey), 'Ed448': (ed448.Ed448PrivateKey, ed448.Ed448PublicKey), 'X25519': (x25519.X25519PrivateKey, x25519.X25519PublicKey), 'X448': (x448.X448PrivateKey, x448.X448PublicKey)}


def enc(value):
    return base64.urlsafe_b64encode(value).decode('ascii').rstrip('=')


def dec(value):
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ValueError()
    out = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
    if enc(out) != value:
        raise ValueError()
    return out


def num(value):
    raw = dec(value)
    if len(raw) > 1 and raw[0] == 0:
        raise ValueError()
    return int.from_bytes(raw, 'big')


def integer(value):
    return enc(value.to_bytes((value.bit_length() + 7) // 8, 'big'))


def unique(pairs):
    result = {}
    for key, val in pairs:
        if key in result:
            raise ValueError()
        result[key] = val
    return result


def from_jwk(data):
    try:
        j = json.loads(data, object_pairs_hook=unique)
        if not isinstance(j, dict) or 'keys' in j or 'oth' in j:
            raise ValueError()
        # JWK metadata such as alg/use/kid is not retained as key policy.
        if j['kty'] == 'RSA':
            n, e = num(j['n']), num(j['e'])
            allowed = (2048, 3072, 4096) if any(field in j for field in ('d', 'p', 'q', 'dp', 'dq', 'qi')) else (1024, 2048, 3072, 4096)
            if n.bit_length() not in allowed or e != 65537:
                raise ValueError()
            if any(num(j[field]).bit_length() > 4096 for field in ('d', 'p', 'q', 'dp', 'dq', 'qi') if field in j):
                raise ValueError()
            pub = rsa.RSAPublicNumbers(e, n)
            if 'd' in j:
                key = rsa.RSAPrivateNumbers(num(j['p']), num(j['q']), num(j['d']), num(j['dp']), num(j['dq']), num(j['qi']), pub).private_key()
            else:
                if any(x in j for x in ('p', 'q', 'dp', 'dq', 'qi')):
                    raise ValueError()
                key = pub.public_key()
        elif j['kty'] == 'EC':
            curve = CURVES[j['crv']]()
            size = (curve.key_size + 7) // 8
            if any(len(dec(j[x])) != size for x in ('x', 'y')):
                raise ValueError()
            pub = ec.EllipticCurvePublicNumbers(int.from_bytes(dec(j['x']), 'big'), int.from_bytes(dec(j['y']), 'big'), curve)
            if 'd' in j:
                if len(dec(j['d'])) != size:
                    raise ValueError()
                key = ec.EllipticCurvePrivateNumbers(int.from_bytes(dec(j['d']), 'big'), pub).private_key()
            else:
                key = pub.public_key()
        elif j['kty'] == 'OKP':
            private_cls, public_cls = OKP[j['crv']]
            expected = public_cls.from_public_bytes(dec(j['x']))
            key = private_cls.from_private_bytes(dec(j['d'])) if 'd' in j else expected
            if public_of(key).public_bytes(S.Encoding.Raw, S.PublicFormat.Raw) != expected.public_bytes(S.Encoding.Raw, S.PublicFormat.Raw):
                raise ValueError()
        else:
            raise ValueError()
        algorithm(key)
        return key
    except Exception:
        raise KeyError('JWK 无效、算法不支持或公私钥不匹配；只支持单个非对称 JWK，不支持 JWKS 或对称密钥') from None


def to_jwk(key, private=False):
    pub = public_of(key)
    if isinstance(pub, rsa.RSAPublicKey):
        pn = pub.public_numbers()
        j = {'kty': 'RSA', 'n': integer(pn.n), 'e': integer(pn.e)}
        if private:
            v = key.private_numbers()
            j.update(d=integer(v.d), p=integer(v.p), q=integer(v.q), dp=integer(v.dmp1), dq=integer(v.dmq1), qi=integer(v.iqmp))
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pn = pub.public_numbers()
        crv = next(k for k, cls in CURVES.items() if cls().name == pub.curve.name)
        size = (pub.curve.key_size + 7) // 8
        j = {'kty': 'EC', 'crv': crv, 'x': enc(pn.x.to_bytes(size, 'big')), 'y': enc(pn.y.to_bytes(size, 'big'))}
        if private:
            j['d'] = enc(key.private_numbers().private_value.to_bytes(size, 'big'))
    else:
        j = {'kty': 'OKP', 'crv': algorithm(key), 'x': enc(pub.public_bytes(S.Encoding.Raw, S.PublicFormat.Raw))}
        if private:
            j['d'] = enc(key.private_bytes(S.Encoding.Raw, S.PrivateFormat.Raw, S.NoEncryption()))
    return (json.dumps(j, indent=2) + '\n').encode('ascii')
