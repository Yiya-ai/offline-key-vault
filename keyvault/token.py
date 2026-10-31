"""Generic PKCS#11 adapter. Importing this module never loads a driver."""
import hashlib
import os
from contextlib import contextmanager
from .safeio import local_path, opened_local
from cryptography.hazmat.primitives.asymmetric import rsa, ec


class PKCS11Token:
    def __init__(self, module, expected_sha256):
        path = local_path(module)
        # Windows denies writes/renames until LoadLibrary has opened this file.
        # POSIX descriptors do not enforce mandatory sharing; see SECURITY.md.
        with opened_local(path) as stream:
            data = stream.read(64 * 1024 * 1024 + 1)
            if len(data) > 64 * 1024 * 1024:
                raise ValueError('PKCS#11 驱动文件过大')
            actual = hashlib.sha256(data).hexdigest()
            if not isinstance(expected_sha256, str) or actual != expected_sha256.lower():
                raise ValueError('PKCS#11 驱动摘要不匹配')
            import PyKCS11
            self.api = PyKCS11
            self.library = PyKCS11.PyKCS11Lib()
            self.library.load(str(path))
        self.digest = actual

    def slots(self):
        result = []
        for slot in self.library.getSlotList(tokenPresent=True):
            info = self.library.getTokenInfo(slot)
            result.append({'slot': slot, 'label': info.label.strip(), 'serial': info.serialNumber.strip(), 'model': info.model.strip()})
        return result

    @contextmanager
    def _session(self, slot, pin, write=False):
        flags = self.api.CKF_SERIAL_SESSION | (self.api.CKF_RW_SESSION if write else 0)
        handle = self.library.openSession(slot, flags)
        logged_in = False
        try:
            if pin:
                handle.login(pin); logged_in = True
            yield handle
        finally:
            try:
                if logged_in: handle.logout()
            finally: handle.closeSession()

    def public_keys(self, slot, pin=''):
        from asn1crypto import core
        api = self.api; result = []
        with self._session(slot, pin) as session:
            objects = session.findObjects([(api.CKA_CLASS, api.CKO_PUBLIC_KEY)])
            if len(objects) > 1000: raise ValueError('令牌对象过多')
            for obj in objects:
                kind, ident, label = session.getAttributeValue(obj, [api.CKA_KEY_TYPE, api.CKA_ID, api.CKA_LABEL])
                if kind == api.CKK_RSA:
                    n, e = session.getAttributeValue(obj, [api.CKA_MODULUS, api.CKA_PUBLIC_EXPONENT])
                    public = rsa.RSAPublicNumbers(int.from_bytes(bytes(e), 'big'), int.from_bytes(bytes(n), 'big')).public_key()
                elif kind == api.CKK_EC:
                    params, point = session.getAttributeValue(obj, [api.CKA_EC_PARAMS, api.CKA_EC_POINT])
                    oid = core.ObjectIdentifier.load(bytes(params), strict=True).native
                    curve = {'1.2.840.10045.3.1.7': ec.SECP256R1, '1.3.132.0.34': ec.SECP384R1, '1.3.132.0.35': ec.SECP521R1}.get(oid)
                    if curve is None: continue
                    public = ec.EllipticCurvePublicKey.from_encoded_point(curve(), core.OctetString.load(bytes(point), strict=True).native)
                else: continue
                from .keys import algorithm
                algorithm(public)
                result.append({'id': bytes(ident).hex(), 'label': str(label), 'public': public})
        return result

    def generate_rsa(self, slot, pin, label, bits=3072):
        if bits not in (2048, 3072, 4096) or not label or len(label) > 120: raise ValueError('令牌密钥参数无效')
        api = self.api; ident = os.urandom(20)
        with self._session(slot, pin, write=True) as session:
            public = [(api.CKA_TOKEN, True), (api.CKA_LABEL, label), (api.CKA_ID, tuple(ident)), (api.CKA_VERIFY, True), (api.CKA_MODULUS_BITS, bits), (api.CKA_PUBLIC_EXPONENT, (1, 0, 1))]
            private = [(api.CKA_TOKEN, True), (api.CKA_PRIVATE, True), (api.CKA_SENSITIVE, True), (api.CKA_EXTRACTABLE, False), (api.CKA_LABEL, label), (api.CKA_ID, tuple(ident)), (api.CKA_SIGN, True)]
            pub, priv = session.generateKeyPair(public, private, api.Mechanism(api.CKM_RSA_PKCS_KEY_PAIR_GEN, None))
            sensitive, extractable = session.getAttributeValue(priv, [api.CKA_SENSITIVE, api.CKA_EXTRACTABLE])
            if not sensitive or extractable: raise ValueError('设备未遵守不可导出策略；请在厂商工具中检查新对象')
        return ident.hex()

    def sign_rsa_sha256(self, slot, pin, key_id, data):
        if not isinstance(data, bytes) or len(data) > 131072: raise ValueError('待签名数据超过限制')
        ident = bytes.fromhex(key_id)
        if not 1 <= len(ident) <= 128: raise ValueError('令牌密钥 ID 无效')
        api = self.api
        with self._session(slot, pin) as session:
            objects = session.findObjects([(api.CKA_CLASS, api.CKO_PRIVATE_KEY), (api.CKA_ID, tuple(ident)), (api.CKA_KEY_TYPE, api.CKK_RSA)])
            if len(objects) != 1: raise ValueError('未找到唯一 RSA 私钥')
            return bytes(session.sign(objects[0], data, api.Mechanism(api.CKM_SHA256_RSA_PKCS, None)))
