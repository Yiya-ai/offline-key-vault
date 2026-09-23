"""Key attachments are stored inside the vault's authenticated ciphertext."""
import base64
import re
from cryptography import x509
from cryptography.hazmat.primitives import serialization as S
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7


class Bundle:
    def __init__(self, key, attachments, alias=''):
        self.key, self.attachments, self.alias = key, attachments, alias
    def __getattr__(self, name): return getattr(self.key, name)


def cert_bundle(key, certs, alias=''):
    from .keys import fingerprint
    if not certs or len(certs) > 50: raise ValueError('证书集合必须有 1–50 张证书')
    matches = [c for c in certs if fingerprint(c.public_key()) == fingerprint(key)]
    if not matches: raise ValueError('证书集合没有与密钥匹配的证书')
    ordered = [matches[0]] + [c for c in certs if c != matches[0]]
    return Bundle(key, {'certificates': [base64.b64encode(c.public_bytes(S.Encoding.DER)).decode('ascii') for c in ordered]}, alias)


def validate(attachments, public):
    from .keys import fingerprint
    if not isinstance(attachments, dict) or set(attachments) - {'certificates', 'ssh_certificate'}: raise ValueError('附件类型无效')
    certs = attachments.get('certificates')
    if certs is not None:
        if not isinstance(certs, list) or not 1 <= len(certs) <= 50: raise ValueError('证书数量无效')
        decoded = [x509.load_der_x509_certificate(base64.b64decode(c, validate=True)) for c in certs]
        if fingerprint(decoded[0].public_key()) != fingerprint(public): raise ValueError('首张证书与密钥不匹配')
    cert = attachments.get('ssh_certificate')
    if cert is not None:
        if not isinstance(cert, str) or len(cert) > 131072: raise ValueError('SSH 证书无效')
        identity = S.load_ssh_public_identity(cert.encode('ascii'))
        if not isinstance(identity, S.SSHCertificate): raise ValueError('不是 SSH 证书')
        identity.verify_cert_signature()
        if fingerprint(identity.public_key()) != fingerprint(public): raise ValueError('SSH 证书与密钥不匹配')


def try_load(data, password=''):
    from .keys import import_key, fingerprint
    from .import_guard import check_der
    stripped = data.strip()
    if stripped.startswith((b'ssh-', b'ecdsa-')) and b'-cert-v01@openssh.com ' in stripped:
        identity = S.load_ssh_public_identity(stripped)
        identity.verify_cert_signature()
        return Bundle(identity.public_key(), {'ssh_certificate': identity.public_bytes().decode('ascii')})
    if stripped.startswith(b'-----BEGIN CERTIFICATE-----'):
        blocks = re.findall(rb'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----', stripped)
        if not blocks or re.sub(rb'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----', b'', stripped).strip(): raise ValueError('证书 PEM 包含额外内容')
        certs = [x509.load_pem_x509_certificate(b) for b in blocks]
        return cert_bundle(certs[0].public_key(), certs)
    if data.startswith(b'0'):
        try: cert = x509.load_der_x509_certificate(data)
        except ValueError: pass
        else: return cert_bundle(cert.public_key(), [cert])
        from asn1crypto import core
        seq = core.Sequence.load(data, strict=True)
        if len(seq) >= 2 and isinstance(seq[0], core.Integer) and seq[0].native == 3 and isinstance(seq[1], core.Sequence):
            check_der(data, password.encode('utf-8'))
            private, cert, extra = pkcs12.load_key_and_certificates(data, password.encode('utf-8') if password else None)
            certs = ([cert] if cert is not None else []) + list(extra)
            if private is None and not certs: raise ValueError('PKCS#12 没有密钥或证书')
            key = private or certs[0].public_key()
            return cert_bundle(key, certs) if certs else key
    return None


def import_items(data, password='', raw_kind=None, key_password=''):
    from .keys import import_key, MAX_KEY_BYTES
    if isinstance(data, str): data = data.strip().encode('utf-8')
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_KEY_BYTES: raise ValueError('文件为空或超过 128 KiB')
    if data.startswith(b'\xfe\xed\xfe\xed'):
        import jks
        if len(data) < 12 or int.from_bytes(data[8:12], 'big') > 50: raise ValueError('JKS 条目超过 50 个')
        store = jks.KeyStore.loads(data, password, try_decrypt_keys=False)
        items = []
        for alias, entry in store.entries.items():
            if isinstance(entry, jks.PrivateKeyEntry):
                entry.decrypt(key_password or password)
                key = import_key(entry.pkey_pkcs8)
                certs = [x509.load_der_x509_certificate(c) for kind, c in entry.cert_chain if kind == 'X.509']
                if len(certs) != len(entry.cert_chain): raise ValueError('JKS 证书类型不支持')
                items.append(cert_bundle(key, certs, alias))
            elif isinstance(entry, jks.TrustedCertEntry):
                cert = x509.load_der_x509_certificate(entry.cert)
                items.append(cert_bundle(cert.public_key(), [cert], alias))
            else: raise ValueError('JKS 条目类型不支持')
        if not items: raise ValueError('JKS 没有可导入条目')
        return items
    return [import_key(data, password, raw_kind)]


def export_attachment(record, fmt, key=None, password=''):
    attachments = record.get('attachments', {})
    certificates = [base64.b64decode(c, validate=True) for c in attachments.get('certificates', [])]
    certs = [x509.load_der_x509_certificate(c) for c in certificates]
    if fmt == 'SSH-Certificate':
        return (attachments['ssh_certificate'] + '\n').encode('ascii')
    if fmt == 'Certificate-PEM': return certs[0].public_bytes(S.Encoding.PEM)
    if fmt == 'Certificate-Chain': return b''.join(c.public_bytes(S.Encoding.PEM) for c in certs)
    if fmt == 'PKCS7': return pkcs7.serialize_certificates(certs, S.Encoding.DER)
    if fmt == 'PKCS12':
        from .native_crypto import export_p12
        return export_p12(key.private_bytes(S.Encoding.PEM, S.PrivateFormat.PKCS8, S.NoEncryption()), password.encode('utf-8'), certificates)
    if fmt == 'JKS':
        import jks
        if not certs: raise ValueError('JKS 导出需要匹配证书，请先导入证书或证书链')
        alias = record['name'].lower()
        if key is not None:
            entry = jks.PrivateKeyEntry.new(alias, certificates, key.private_bytes(S.Encoding.DER, S.PrivateFormat.PKCS8, S.NoEncryption()), 'pkcs8')
            entries = [entry]
        else:
            entries = [jks.TrustedCertEntry.new(alias + ('-' + str(i) if i else ''), c) for i, c in enumerate(certificates)]
        return jks.KeyStore.new('jks', entries).saves(password)
    raise ValueError('该记录没有对应附件')
