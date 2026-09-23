"""Version 2 local protection. Counters are not rollback-resistant hardware state."""
import base64
import copy
import hashlib
import hmac
import json
import os
import uuid
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from . import keys
from .safeio import FileLock, atomic_replace, local_path, read_limited, write_new

LIMIT = 16 * 1024 * 1024
KDF = 'scrypt-131072-8-1'
DESTROY_CONFIRMATION = '永久销毁当前库'


class VaultError(ValueError):
    pass


class AuthenticationError(VaultError):
    pass


class VaultDestroyed(VaultError):
    pass


def wipe(value):
    if value is not None:
        value[:] = b'\0' * len(value)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('duplicate field')
        result[name] = value
    return result


def b64(value):
    return base64.b64encode(value).decode('ascii')


def decode(value, length=None):
    if not isinstance(value, str):
        raise ValueError()
    raw = base64.b64decode(value, validate=True)
    if length is not None and len(raw) != length:
        raise ValueError()
    if b64(raw) != value:
        raise ValueError()
    return raw


def derive(password, salt, factor=None):
    password_bytes = keys.password_bytes(password)
    if not password.strip():
        raise VaultError('请输入口令；空输入未消耗密码尝试次数')
    # HMAC combines a 256-bit independent possession factor with the knowledge factor.
    material = password_bytes if factor is None else hmac.digest(factor, b'OKV2/recovery\0' + password_bytes, 'sha256')
    return bytearray(Scrypt(salt=salt, length=32, n=131072, r=8, p=1).derive(material))


def wrap(dek, password, vault_id, purpose, factor=None):
    salt, nonce = os.urandom(16), os.urandom(12)
    kek = derive(password, salt, factor)
    try:
        data = AESGCM(bytes(kek)).encrypt(nonce, bytes(dek), ('OKV2/' + vault_id + '/' + purpose).encode('ascii'))
        return {'kdf': KDF, 'salt': b64(salt), 'nonce': b64(nonce), 'data': b64(data)}
    finally:
        wipe(kek)


def unwrap(doc, password, purpose, factor=None):
    slot = doc[purpose]
    kek = derive(password, decode(slot['salt'], 16), factor)
    try:
        return bytearray(AESGCM(bytes(kek)).decrypt(decode(slot['nonce'], 12), decode(slot['data'], 48), ('OKV2/' + doc['id'] + '/' + purpose).encode('ascii')))
    finally:
        wipe(kek)


def aad(doc):
    # Authenticate policy and credential slots with the encrypted payload.
    return b'OKV2/payload\0' + canonical({k: v for k, v in doc.items() if k not in {'checksum', 'failures', 'nonce', 'data'}})


def pack(doc):
    value = {k: v for k, v in doc.items() if k != 'checksum'}
    value['checksum'] = hashlib.sha256(canonical(value)).hexdigest()
    raw = canonical(value)
    if len(raw) > LIMIT:
        raise VaultError('密钥库达到 16 MiB 大小限制')
    return raw


def seal(doc, records, dek):
    result = copy.deepcopy(doc)
    nonce = os.urandom(12)
    result['nonce'] = b64(nonce)
    result['data'] = b64(AESGCM(bytes(dek)).encrypt(nonce, canonical({'records': records}), aad(result)))
    return result


def parse(raw):
    try:
        if len(raw) > LIMIT:
            raise ValueError()
        doc = json.loads(raw, object_pairs_hook=unique)
        if not isinstance(doc, dict):
            raise ValueError()
        if doc.get('format') == 'OKV-DESTROYED':
            raise VaultDestroyed('当前密钥库已触发永久销毁，主口令和恢复凭据均已失效。历史备份不受影响。')
        if set(doc) != {'format', 'id', 'master', 'recovery', 'max_failures', 'failures', 'nonce', 'data', 'checksum'} or doc['format'] != 'OKV2':
            raise ValueError()
        if str(uuid.UUID(doc['id'])) != doc['id']:
            raise ValueError()
        maximum = doc['max_failures']
        if type(maximum) is not int or (maximum != 0 and not 5 <= maximum <= 100):
            raise ValueError()
        if type(doc['failures']) is not int or not 0 <= doc['failures'] < (maximum or 1):
            raise ValueError()
        for purpose in ('master', 'recovery'):
            slot = doc[purpose]
            if purpose == 'recovery' and slot is None:
                continue
            if not isinstance(slot, dict) or set(slot) != {'kdf', 'salt', 'nonce', 'data'} or slot['kdf'] != KDF:
                raise ValueError()
            decode(slot['salt'], 16); decode(slot['nonce'], 12); decode(slot['data'], 48)
        decode(doc['nonce'], 12)
        if len(decode(doc['data'])) < 16:
            raise ValueError()
        expected = hashlib.sha256(canonical({k: v for k, v in doc.items() if k != 'checksum'})).hexdigest()
        if not isinstance(doc['checksum'], str) or not hmac.compare_digest(doc['checksum'], expected):
            raise ValueError()
        return doc
    except VaultDestroyed:
        raise
    except Exception:
        raise VaultError('密钥库格式或完整性检查失败；未消耗密码尝试次数') from None


def is_protected(raw):
    try:
        doc = json.loads(raw, object_pairs_hook=unique)
        return isinstance(doc, dict) and doc.get('format') in ('OKV2', 'OKV-DESTROYED')
    except (ValueError, TypeError):
        return False


def payload(doc, dek):
    from .vault import _validate_records
    try:
        value = json.loads(AESGCM(bytes(dek)).decrypt(decode(doc['nonce'], 12), decode(doc['data']), aad(doc)), object_pairs_hook=unique)
        if not isinstance(value, dict) or set(value) != {'records'}:
            raise ValueError()
        _validate_records(value['records'])
        return value['records']
    except Exception:
        raise VaultError('口令已通过，但加密内容或策略校验失败；未消耗密码尝试次数') from None


def save(path, doc, digest):
    raw = pack(doc)
    atomic_replace(path, raw, expected_digest=digest)
    return hashlib.sha256(raw).digest()


def failed(path, doc, digest):
    maximum = doc['max_failures']
    if not maximum:
        raise AuthenticationError('凭据校验失败；自毁未启用')
    changed = copy.deepcopy(doc)
    changed['failures'] += 1
    if changed['failures'] >= maximum:
        # Atomic replacement removes the entire ciphertext and BOTH key slots.
        # This is logical destruction of this file, not secure erasure of SSD history.
        raw = canonical({'format': 'OKV-DESTROYED', 'id': doc['id']})
        atomic_replace(path, raw, expected_digest=digest)
        raise VaultDestroyed('已达到失败次数上限，当前密钥库已永久销毁，恢复凭据也已失效。历史备份不受影响。')
    new_digest = save(path, changed, digest)
    return changed, new_digest


def recovery_factor(path, vault_id):
    try:
        doc = json.loads(read_limited(path, 4096), object_pairs_hook=unique)
        if set(doc) != {'format', 'id', 'secret'} or doc['format'] != 'OKV-RECOVERY1' or doc['id'] != vault_id:
            raise ValueError()
        return bytearray(decode(doc['secret'], 32))
    except (ValueError, TypeError, KeyError):
        raise VaultError('恢复文件格式错误或不属于当前库；未消耗密码尝试次数') from None


class ProtectedVault:
    def security_status(self):
        self._require()
        doc = self._protected
        return {'max_failures': doc['max_failures'] if doc else 0,
                'failures': doc['failures'] if doc else 0, 'recovery': bool(doc and doc['recovery'])}

    @staticmethod
    def inspect_security(path):
        raw = read_limited(path, LIMIT)
        if not is_protected(raw):
            from .vault import _envelope
            _envelope(raw)
            return {'max_failures': 0, 'failures': 0, 'recovery': False}
        doc = parse(raw)
        return {'max_failures': doc['max_failures'], 'failures': doc['failures'], 'recovery': doc['recovery'] is not None}

    def _open_protected(self, path, raw, lock, password):
        doc, dek = parse(raw), None
        digest = hashlib.sha256(raw).digest()
        try:
            try:
                dek = unwrap(doc, password, 'master')
            except InvalidTag:
                updated, _ = failed(path, doc, digest)
                raise AuthenticationError(f"凭据校验失败；再失败 {updated['max_failures'] - updated['failures']} 次将永久销毁当前库") from None
            records = payload(doc, dek)
            if doc['failures']:
                doc['failures'] = 0
                digest = save(path, doc, digest)
            self.path, self._lock, self._key = path, lock, dek
            self._protected, self._digest, self._records = doc, digest, records
            dek = None
        finally:
            wipe(dek)

    def _verify_protected(self, password):
        self._check_current()
        candidate = None
        try:
            try:
                candidate = unwrap(self._protected, password, 'master')
            except InvalidTag:
                try:
                    self._protected, self._digest = failed(self.path, self._protected, self._digest)
                except AuthenticationError:
                    raise
                except BaseException:
                    self.close()
                    raise
                remaining = self._protected['max_failures'] - self._protected['failures']
                raise AuthenticationError(f'凭据校验失败；再失败 {remaining} 次将永久销毁当前库') from None
            if not hmac.compare_digest(candidate, self._key):
                self.close()
                raise VaultError('解密密钥不一致，未执行操作')
            if self._protected['failures']:
                doc = copy.deepcopy(self._protected)
                doc['failures'] = 0
                try:
                    digest = save(self.path, doc, self._digest)
                except BaseException:
                    self.close()
                    raise
                self._protected, self._digest = doc, digest
        finally:
            wipe(candidate)

    def _commit_protected(self, records, doc=None):
        self._check_current()
        updated = seal(self._protected if doc is None else doc, records, self._key)
        digest = save(self.path, updated, self._digest)
        self._protected, self._digest, self._records = updated, digest, records

    def configure_security(self, password, max_failures=0, *, recovery_password=None,
                           recovery_path=None, remove_recovery=False, confirmation=''):
        self._require()
        if type(max_failures) is not int or (max_failures != 0 and not 5 <= max_failures <= 100):
            raise VaultError('自毁阈值必须是 5 到 100 的整数；0 表示关闭')
        if max_failures and confirmation != DESTROY_CONFIRMATION:
            raise VaultError('启用自毁必须明确确认永久销毁当前库')
        if (recovery_password is None) != (recovery_path is None) or (remove_recovery and recovery_path is not None):
            raise VaultError('恢复设置参数不完整')
        if recovery_password is not None:
            keys.password_bytes(recovery_password, new=True)
            if recovery_password == password:
                raise VaultError('恢复口令必须与主口令不同，并分开保存')
            recovery_path = local_path(recovery_path)
            if recovery_path.exists() or recovery_path == self.path:
                raise VaultError('恢复文件必须保存到新的独立文件，不覆盖已有文件')
        self.verify(password)
        self._check_current()
        dek, factor = None, None
        try:
            if self._protected:
                doc = copy.deepcopy(self._protected)
                dek = bytearray(self._key)
            else:
                dek = bytearray(os.urandom(32))
                vault_id = str(uuid.uuid4())
                doc = {'format': 'OKV2', 'id': vault_id, 'master': wrap(dek, password, vault_id, 'master'),
                       'recovery': None, 'max_failures': 0, 'failures': 0}
            doc['max_failures'], doc['failures'] = max_failures, 0
            if remove_recovery:
                doc['recovery'] = None
            if recovery_password is not None:
                factor = bytearray(os.urandom(32))
                doc['recovery'] = wrap(dek, recovery_password, doc['id'], 'recovery', factor)
                file_bytes = canonical({'format': 'OKV-RECOVERY1', 'id': doc['id'], 'secret': b64(factor)})
                write_new(recovery_path, file_bytes)
                # Verify the stored possession factor before enabling recovery.
                stored = recovery_factor(recovery_path, doc['id'])
                try:
                    if not hmac.compare_digest(stored, factor):
                        raise VaultError('恢复文件写入校验失败，设置未保存')
                finally:
                    wipe(stored)
            updated = seal(doc, self._records, dek)
            digest = save(self.path, updated, self._digest)
            wipe(self._key)
            self._key, dek = dek, None
            self._salt = None
            self._protected, self._digest = updated, digest
        finally:
            wipe(dek); wipe(factor)

    def _change_protected_password(self, new):
        doc = copy.deepcopy(self._protected)
        doc['master'] = wrap(self._key, new, doc['id'], 'master')
        self._commit_protected(copy.deepcopy(self._records), doc)

    def recover(self, path, recovery_password, recovery_path, new_password):
        keys.password_bytes(new_password, new=True)
        keys.password_bytes(recovery_password)
        if new_password == recovery_password:
            raise VaultError('新主口令必须与恢复口令不同')
        self.close()
        path = local_path(path)
        lock, dek, factor = FileLock(path), None, None
        try:
            raw = read_limited(path, LIMIT)
            if not is_protected(raw):
                raise VaultError('此库未配置双因素恢复；无法找回原口令')
            doc = parse(raw)
            if doc['recovery'] is None:
                raise VaultError('此库未配置双因素恢复')
            digest = hashlib.sha256(raw).digest()
            factor = recovery_factor(recovery_path, doc['id'])
            try:
                dek = unwrap(doc, recovery_password, 'recovery', factor)
            except InvalidTag:
                updated, _ = failed(path, doc, digest)
                raise AuthenticationError(f"恢复凭据校验失败；再失败 {updated['max_failures'] - updated['failures']} 次将永久销毁当前库") from None
            records = payload(doc, dek)
            doc['master'] = wrap(dek, new_password, doc['id'], 'master')
            doc['failures'] = 0
            doc = seal(doc, records, dek)
            digest = save(path, doc, digest)
            self.path, self._lock, self._key = path, lock, dek
            self._protected, self._digest, self._records = doc, digest, records
            lock, dek = None, None
        finally:
            wipe(dek); wipe(factor)
            if lock is not None:
                lock.close()
