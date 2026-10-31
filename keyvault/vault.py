"""Authenticated encrypted vault; metadata never appears outside ciphertext."""
import base64
import copy
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from . import keys
from .protection import ProtectedVault, VaultError, AuthenticationError, VaultDestroyed, is_protected
from .safeio import FileLock, atomic_replace, local_path, read_limited, write_new

LIMIT = 16 * 1024 * 1024
MAX_RECORDS = 1000
AAD = b'OfflineKeyVault/v1;scrypt:N=131072,r=8,p=1;AES-256-GCM'


def _json(data):
    return json.dumps(data, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def _b64(data):
    return base64.b64encode(data).decode('ascii')


def _derive(password, salt):
    return bytearray(Scrypt(salt=salt, length=32, n=131072, r=8, p=1).derive(keys.password_bytes(password)))


def _wipe(buffer):
    if buffer is not None:
        buffer[:] = b'\0' * len(buffer)


def _unique(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError('duplicate field')
        result[k] = v
    return result


def _envelope(raw):
    try:
        if len(raw) > LIMIT:
            raise ValueError()
        doc = json.loads(raw, object_pairs_hook=_unique)
        if set(doc) != {'format', 'kdf', 'salt', 'nonce', 'data'} or doc['format'] != 'OKV1' or doc['kdf'] != 'scrypt-131072-8-1':
            raise ValueError()
        salt, nonce, data = [base64.b64decode(doc[k], validate=True) for k in ('salt', 'nonce', 'data')]
        if len(salt) != 16 or len(nonce) != 12 or len(data) < 16:
            raise ValueError()
        return salt, nonce, data
    except Exception:
        raise VaultError('密钥库格式无效、版本不支持或文件过大') from None


def _seal(records, key, salt):
    nonce = os.urandom(12)
    data = AESGCM(bytes(key)).encrypt(nonce, _json({'records': records}), AAD)
    raw = _json({'format': 'OKV1', 'kdf': 'scrypt-131072-8-1', 'salt': _b64(salt), 'nonce': _b64(nonce), 'data': _b64(data)})
    if len(raw) > LIMIT:
        raise VaultError('密钥库达到 16 MiB 大小限制')
    return raw


def metadata(name, tags, notes):
    if not isinstance(name, str) or not name.strip() or len(name) > 120 or any(ord(c) < 32 for c in name):
        raise VaultError('名称不能为空，最多 120 字符，不能包含控制字符')
    if isinstance(tags, str):
        tags = tags.replace('，', ',').split(',')
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        raise VaultError('标签格式错误')
    clean = list(dict.fromkeys(t.strip() for t in tags if t.strip()))
    if len(clean) > 20 or any(len(t) > 40 or any(ord(c) < 32 for c in t) for t in clean):
        raise VaultError('最多 20 个标签，每个最多 40 字符，不能包含控制字符')
    if not isinstance(notes, str) or len(notes) > 10000:
        raise VaultError('备注最多 10000 字符')
    return {'name': name.strip(), 'tags': clean, 'notes': notes}


def _validate_records(records):
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError()
    ids, fps = set(), set()
    required = {'id', 'name', 'tags', 'notes', 'algorithm', 'fingerprint', 'public', 'private', 'created', 'updated'}
    for r in records:
        if not isinstance(r, dict) or not required <= set(r) or set(r) - required - {'attachments', 'original'}:
            raise ValueError()
        if str(uuid.UUID(r['id'])) != r['id'] or r['id'] in ids or r['fingerprint'] in fps:
            raise ValueError()
        if not isinstance(r['tags'], list) or metadata(r['name'], r['tags'], r['notes']) != {k: r[k] for k in ('name', 'tags', 'notes')}:
            raise ValueError('元数据格式非规范')
        for field in ('created', 'updated'):
            datetime.fromisoformat(r[field])
        if not isinstance(r['public'], str) or len(r['public']) > keys.MAX_KEY_BYTES:
            raise ValueError()
        if r['private'] is not None and (not isinstance(r['private'], str) or len(r['private']) > keys.MAX_KEY_BYTES):
            raise ValueError()
        pub = keys.import_key(r['public'])
        if hasattr(pub, 'private_bytes') or keys.fingerprint(pub) != r['fingerprint'] or keys.algorithm(pub) != r['algorithm']:
            raise ValueError()
        if r['private'] is not None:
            private = keys.import_key(r['private'])
            if not hasattr(private, 'private_bytes') or keys.fingerprint(private) != r['fingerprint']:
                raise ValueError()
        if 'attachments' in r:
            from .material import validate
            validate(r['attachments'], pub)
        if 'original' in r:
            raw = base64.b64decode(r['original'], validate=True)
            if not 0 < len(raw) <= keys.MAX_KEY_BYTES or _b64(raw) != r['original']: raise ValueError()
        ids.add(r['id'])
        fps.add(r['fingerprint'])


class Vault(ProtectedVault):
    def __init__(self):
        self.path = None
        self._key = None
        self._salt = None
        self._records = []
        self._lock = None
        self._digest = None
        self._protected = None

    @property
    def unlocked(self):
        return self._key is not None

    def _require(self):
        if not self.unlocked:
            raise VaultError('密钥库已锁定')

    def create(self, path, password):
        keys.password_bytes(password, new=True)
        self.close()
        p = local_path(path)
        lock = FileLock(p)
        key = None
        try:
            salt = os.urandom(16)
            key = _derive(password, salt)
            raw = _seal([], key, salt)
            write_new(p, raw)
            self.path, self._salt, self._key, self._lock = p, salt, key, lock
            self._digest = hashlib.sha256(raw).digest()
        except BaseException:
            _wipe(key)
            lock.close()
            raise

    def open(self, path, password):
        self.close()
        p = local_path(path)
        lock = FileLock(p)
        key = None
        try:
            raw = read_limited(p, LIMIT)
            if is_protected(raw):
                self._open_protected(p, raw, lock, password)
                return
            salt, nonce, encrypted = _envelope(raw)
            key = _derive(password, salt)
            try:
                payload = json.loads(AESGCM(bytes(key)).decrypt(nonce, encrypted, AAD), object_pairs_hook=_unique)
                if set(payload) != {'records'}:
                    raise ValueError()
                _validate_records(payload['records'])
            except Exception:
                raise VaultError('口令错误、密钥库损坏或内容校验失败') from None
            self.path, self._salt, self._key, self._lock = p, salt, key, lock
            self._records = payload['records']
            self._digest = hashlib.sha256(raw).digest()
        except BaseException:
            _wipe(key)
            lock.close()
            raise

    def verify(self, password):
        self._require()
        if self._protected is not None:
            return self._verify_protected(password)
        self._check_current()
        candidate = _derive(password, self._salt)
        try:
            if not hmac.compare_digest(candidate, self._key):
                raise VaultError('主口令错误')
        finally:
            _wipe(candidate)

    def _check_current(self):
        self._require()
        if not hmac.compare_digest(hashlib.sha256(read_limited(self.path, LIMIT)).digest(), self._digest):
            raise VaultError('磁盘文件已被外部修改，请锁定后重新打开；未覆盖原文件')

    def _commit(self, records, key=None, salt=None):
        self._check_current()
        if self._protected is not None:
            if key is not None or salt is not None:
                raise VaultError("受保护密钥库必须通过凭据封装更新口令")
            return self._commit_protected(records)
        raw = _seal(records, self._key if key is None else key, self._salt if salt is None else salt)
        self._check_current()
        atomic_replace(self.path, raw, expected_digest=self._digest)
        self._digest = hashlib.sha256(raw).digest()
        self._records = records

    def records(self, query=''):
        self._require()
        query = query.casefold().strip()
        return [{k: copy.deepcopy(v) for k, v in r.items() if k in {'id', 'name', 'tags', 'notes', 'algorithm', 'fingerprint', 'public', 'created', 'updated', 'attachments'}} | {'has_private': r['private'] is not None, 'has_original': 'original' in r}
                for r in self._records if not query or query in ' '.join([r['name'], *r['tags'], r['notes'], r['algorithm'], r['fingerprint']]).casefold()]

    def _record(self, record_id):
        self._require()
        for r in self._records:
            if r['id'] == record_id:
                return r
        raise VaultError('未找到所选记录')

    def add(self, key, name, tags='', notes='', *, source=None):
        self._require()
        if source is not None:
            if isinstance(source, str): source = source.encode('utf-8')
            if not isinstance(source, bytes) or not 0 < len(source) <= keys.MAX_KEY_BYTES: raise VaultError('导入原文为空或过大')
        meta = metadata(name, tags, notes)
        pub, private = keys.normalized(key)
        fp = keys.fingerprint(key)
        attachments = copy.deepcopy(getattr(key, 'attachments', {}))
        if attachments:
            from .material import validate
            validate(attachments, keys.public_of(key))
        now = datetime.now(timezone.utc).isoformat(timespec='seconds')
        records = copy.deepcopy(self._records)
        for r in records:
            if r['fingerprint'] == fp:
                if (r['private'] is None and private is not None) or attachments or source is not None:
                    if source is not None: r['original'] = _b64(source)
                    if r['private'] is None: r['private'] = private
                    r['updated'] = now
                    if attachments: r['attachments'] = r.get('attachments', {}) | attachments
                    self._commit(records)
                    return r['id'], True
                raise VaultError('密钥已存在（公钥指纹相同）')
        if len(records) >= MAX_RECORDS:
            raise VaultError('最多保存 1000 条密钥记录')
        record_id = str(uuid.uuid4())
        records.append(dict(id=record_id, **meta, public=pub, private=private, algorithm=keys.algorithm(key), fingerprint=fp, created=now, updated=now))
        if source is not None: records[-1]['original'] = _b64(source)
        if attachments: records[-1]['attachments'] = attachments
        self._commit(records)
        return record_id, False

    def add_many(self, items, name, tags='', notes='', *, source=None):
        self._require()
        if not 1 <= len(items) <= 50: raise VaultError('一次最多导入 50 条记录')
        original = self._records
        commit = self._commit
        self._records = copy.deepcopy(original)
        self._commit = lambda records: setattr(self, '_records', records)
        results = []
        try:
            for index, item in enumerate(items):
                title = name if len(items) == 1 else name + ' / ' + (getattr(item, 'alias', '') or str(index + 1))
                results.append(self.add(item, title, tags, notes, source=source if len(items) == 1 else None))
            staged = self._records
        finally:
            self._records = original
            del self._commit
        commit(staged)
        return results[0]

    def edit(self, record_id, name, tags, notes):
        self._record(record_id)
        meta = metadata(name, tags, notes)
        records = copy.deepcopy(self._records)
        for r in records:
            if r['id'] == record_id:
                r.update(meta, updated=datetime.now(timezone.utc).isoformat(timespec='seconds'))
        self._commit(records)

    def delete(self, record_id, password):
        self.verify(password)
        self._record(record_id)
        self._commit([r for r in self._records if r['id'] != record_id])

    def export(self, record_id, path, fmt, private=False, password='', export_password='', plaintext=False):
        self._check_current()
        r = self._record(record_id)
        if private:
            self.verify(password)
            if not r['private']:
                raise VaultError('此记录只有公钥')
            key = keys.import_key(r['private'])
            if fmt in ('JKS', 'PKCS12'):
                if plaintext: raise VaultError('容器导出必须设置口令')
                keys.password_bytes(export_password, new=True)
                from .material import export_attachment
                data = export_attachment(r, fmt, key, export_password)
            else:
                data = keys.export_private(key, fmt, export_password, plaintext)
        else:
            if fmt in ('Certificate-PEM', 'Certificate-Chain', 'PKCS7', 'SSH-Certificate', 'JKS'):
                from .material import export_attachment
                if fmt == 'JKS': keys.password_bytes(export_password, new=True)
                data = export_attachment(r, fmt, password=export_password)
            else:
                data = keys.export_public(keys.import_key(r['public']), fmt)
        write_new(path, data)

    def content(self, record_id, *, private=False, password=''):
        self._require()
        self._check_current()
        if private: self.verify(password)
        record = self._record(record_id)
        value = record['private'] if private else record['public']
        if value is None: raise VaultError('此记录只有公钥')
        return value

    def original_bytes(self, record_id, password):
        # Original containers may contain private keys even when a UI label is public.
        # Never expose original bytes through the unauthenticated records() listing.
        self.verify(password)
        record = self._record(record_id)
        if 'original' not in record:
            raise VaultError('此记录未保留导入原文；旧记录或多条目容器不能倒推原始文件')
        return base64.b64decode(record['original'], validate=True)

    def export_original(self, record_id, path, password):
        write_new(path, self.original_bytes(record_id, password))

    def backup(self, path):
        self._check_current()
        raw = read_limited(self.path, LIMIT)
        if hashlib.sha256(raw).digest() != self._digest:
            raise VaultError('磁盘文件已改变')
        write_new(path, raw)

    def change_password(self, old, new):
        keys.password_bytes(new, new=True)
        self.verify(old)
        if self._protected is not None:
            return self._change_protected_password(new)
        salt = os.urandom(16)
        key = _derive(new, salt)
        try:
            self._commit(copy.deepcopy(self._records), key, salt)
        except BaseException:
            _wipe(key)
            raise
        _wipe(self._key)
        self._key, self._salt = key, salt

    def close(self):
        _wipe(self._key)
        self._key, self._salt, self._digest = None, None, None
        self._records.clear()
        self._protected = None
        if self._lock:
            self._lock.close()
        self._lock = None
