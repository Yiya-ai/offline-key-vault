"""Private local export preferences; never stores keys or passwords."""
import hashlib
import json
from pathlib import Path, PureWindowsPath
import unicodedata
from .safeio import FileLock, local_path, read_limited, atomic_replace, write_new


def export_filename(name, extension):
    if not isinstance(name, str) or not extension.startswith('.') or any(c in extension for c in '/\\'):
        raise ValueError('导出文件名参数无效')
    clean = ''.join('_' if c in '<>:"/\\|?*' or unicodedata.category(c).startswith('C') else c for c in name).strip(' .')
    clean = clean or 'key'
    if clean.lower().endswith(extension.lower()):
        clean = clean[:-len(extension)].rstrip(' .') or 'key'
    if PureWindowsPath(clean).is_reserved():
        clean = '_' + clean
    if len(clean.encode('utf-8')) > 180:
        suffix = '-' + hashlib.sha256(name.encode('utf-8')).hexdigest()[:8]
        clean = clean.encode('utf-8')[:160].decode('utf-8', errors='ignore').rstrip(' .') + suffix
    return clean + extension


def _unique(pairs):
    doc = {}
    for key, value in pairs:
        if key in doc: raise ValueError('重复设置字段')
        doc[key] = value
    return doc


class Preferences:
    def __init__(self, path=None):
        self.path = Path(path) if path is not None else Path.home() / '.offline-key-vault-preferences.json'

    def load_all(self):
        empty = {'export_directory': '', 'vault_directory': '', 'import_directory': ''}
        try:
            raw = read_limited(self.path, 16384)
        except FileNotFoundError:
            return empty
        try:
            doc = json.loads(raw, object_pairs_hook=_unique)
            fields = {'format', 'export_directory'} if doc.get('format') == 'OKV-PREFERENCES1' else {'format', *empty}
            if not isinstance(doc, dict) or set(doc) != fields or doc['format'] not in ('OKV-PREFERENCES1', 'OKV-PREFERENCES2'):
                raise ValueError()
            values = empty | {key: doc[key] for key in empty if key in doc}
            if any(not isinstance(value, str) or len(value) > 4096 for value in values.values()):
                raise ValueError()
            return values
        except (ValueError, TypeError, AttributeError):
            raise ValueError('本地路径设置格式错误，请在设置中重新保存') from None

    def load(self):
        return self.load_all()['export_directory']

    def directory(self, kind):
        if kind not in ('export', 'vault', 'import'):
            raise ValueError('未知默认路径类型')
        value = self.load_all()[kind + '_directory']
        if not value:
            return ''
        path = local_path(value, directory=True)
        if not path.is_dir():
            raise ValueError('默认目录已不存在，请在设置中重新选择')
        return str(path)

    def export_directory(self):
        return self.directory('export')

    def save_all(self, export_directory='', vault_directory='', import_directory='', _legacy=False):
        values = dict(export_directory=export_directory, vault_directory=vault_directory, import_directory=import_directory)
        for key, value in values.items():
            if not isinstance(value, str): value = str(value)
            value = value.strip()
            if value:
                path = local_path(value, directory=True)
                if not path.is_dir(): raise ValueError('请选择已存在的本地目录')
                value = str(path)
            if len(value) > 4096: raise ValueError('目录路径过长')
            values[key] = value
        doc = {'format': 'OKV-PREFERENCES2', **values}
        if _legacy and not values['vault_directory'] and not values['import_directory']:
            doc = {'format': 'OKV-PREFERENCES1', 'export_directory': values['export_directory']}
        raw = json.dumps(doc, ensure_ascii=False).encode('utf-8')
        if len(raw) > 16384: raise ValueError('路径设置过大')
        path = local_path(self.path)
        lock = FileLock(path)
        try:
            try:
                current = read_limited(path, 16384)
            except FileNotFoundError:
                write_new(path, raw)
            else:
                atomic_replace(path, raw, expected_digest=hashlib.sha256(current).digest())
        finally:
            lock.close()

    def save(self, directory):
        values = self.load_all()
        values['export_directory'] = directory
        self.save_all(**values, _legacy=True)
