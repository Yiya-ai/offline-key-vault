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

    def load(self):
        try:
            raw = read_limited(self.path, 16384)
        except FileNotFoundError:
            return ''
        try:
            doc = json.loads(raw, object_pairs_hook=_unique)
            if not isinstance(doc, dict) or set(doc) != {'format', 'export_directory'} or doc['format'] != 'OKV-PREFERENCES1' or not isinstance(doc['export_directory'], str):
                raise ValueError()
            return doc['export_directory']
        except (ValueError, TypeError):
            raise ValueError('本地导出设置格式错误，请在“导出设置”中重新保存') from None

    def export_directory(self):
        value = self.load()
        if not value:
            return ''
        directory = local_path(value, directory=True)
        if not directory.is_dir():
            raise ValueError('默认导出目录已不存在，请在“导出设置”中重新选择')
        return str(directory)

    def save(self, directory):
        value = ''
        if directory:
            path = local_path(directory, directory=True)
            if not path.is_dir(): raise ValueError('请选择已存在的本地目录')
            value = str(path)
        path = local_path(self.path)
        lock = FileLock(path)
        try:
            raw = json.dumps({'format': 'OKV-PREFERENCES1', 'export_directory': value}, ensure_ascii=False).encode('utf-8')
            try:
                current = read_limited(path, 16384)
            except FileNotFoundError:
                write_new(path, raw)
            else:
                atomic_replace(path, raw, expected_digest=hashlib.sha256(current).digest())
        finally:
            lock.close()
