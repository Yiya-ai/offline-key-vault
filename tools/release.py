"""Offline source release allowlist, content audit and ZIP builder (stdlib only)."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).absolute().parent.parent
MANIFEST = 'tools/release_manifest.json'
MAX_BYTES = 2 * 1024 * 1024
PRIVATE_PARTS = frozenset({'.git', 'vendor', 'build', 'dist', 'exports', 'test-results',
                           '__pycache__', '.pytest_cache', '.venv', 'venv', 'wheelhouse',
                           'node_modules', '.vendor', '.playwright-cli', 'output'})
SOURCE_SUFFIXES = frozenset({'.py', '.md', '.txt', '.cs', '.c', '.cmd', '.command', '.json', '.yml'})
WEB_SOURCE_SUFFIXES = frozenset({'.js', '.mjs', '.html', '.css', '.svg'})
SPECIAL_NAMES = frozenset({'LICENSE', '.gitignore', '.gitattributes',
                          'web/wasm-build/Dockerfile', 'web/wasm-build/.dockerignore'})
PATTERNS = (
    ('personal-home-path', re.compile(r'(?:[A-Za-z]:[\\/]+Users[\\/]+|/(?:Users|home)/)[A-Za-z0-9_.-]+')),
    ('credential-token', re.compile(r'(?:gh[pousr]_|github_pat_|sk-proj-)[A-Za-z0-9_-]{20,}')),
    ('literal-private-key', re.compile(r'-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----\s+[A-Za-z0-9+/=]{32,}')),
)


class ReleaseError(ValueError):
    """Safe message: never interpolate input contents or exception details."""


def validate_names(names):
    if not isinstance(names, list) or not names or len(names) > 1000:
        raise ReleaseError('Invalid source manifest file list')
    seen = set()
    for name in names:
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.\-/]+', name):
            raise ReleaseError('Invalid source manifest path')
        path = PurePosixPath(name)
        if (path.is_absolute() or path.as_posix() != name or '..' in path.parts
                or any(part.lower() in PRIVATE_PARTS for part in path.parts)
                or any(part.lower().startswith('.env') for part in path.parts)
                or (path.suffix not in SOURCE_SUFFIXES and name not in SPECIAL_NAMES
                    and not (path.parts[0] == 'web' and path.suffix in WEB_SOURCE_SUFFIXES)
                    and not (path.parts[:2] == ('web', 'wasm-build') and path.suffix == '.sh'))):
            raise ReleaseError('Disallowed source manifest path')
        if name.casefold() in seen:
            raise ReleaseError('Duplicate source manifest path')
        seen.add(name.casefold())
    return tuple(names)


def checked_path(path, *, allow_missing=False):
    path = Path(path).absolute()
    for item in (*reversed(path.parents), path):
        try:
            info = item.lstat()
        except FileNotFoundError:
            if allow_missing and item == path:
                continue
            raise ReleaseError('Missing source or output path') from None
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ReleaseError('Linked or reparse paths are forbidden')
        if item == path and stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise ReleaseError('Hard-linked files are forbidden')
    return path


def read_source(root, name):
    path = checked_path(Path(root) / name)
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ReleaseError('Source is not a bounded regular file')
    with path.open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ReleaseError('Source exceeds size limit')
    return data


def parse_manifest(data):
    try:
        doc = json.loads(data)
    except (ValueError, UnicodeError):
        raise ReleaseError('Invalid release manifest JSON') from None
    if not isinstance(doc, dict) or doc.get('schema') != 1:
        raise ReleaseError('Unsupported release manifest schema')
    return validate_names(doc.get('files'))


def scan(name, data):
    try:
        source = data.decode('utf-8-sig')
    except UnicodeError:
        return [{'file': name, 'line': 0, 'kind': 'non-utf8-source'}]
    findings = []
    if '\x00' in source:
        findings.append({'file': name, 'line': 0, 'kind': 'binary-source'})
    for kind, pattern in PATTERNS:
        for match in pattern.finditer(source):
            findings.append({'file': name, 'line': source.count('\n', 0, match.start()) + 1, 'kind': kind})
    if name.endswith('.py'):
        try:
            ast.parse(source, filename=name)
        except (SyntaxError, ValueError) as error:
            findings.append({'file': name, 'line': getattr(error, 'lineno', 0), 'kind': 'python-syntax'})
    return findings


def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args], capture_output=True, timeout=30)
    if result.returncode:
        raise ReleaseError('Local Git operation failed; no remote operation attempted')
    return result.stdout


def audit(root=ROOT, *, index=False):
    manifest = read_source(root, MANIFEST)
    names = parse_manifest(manifest)
    if MANIFEST not in names:
        raise ReleaseError('Manifest must include itself')
    snapshot = {name: read_source(root, name) for name in names}
    if snapshot[MANIFEST] != manifest:
        raise ReleaseError('Manifest changed during audit')
    findings = [finding for name, data in snapshot.items() for finding in scan(name, data)]
    if index:
        entries = {}
        for entry in git(root, 'ls-files', '--stage', '-z').split(b'\0'):
            if not entry:
                continue
            meta, path = entry.split(b'\t', 1)
            mode, oid, stage = meta.split()
            name = path.decode('utf-8')
            if mode not in (b'100644', b'100755') or stage != b'0' or name in entries:
                raise ReleaseError('Index contains links, submodules or unresolved conflicts')
            entries[name] = oid.decode('ascii')
        if set(entries) != set(names):
            raise ReleaseError('Index differs from source allowlist; inspect git status locally')
        for name, oid in entries.items():
            size = int(git(root, 'cat-file', '-s', oid))
            if size > MAX_BYTES:
                raise ReleaseError('Staged source exceeds size limit')
            data = git(root, 'cat-file', 'blob', oid)
            findings.extend(scan(name, data))
            if data.replace(b'\r\n', b'\n') != snapshot[name].replace(b'\r\n', b'\n'):
                findings.append({'file': name, 'line': 0, 'kind': 'unstaged-difference'})
    return snapshot, findings


def require_clean(root=ROOT, *, index=False):
    snapshot, findings = audit(root, index=index)
    if findings:
        print(json.dumps({'ok': False, 'findings': findings}, ensure_ascii=True))
        raise ReleaseError('Source audit failed; content values have been withheld')
    return snapshot


def build_source(root=ROOT):
    # Serialize the exact in-memory bytes that passed audit, not a second disk read.
    snapshot = require_clean(root)
    output_dir = Path(root) / 'dist'
    checked_path(output_dir, allow_missing=True)
    output_dir.mkdir(exist_ok=True)
    output = checked_path(output_dir / 'offline-key-vault-source.zip', allow_missing=True)
    checksum = checked_path(output.with_suffix('.zip.sha256'), allow_missing=True)
    handle, temporary = tempfile.mkstemp(prefix='source-', suffix='.tmp', dir=output_dir)
    os.close(handle)
    try:
        with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, data in sorted(snapshot.items()):
                info = zipfile.ZipInfo('offline-key-vault/' + name, (2026, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (0o100755 if name.endswith('.command') else 0o100644) << 16
                archive.writestr(info, data)
        with zipfile.ZipFile(temporary) as archive:
            if archive.testzip() or len(archive.namelist()) != len(snapshot):
                raise ReleaseError('Source archive verification failed')
            for name, data in snapshot.items():
                if archive.read('offline-key-vault/' + name) != data:
                    raise ReleaseError('Source archive content mismatch')
        digest = hashlib.sha256(Path(temporary).read_bytes()).hexdigest()
        os.replace(temporary, output)
        checksum.write_text(digest + '  ' + output.name + '\n', encoding='ascii')
    finally:
        Path(temporary).unlink(missing_ok=True)
    return {'ok': True, 'files': len(snapshot), 'archive': output.name, 'sha256': digest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('audit', 'source', 'stage'))
    parser.add_argument('--index', action='store_true', help='Audit all staged/tracked index blobs')
    args = parser.parse_args()
    if args.index and args.command != 'audit':
        parser.error('--index applies only to audit')
    try:
        if args.command == 'source':
            result = build_source()
        else:
            snapshot = require_clean(index=args.index)
            if args.command == 'stage':
                git(ROOT, 'add', '--', *snapshot)
                require_clean(index=True)
            result = {'ok': True, 'files': len(snapshot), 'index_checked': args.index or args.command == 'stage'}
        print(json.dumps(result))
        return 0
    except ReleaseError as error:
        print(json.dumps({'ok': False, 'error': str(error)}))
        return 1
    except (OSError, ValueError, subprocess.SubprocessError):
        print(json.dumps({'ok': False, 'error': 'Audit/build could not complete; local environment check required'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
