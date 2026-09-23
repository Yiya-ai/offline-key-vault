"""Only synthetic data and disposable repositories; never touch user vaults."""
import json
import subprocess
import zipfile
import pytest
from tools import release


def fixture_project(root):
    (root / 'tools').mkdir()
    (root / 'main.py').write_text('print("synthetic")\n', encoding='utf-8')
    (root / release.MANIFEST).write_text(json.dumps({'schema': 1, 'files': ['main.py', release.MANIFEST]}), encoding='utf-8')
    return root


def test_source_archive_excludes_runtime_and_is_reproducible(tmp_path):
    root = fixture_project(tmp_path)
    (root / 'exports').mkdir()
    (root / 'exports/private.pem').write_text('synthetic excluded material', encoding='utf-8')
    (root / '.env').write_text('synthetic=excluded', encoding='utf-8')
    first = release.build_source(root)
    second = release.build_source(root)
    assert first['sha256'] == second['sha256']
    with zipfile.ZipFile(root / 'dist' / first['archive']) as archive:
        assert set(archive.namelist()) == {'offline-key-vault/main.py', 'offline-key-vault/' + release.MANIFEST}
        assert archive.read('offline-key-vault/main.py') == (root / 'main.py').read_bytes()


@pytest.mark.parametrize('name', ['../outside.py', '/outside.py', 'exports/leak.py', 'secrets.pem', '.env.txt', 'dir//x.py'])
def test_manifest_rejects_unsafe_paths(name):
    with pytest.raises(release.ReleaseError):
        release.validate_names([name])


@pytest.mark.parametrize('kind,secret', [
    ('credential-token', 'gh' + 'p_' + 'X' * 30),
    ('personal-home-path', 'C:/' + 'Users/' + 'SyntheticUser/file'),
    ('literal-private-key', '-----BEGIN ' + 'PRIVATE KEY-----\n' + 'A' * 50),
])
def test_secret_scan_withholds_values(kind, secret):
    findings = release.scan('sample.txt', secret.encode())
    assert any(item['kind'] == kind for item in findings)
    assert secret not in json.dumps(findings)


def test_generic_keywords_and_placeholders_are_allowed():
    assert release.scan('guide.md', b'Cookie, token, UID. C:/Users/<user>/example. Generate keys during tests.') == []


def test_failed_audit_does_not_write_archive(tmp_path):
    root = fixture_project(tmp_path)
    (root / 'main.py').write_text('broken syntax (', encoding='utf-8')
    with pytest.raises(release.ReleaseError):
        release.build_source(root)
    assert not (root / 'dist').exists()


def test_index_scan_uses_staged_bytes_and_rejects_extra_files(tmp_path):
    root = fixture_project(tmp_path)
    subprocess.run(['git', 'init', '-q', str(root)], check=True, capture_output=True)
    release.git(root, 'add', '--', 'main.py', release.MANIFEST)
    assert release.audit(root, index=True)[1] == []
    secret = 'gh' + 'p_' + 'X' * 30
    (root / 'main.py').write_text('value = ' + repr(secret), encoding='utf-8')
    release.git(root, 'add', '--', 'main.py')
    (root / 'main.py').write_text('print("synthetic")\n', encoding='utf-8')
    findings = release.audit(root, index=True)[1]
    assert any(item['kind'] == 'credential-token' for item in findings)
    assert any(item['kind'] == 'unstaged-difference' for item in findings)
    assert secret not in json.dumps(findings)
    (root / 'unexpected.okv').write_text('synthetic only', encoding='utf-8')
    release.git(root, 'add', '--', 'unexpected.okv')
    with pytest.raises(release.ReleaseError, match='allowlist'):
        release.audit(root, index=True)


def test_linked_source_rejected(tmp_path):
    import os
    root = fixture_project(tmp_path)
    os.link(root / 'main.py', root / 'alias.py')
    with pytest.raises(release.ReleaseError, match='Hard-linked'):
        release.audit(root)
