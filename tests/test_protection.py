"""Security regressions: synthetic vaults only, never use real user material."""
import base64
import copy
import hashlib
import json
from unittest.mock import patch
import pytest
from keyvault import keys, protection
from keyvault.vault import Vault, VaultError, AuthenticationError, VaultDestroyed
from keyvault.safeio import StorageError

MASTER = 'synthetic master password 123'
RECOVERY = 'independent recovery passphrase 456'
NEW = 'synthetic replacement password 789'
CONFIRM = protection.DESTROY_CONFIRMATION


@pytest.fixture
def make_vault(tmp_path):
    opened = []
    def make(maximum=5, recovery=True):
        index = len(opened)
        path, factor = tmp_path / f'synthetic-{index}.okv', tmp_path / f'factor-{index}.okvr'
        vault = Vault(); opened.append(vault)
        vault.create(path, MASTER)
        rid, _ = vault.add(keys.generate('Ed25519'), 'synthetic private record', '测试', 'private notes')
        options = {'recovery_password': RECOVERY, 'recovery_path': factor} if recovery else {}
        vault.configure_security(MASTER, maximum, confirmation=CONFIRM, **options)
        return vault, path, factor, rid
    yield make
    for vault in opened:
        vault.close()


def test_default_off_and_opt_in_confirmation(tmp_path):
    vault = Vault()
    path = tmp_path / 'default.okv'
    try:
        vault.create(path, MASTER)
        assert vault.security_status() == {'max_failures': 0, 'failures': 0, 'recovery': False}
        before = path.read_bytes()
        with pytest.raises(VaultError, match='确认'):
            vault.configure_security(MASTER, 5)
        assert path.read_bytes() == before
        for maximum in (True, 1, 4, 101, -1, '5'):
            with pytest.raises(VaultError):
                vault.configure_security(MASTER, maximum, confirmation=CONFIRM)
        assert path.read_bytes() == before
    finally:
        vault.close()


def test_migration_encryption_crud_and_password_change(make_vault, tmp_path):
    vault, path, factor, rid = make_vault()
    raw = path.read_bytes()
    assert json.loads(raw)['format'] == 'OKV2'
    for secret in (MASTER, RECOVERY, 'synthetic private record', 'private notes', 'PRIVATE KEY'):
        assert secret.encode() not in raw and secret.encode() not in factor.read_bytes()
    vault.edit(rid, 'updated', ['local'], 'still encrypted')
    vault.change_password(MASTER, NEW)
    vault.close()
    with pytest.raises(AuthenticationError):
        vault.open(path, MASTER)
    vault.open(path, NEW)
    assert vault.records()[0]['name'] == 'updated'
    vault.export(rid, tmp_path / 'export.pem', 'PEM', True, NEW, MASTER)
    assert keys.fingerprint(keys.import_key((tmp_path / 'export.pem').read_bytes(), MASTER)) == vault.records()[0]['fingerprint']
    vault.delete(rid, NEW)
    assert not vault.records()


def test_failure_count_survives_reopen_and_success_resets(make_vault):
    vault, path, _, _ = make_vault()
    vault.close()
    for attempt in range(1, 4):
        with pytest.raises(AuthenticationError):
            vault.open(path, 'wrong password')
        assert not vault.unlocked
        assert Vault.inspect_security(path)['failures'] == attempt
    vault.open(path, MASTER)
    assert vault.security_status()['failures'] == 0
    vault.close()
    assert Vault.inspect_security(path)['failures'] == 0


def test_threshold_destroys_all_ciphertext_and_recovery(make_vault, tmp_path):
    vault, path, factor, _ = make_vault()
    backup = tmp_path / 'intentional-backup.okv'
    vault.backup(backup)
    old_key = vault._key
    for _ in range(4):
        with pytest.raises(AuthenticationError):
            vault.verify('wrong password')
    with pytest.raises(VaultDestroyed):
        vault.verify('wrong password')
    assert not vault.unlocked and not vault._records
    assert not any(old_key)
    tombstone = json.loads(path.read_bytes())
    assert set(tombstone) == {'format', 'id'} and tombstone['format'] == 'OKV-DESTROYED'
    with pytest.raises(VaultDestroyed):
        vault.open(path, MASTER)
    with pytest.raises(VaultDestroyed):
        vault.recover(path, RECOVERY, factor, NEW)
    # Independent backups are intentionally outside the destruction boundary.
    vault.open(backup, MASTER)
    assert len(vault.records()) == 1


def test_locked_unlock_threshold(make_vault):
    vault, path, _, _ = make_vault(recovery=False)
    vault.close()
    for _ in range(4):
        with pytest.raises(AuthenticationError):
            vault.open(path, 'wrong password')
    with pytest.raises(VaultDestroyed):
        vault.open(path, 'wrong password')
    assert json.loads(path.read_bytes())['format'] == 'OKV-DESTROYED'


def test_recovery_requires_both_factors_and_preserves_records(make_vault, tmp_path):
    vault, path, factor, rid = make_vault()
    expected = vault.records()
    vault.close()
    before = path.read_bytes()
    with pytest.raises(OSError):
        vault.recover(path, RECOVERY, tmp_path / 'missing.okvr', NEW)
    assert path.read_bytes() == before
    with pytest.raises(AuthenticationError):
        vault.recover(path, 'wrong recovery phrase', factor, NEW)
    assert Vault.inspect_security(path)['failures'] == 1
    wrong = json.loads(factor.read_bytes()); wrong['secret'] = base64.b64encode(b'x' * 32).decode()
    wrong_file = tmp_path / 'wrong-factor.okvr'; wrong_file.write_text(json.dumps(wrong))
    with pytest.raises(AuthenticationError):
        vault.recover(path, RECOVERY, wrong_file, NEW)
    assert Vault.inspect_security(path)['failures'] == 2
    vault.recover(path, RECOVERY, factor, NEW)
    assert vault.records() == expected and vault.security_status()['failures'] == 0
    vault.close()
    with pytest.raises(AuthenticationError):
        vault.open(path, MASTER)
    vault.open(path, NEW)
    assert vault.records()[0]['id'] == rid


def test_recovery_attempts_share_destruction_counter(make_vault):
    vault, path, factor, _ = make_vault()
    for _ in range(4):
        with pytest.raises(AuthenticationError):
            vault.verify('wrong password')
    vault.close()
    with pytest.raises(VaultDestroyed):
        vault.recover(path, 'wrong recovery phrase', factor, NEW)
    with pytest.raises(VaultDestroyed):
        vault.recover(path, RECOVERY, factor, NEW)


def test_private_export_delete_change_password_share_counter(make_vault, tmp_path):
    vault, path, _, rid = make_vault()
    export = tmp_path / 'must-not-exist.pem'
    for action in (lambda: vault.export(rid, export, 'PEM', True, 'wrong', NEW),
                   lambda: vault.delete(rid, 'wrong'), lambda: vault.change_password('wrong', NEW)):
        with pytest.raises(AuthenticationError):
            action()
    assert vault.security_status()['failures'] == 3
    assert len(vault.records()) == 1 and not export.exists()
    vault.close()
    assert Vault.inspect_security(path)['failures'] == 3


def test_disabled_policy_does_not_write_failed_attempts(make_vault):
    vault, path, _, _ = make_vault(0)
    before = path.read_bytes()
    for _ in range(2):
        with pytest.raises(AuthenticationError):
            vault.verify('wrong')
    assert vault.unlocked and before == path.read_bytes()
    vault.close()
    with pytest.raises(AuthenticationError):
        vault.open(path, 'wrong')
    assert before == path.read_bytes()


@pytest.mark.parametrize('damage', ['checksum', 'master', 'data', 'kdf', 'policy', 'duplicate', 'truncated'])
def test_corruption_never_consumes_attempt_or_destroys(make_vault, damage):
    vault, path, _, _ = make_vault()
    vault.close()
    doc = json.loads(path.read_bytes())
    if damage == 'checksum': doc['checksum'] = '0' * 64
    elif damage == 'master': doc['master']['data'] = base64.b64encode(b'x' * 48).decode()
    elif damage == 'data': doc['data'] = base64.b64encode(b'x' * 32).decode()
    elif damage == 'kdf': doc['master']['kdf'] = 'unbounded-kdf'
    elif damage == 'policy': doc['max_failures'] = 1
    raw = json.dumps(doc).encode()
    if damage == 'duplicate': raw = raw[:-1] + b',"failures":4}'
    if damage == 'truncated': raw = raw[:50]
    path.write_bytes(raw)
    with pytest.raises(VaultError):
        vault.open(path, MASTER)
    assert path.read_bytes() == raw and not vault.unlocked


def test_authenticated_payload_corruption_not_password_failure(make_vault):
    vault, path, _, _ = make_vault()
    vault.close()
    doc = json.loads(path.read_bytes())
    doc['data'] = base64.b64encode(b'x' * 32).decode()
    raw = protection.pack(doc)  # Valid public checksum is not cryptographic authentication.
    path.write_bytes(raw)
    with pytest.raises(VaultError, match='口令已通过'):
        vault.open(path, MASTER)
    assert path.read_bytes() == raw


def test_io_failure_on_attempt_locks_without_claiming_destruction(make_vault):
    vault, path, _, _ = make_vault()
    for _ in range(4):
        with pytest.raises(AuthenticationError): vault.verify('wrong')
    before, key = path.read_bytes(), vault._key
    with patch('keyvault.protection.atomic_replace', side_effect=OSError('synthetic write failure')):
        with pytest.raises(OSError): vault.verify('wrong')
    assert path.read_bytes() == before and not vault.unlocked and not any(key)
    vault.open(path, MASTER)
    assert vault.security_status()['failures'] == 0


def test_recovery_commit_failure_is_atomic(make_vault):
    vault, path, factor, _ = make_vault()
    vault.close()
    before = path.read_bytes()
    with patch('keyvault.protection.atomic_replace', side_effect=OSError('synthetic write failure')):
        with pytest.raises(OSError): vault.recover(path, RECOVERY, factor, NEW)
    assert before == path.read_bytes() and not vault.unlocked
    vault.open(path, MASTER)


def test_migration_commit_failure_preserves_v1(tmp_path):
    vault = Vault(); path = tmp_path / 'migration.okv'; factor = tmp_path / 'factor.okvr'
    try:
        vault.create(path, MASTER)
        before = path.read_bytes()
        with patch('keyvault.protection.atomic_replace', side_effect=OSError('synthetic write failure')):
            with pytest.raises(OSError):
                vault.configure_security(MASTER, 5, confirmation=CONFIRM, recovery_password=RECOVERY, recovery_path=factor)
        assert path.read_bytes() == before and vault.unlocked and vault._protected is None
        assert factor.exists()  # Orphan factor has no data or decryption key; no rollback overwrite.
        vault.close(); vault.open(path, MASTER)
    finally:
        vault.close()


def test_rotate_and_disable_recovery(make_vault, tmp_path):
    vault, path, old, _ = make_vault()
    new_factor = tmp_path / 'replacement.okvr'
    vault.configure_security(MASTER, 5, confirmation=CONFIRM, recovery_password=RECOVERY, recovery_path=new_factor)
    vault.close()
    with pytest.raises(AuthenticationError): vault.recover(path, RECOVERY, old, NEW)
    vault.recover(path, RECOVERY, new_factor, NEW)
    vault.configure_security(NEW, 0, remove_recovery=True)
    assert vault.security_status() == {'max_failures': 0, 'failures': 0, 'recovery': False}
    vault.close()
    before = path.read_bytes()
    with pytest.raises(VaultError, match='未配置'): vault.recover(path, RECOVERY, new_factor, MASTER)
    assert path.read_bytes() == before
    vault.open(path, NEW)


def test_invalid_recovery_input_no_attempt(make_vault, tmp_path):
    vault, path, factor, _ = make_vault()
    vault.close()
    before = path.read_bytes()
    with pytest.raises(ValueError): vault.recover(path, RECOVERY, factor, 'short')
    other = tmp_path / 'other.okvr'; other.write_text('{"format":"OKV-RECOVERY1","id":"other","secret":""}')
    with pytest.raises(VaultError): vault.recover(path, RECOVERY, other, NEW)
    assert path.read_bytes() == before


def test_external_change_and_concurrent_open_do_not_consume_attempt(make_vault):
    vault, path, _, _ = make_vault()
    before = path.read_bytes()
    other = Vault()
    try:
        with pytest.raises(StorageError): other.open(path, 'wrong')
        assert path.read_bytes() == before
        path.write_bytes(before + b' ')
        with pytest.raises(VaultError, match='外部修改'): vault.verify('wrong')
        assert path.read_bytes() == before + b' '
    finally:
        other.close()


def test_no_record_write_resets_failed_count(make_vault):
    vault, path, _, rid = make_vault()
    with pytest.raises(AuthenticationError): vault.verify('wrong')
    vault.edit(rid, 'edited', '', '')
    assert vault.security_status()['failures'] == 1
    vault.close()
    assert Vault.inspect_security(path)['failures'] == 1


def test_password_change_preserves_recovery(make_vault):
    vault, path, factor, _ = make_vault()
    vault.change_password(MASTER, NEW)
    vault.close()
    vault.recover(path, RECOVERY, factor, MASTER)
    assert len(vault.records()) == 1


def test_blank_password_and_invalid_new_password_do_not_consume_attempt(make_vault):
    vault, path, factor, _ = make_vault()
    before = path.read_bytes()
    for invalid in ('', '   ', 'x' * 1025):
        with pytest.raises(ValueError): vault.verify(invalid)
    with pytest.raises(ValueError): vault.change_password('wrong', 'short')
    assert path.read_bytes() == before
    vault.close()
    with pytest.raises(ValueError): vault.open(path, '')
    with pytest.raises(ValueError): vault.recover(path, '', factor, NEW)
    assert path.read_bytes() == before
