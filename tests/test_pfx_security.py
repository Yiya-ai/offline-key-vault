"""Reject unsafe MAC schemes before calling the native PKCS#12 parser."""
from unittest.mock import patch
import pytest
from asn1crypto import pkcs12 as ap
from cryptography.hazmat.primitives import serialization as S
from cryptography.hazmat.primitives.serialization import pkcs12
from keyvault import keys
from keyvault.import_guard import check_der


@pytest.fixture
def pfx():
    key = keys.generate('Ed25519')
    blob = pkcs12.serialize_key_and_certificates(b'synthetic', key, None, None,
        S.BestAvailableEncryption(b'synthetic password'))
    return ap.Pfx.load(blob, strict=True)


@pytest.mark.parametrize('mutation', ['missing', 'pbmac1', 'unknown', 'short-digest', 'empty-salt', 'huge-salt', 'iterations'])
def test_unsafe_mac_rejected_before_native(pfx, mutation):
    if mutation == 'missing':
        del pfx['mac_data']
    elif mutation in ('pbmac1', 'unknown'):
        pfx['mac_data']['mac']['digest_algorithm']['algorithm'] = '1.2.840.113549.1.5.14' if mutation == 'pbmac1' else '1.2.3.4'
    elif mutation == 'short-digest':
        pfx['mac_data']['mac']['digest'] = b'x'
    elif mutation == 'empty-salt':
        pfx['mac_data']['mac_salt'] = b''
    elif mutation == 'huge-salt':
        pfx['mac_data']['mac_salt'] = b'x' * 1025
    else:
        pfx['mac_data']['iterations'] = 2000001
    with patch('keyvault.keys.pkcs12.load_key_and_certificates') as native:
        with pytest.raises(ValueError):
            keys.import_key(pfx.dump(), 'synthetic password')
        native.assert_not_called()


def test_mac_work_included_in_total_budget(pfx):
    # Exercise check_der's complete budget, without performing costly KDFs.
    # Empty bags let both encrypted safes be visited; only the MAC pushes work over.
    from asn1crypto import cms
    pfx['mac_data']['iterations'] = 2000000
    safe = cms.ContentInfo({'content_type': 'encrypted_data', 'content': {
        'version': 0, 'encrypted_content_info': {'content_type': 'data',
        'content_encryption_algorithm': {'algorithm': 'aes256_cbc', 'parameters': b'x' * 16},
        'encrypted_content': b'x' * 16}}})
    pfx['auth_safe']['content'] = ap.AuthenticatedSafe([safe, safe]).dump()
    with patch('keyvault.import_guard.decrypt_checked', return_value=(lambda password: ap.SafeContents([]).dump(), 2000000)):
        with pytest.raises(ValueError, match='累计'):
            check_der(pfx.dump(), b'synthetic password')


def test_ordinary_pfx_still_accepted(pfx):
    check_der(pfx.dump(), b'synthetic password')
    assert keys.algorithm(keys.import_key(pfx.dump(), 'synthetic password')) == 'Ed25519'
