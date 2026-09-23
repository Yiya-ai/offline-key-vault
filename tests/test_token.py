from unittest.mock import MagicMock
import pytest
import PyKCS11
from keyvault.token import PKCS11Token


def adapter():
    token = PKCS11Token.__new__(PKCS11Token)
    token.api = PyKCS11
    token.library = MagicMock()
    return token, token.library.openSession.return_value


def test_generated_private_key_is_nonextractable_and_sensitive():
    token, session = adapter()
    session.generateKeyPair.return_value = ('public', 'private')
    session.getAttributeValue.return_value = (True, False)
    identifier = token.generate_rsa(1, 'synthetic PIN', 'test', 3072)
    public, private, mechanism = session.generateKeyPair.call_args.args
    options = dict(private)
    assert options[PyKCS11.CKA_SENSITIVE] is True
    assert options[PyKCS11.CKA_EXTRACTABLE] is False
    assert options[PyKCS11.CKA_PRIVATE] is True
    assert PyKCS11.CKA_VALUE not in options
    assert len(bytes.fromhex(identifier)) == 20
    session.logout.assert_called_once()
    session.closeSession.assert_called_once()
    assert all(value != 'synthetic PIN' for value in vars(token).values())


def test_session_closed_when_signature_fails():
    token, session = adapter()
    session.findObjects.return_value = ['private']
    session.sign.side_effect = RuntimeError('synthetic failure')
    with pytest.raises(RuntimeError): token.sign_rsa_sha256(1, 'synthetic PIN', '012345', b'challenge')
    session.logout.assert_called_once()
    session.closeSession.assert_called_once()


def test_failed_login_is_not_retried():
    token, session = adapter()
    session.login.side_effect = RuntimeError('synthetic incorrect PIN')
    with pytest.raises(RuntimeError): token.public_keys(1, 'synthetic PIN')
    session.login.assert_called_once()
    session.logout.assert_not_called()
    session.closeSession.assert_called_once()


def test_driver_digest_checked_before_loading(tmp_path):
    path = tmp_path / 'fake.dll'; path.write_bytes(b'not a module')
    with pytest.raises(ValueError, match='SHA|摘要'): PKCS11Token(path, '0' * 64)
