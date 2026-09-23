"""Reproduce parser/password failures without using the user's keys or clipboard."""
import pytest
from keyvault import keys
from keyvault.paircheck import compare, PairCheckError

PASSWORD = 'synthetic exported file password'


@pytest.fixture(scope='module')
def pair():
    key = keys.generate('RSA-2048')
    return keys.export_public(key, 'PEM'), keys.export_private(key, 'PEM', PASSWORD)


def test_missing_export_password_identifies_private_side(pair):
    public, private = pair
    with pytest.raises(PairCheckError) as result:
        compare(public, private)
    assert result.value.side == 'private' and result.value.reason == 'password_required'
    assert '导出文件时设置' in str(result.value) and '尚未判断是否匹配' in str(result.value)
    assert compare(public, private, PASSWORD)['matched']


def test_incorrect_password_is_not_mismatch_or_input_echo(pair):
    public, private = pair
    with pytest.raises(PairCheckError) as result:
        compare(public, private, 'synthetic wrong password')
    assert result.value.side == 'private' and result.value.reason == 'parse'
    assert '尚未判断是否匹配' in str(result.value)
    assert 'synthetic wrong password' not in str(result.value)
    assert private.decode().splitlines()[1] not in str(result.value)


@pytest.mark.parametrize('side', ['public', 'private'])
def test_truncated_pem_identifies_side(pair, side):
    public, private = pair
    if side == 'public': public = public[:public.index(b'-----END')]
    else: private = private[:private.index(b'-----END')]
    with pytest.raises(PairCheckError) as result:
        compare(public, private, PASSWORD)
    assert result.value.side == side and result.value.reason == 'incomplete'
    assert 'BEGIN' in str(result.value) and 'END' in str(result.value)


@pytest.mark.parametrize('variant', ['crlf', 'bom', 'literal_newline', 'spaces', 'tabs', 'single_line'])
def test_complete_pem_paste_variants(pair, variant):
    def transform(value):
        if variant == 'crlf': return value.replace(b'\n', b'\r\n')
        if variant == 'bom': return b'\xef\xbb\xbf' + value
        if variant == 'literal_newline': return value.replace(b'\n', b'\\n')
        lines = value.strip().splitlines()
        if variant == 'single_line': return b' '.join(lines)
        separator = b' ' if variant == 'spaces' else b'\t'
        body = separator.join(b''.join(lines[1:-1])[i:i+10] for i in range(0,len(b''.join(lines[1:-1])),10))
        return lines[0] + b'\n' + body + b'\n' + lines[-1]
    assert compare(transform(pair[0]), transform(pair[1]), PASSWORD)['matched']


def test_mixed_objects_and_trailing_junk_stay_rejected(pair):
    public, private = pair
    for blob in (public + private, public + b'extra data', public.replace(b'-----END PUBLIC KEY-----', b'-----END PRIVATE KEY-----')):
        with pytest.raises(PairCheckError): compare(blob, private, PASSWORD)
    with pytest.raises(PairCheckError): compare(public, private + private, PASSWORD)


def test_valid_mismatch_is_a_result(pair):
    other = keys.export_public(keys.generate('RSA-2048'), 'DER')
    assert compare(other, pair[1], PASSWORD)['matched'] is False


def test_binary_der_bytes_and_plaintext_password_diagnostic():
    key = keys.generate('Ed25519')
    public = keys.export_public(key, 'DER')
    private = keys.export_private(key, 'DER', plaintext=True)
    assert compare(public, private)['matched']
    with pytest.raises(PairCheckError): compare(public + b' ', private)
    private_pem = keys.export_private(key, 'PEM', plaintext=True)
    with pytest.raises(PairCheckError) as result: compare(public, private_pem, PASSWORD)
    assert result.value.side == 'private' and '留空' in str(result.value)
