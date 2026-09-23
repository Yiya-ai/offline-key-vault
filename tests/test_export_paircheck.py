import base64
import json
from pathlib import PureWindowsPath
from unittest.mock import patch
import pytest
from cryptography.hazmat.primitives import serialization as S
from keyvault import keys
from keyvault.paircheck import compare
from keyvault.preferences import Preferences, export_filename


@pytest.mark.parametrize('name,expected', [('生产服务器','生产服务器.pem'),('server.pem','server.pem'),('api.v1','api.v1.pem'),('../a:b/c','_a_b_c.pem'),('CON','_CON.pem'),('aux.txt','_aux.txt.pem'),(' .. ','key.pem'),('a\x00b','a_b.pem')])
def test_safe_export_filename(name, expected):
    result = export_filename(name, '.pem')
    assert result == expected
    assert not PureWindowsPath(result).is_reserved()
    assert '/' not in result and chr(92) not in result


def test_long_unicode_filename_is_bounded():
    name = '中文' * 120
    a = export_filename(name, '.pub')
    b = export_filename(name+'a', '.pub')
    assert len(a.encode()) < 200 and a != b and a.endswith('.pub')


def test_preferences_persist_clear_and_reject_network(tmp_path):
    config = tmp_path/'prefs.json'
    prefs = Preferences(config)
    assert prefs.export_directory() == ''
    directory = tmp_path/'导出目录'; directory.mkdir()
    prefs.save(directory)
    assert Preferences(config).export_directory() == str(directory)
    assert set(json.loads(config.read_bytes())) == {'format','export_directory'}
    before = config.read_bytes()
    with pytest.raises(ValueError): prefs.save(r'\\example.invalid\keys')
    assert config.read_bytes() == before
    prefs.save('')
    assert Preferences(config).export_directory() == ''


def test_preferences_no_silent_fallback_for_corrupt_or_unsafe_settings(tmp_path):
    config=tmp_path/'prefs.json'; prefs=Preferences(config)
    config.write_bytes(b'{"format":"OKV-PREFERENCES1","export_directory":"","export_directory":"bad"}')
    with pytest.raises(ValueError): prefs.load()
    config.write_text(json.dumps({'format':'OKV-PREFERENCES1','export_directory':r'\\host\share'}))
    with pytest.raises(ValueError): prefs.export_directory()


@pytest.mark.parametrize('algorithm', ['RSA-2048','ECDSA-P256','Ed25519','Ed448','X25519','X448','SM2'])
def test_pair_matches_and_mismatches_by_material(algorithm):
    private=keys.generate(algorithm); other=keys.generate(algorithm)
    pub=keys.export_public(private,'PEM'); secret=keys.export_private(private,'PEM','synthetic export password')
    result=compare(pub,secret,'synthetic export password')
    assert result['matched'] and result['public_fingerprint']==result['derived_fingerprint']
    assert not compare(keys.export_public(other,'DER'),secret,'synthetic export password')['matched']
    assert set(result)=={'matched','scope','public_algorithm','private_algorithm','public_fingerprint','derived_fingerprint'}


def test_formats_and_roles_and_password_errors():
    private=keys.generate('Ed25519')
    pub=keys.export_public(private,'OpenSSH')
    for fmt in ('OpenSSH','PPK-v2','PPK-v3','PEM','DER'):
        secret=keys.export_private(private,fmt,'synthetic export password')
        assert compare(pub,secret,'synthetic export password')['matched']
        with pytest.raises(ValueError): compare(pub,secret,'incorrect')
    secret=keys.export_private(private,'PEM',plaintext=True)
    with pytest.raises(ValueError,match='公钥输入中包含私钥'): compare(secret,secret)
    with pytest.raises(ValueError,match='私钥输入只有公钥'): compare(pub,pub)
    assert compare(keys.export_public(private,'JWK'),secret)['matched']
    encoded=base64.b64encode(keys.export_public(private,'DER'))
    assert compare(encoded,secret)['matched']


def test_raw_x25519_and_different_algorithms():
    private=keys.generate('X25519')
    assert compare(keys.export_public(private,'Raw-base64'),keys.export_private(private,'Raw-base64',plaintext=True),raw=True)['matched']
    assert not compare(keys.export_public(keys.generate('Ed25519'),'PEM'),keys.export_private(private,'PEM',plaintext=True))['matched']


def test_openpgp_public_metadata_does_not_change_key_match():
    private=keys.generate('OpenPGP-RSA3072')
    pub=keys.export_public(private,'OpenPGP')
    secret=keys.export_private(private,'OpenPGP','synthetic export password')
    result=compare(pub,secret,'synthetic export password')
    assert result['matched'] and '子密钥' in result['scope']
    native=private.key._key.keymaterial.__pubkey__()
    assert compare(native.public_bytes(S.Encoding.PEM,S.PublicFormat.SubjectPublicKeyInfo),secret,'synthetic export password')['matched']


def test_preferences_write_failure_preserves_old_settings(tmp_path):
    prefs=Preferences(tmp_path/'prefs.json'); prefs.save(tmp_path)
    before=prefs.path.read_bytes()
    with patch('keyvault.preferences.atomic_replace',side_effect=OSError('synthetic fault')):
        with pytest.raises(OSError): prefs.save('')
    assert prefs.path.read_bytes()==before


def test_certificates_and_single_entry_containers():
    from datetime import datetime,timedelta,timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from keyvault.material import cert_bundle,export_attachment
    private=keys.generate('RSA-2048')
    name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'synthetic-pair-check')])
    now=datetime.now(timezone.utc)
    cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key()).serial_number(1).not_valid_before(now).not_valid_after(now+timedelta(days=1)).sign(private,hashes.SHA256())
    public=cert.public_bytes(S.Encoding.PEM)
    record={'name':'synthetic','attachments':cert_bundle(private,[cert]).attachments}
    for fmt in ('JKS','PKCS12'):
        container=export_attachment(record,fmt,private,'synthetic store password')
        assert compare(public,container,'synthetic store password')['matched']
    import jks
    trusted=jks.TrustedCertEntry.new('trusted',cert.public_bytes(S.Encoding.DER))
    public_store=jks.KeyStore.new('jks',[trusted]).saves('synthetic store password')
    secret=keys.export_private(private,'PEM',plaintext=True)
    assert compare(public_store,secret,public_password='synthetic store password')['matched']
    multiple=jks.KeyStore.new('jks',[trusted,jks.TrustedCertEntry.new('second',cert.public_bytes(S.Encoding.DER))]).saves('synthetic store password')
    with pytest.raises(ValueError,match='每侧只接受一把'):
        compare(multiple,secret,public_password='synthetic store password')
