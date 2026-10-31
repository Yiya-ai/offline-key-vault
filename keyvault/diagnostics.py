"""Offline portable diagnostics: synthetic keys only, no user vault access."""
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import tkinter as tk


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run():
    from . import keys
    from .vault import Vault, AuthenticationError, VaultDestroyed
    from .app import Application
    import cryptography, bcrypt, asn1crypto, cffi, pycparser, _tkinter
    import pgpy, jks, Cryptodome, argon2, pyasn1, pyasn1_modules, javaobj, _argon2_cffi_bindings
    try:
        import PyKCS11
    except ModuleNotFoundError as error:
        if error.name != 'PyKCS11': raise
        PyKCS11 = None
    frozen = bool(getattr(sys, 'frozen', False))
    portable = frozen or (Path(sys.executable).parent / 'python312._pth').is_file()
    if portable:
        bundle = Path(sys.executable).resolve().parent.parent
        for path in sys.path:
            require(Path(path).resolve().is_relative_to(bundle), 'External import path')
        for module in (cryptography, bcrypt, asn1crypto, cffi, pycparser, _tkinter, tk, json, pgpy, jks, Cryptodome, argon2, PyKCS11, pyasn1, pyasn1_modules, javaobj, _argon2_cffi_bindings):
            if module is None: continue
            require(Path(module.__file__).resolve().is_relative_to(bundle), 'External runtime module')
    try:
        sock = socket.socket()
    except PermissionError:
        pass
    else:
        sock.close()
        raise RuntimeError('Network policy missing')
    password = secrets.token_urlsafe(32)
    changed = secrets.token_urlsafe(32)
    for name in keys.ALGORITHMS:
        key = keys.generate(name)
        data = keys.export_private(key, 'OpenPGP' if name.startswith('OpenPGP') else 'PEM', password)
        require(keys.normalized(keys.import_key(data, password)) == keys.normalized(key), 'Key roundtrip failed')
    key = keys.generate('Ed25519')
    from .paircheck import compare, PairCheckError
    from .preferences import Preferences, export_filename
    pair_public = keys.export_public(key, 'PEM')
    pair_private = keys.export_private(key, 'PEM', password)
    require(compare(pair_public, pair_private, password)['matched'], 'Pair check failed')
    try:
        compare(pair_public, pair_private)
    except PairCheckError as error:
        require(error.side == 'private' and error.reason == 'password_required', 'Pair password diagnostic failed')
    else:
        raise RuntimeError('Encrypted private key accepted without password')
    require(export_filename('sample key', '.pem') == 'sample key.pem', 'Export filename failed')
    ssh = keys.export_private(key, 'OpenSSH', password)
    require(keys.normalized(keys.import_key(ssh, password)) == keys.normalized(key), 'SSH roundtrip failed')
    ppk = keys.export_private(key, 'PPK-v3', password)
    require(keys.normalized(keys.import_key(ppk, password)) == keys.normalized(key), 'PPK roundtrip failed')
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from .material import cert_bundle, export_attachment, import_items
    rsa_key = keys.generate('RSA-2048')
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'offline-diagnostic')])
    now = datetime.now(timezone.utc)
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(rsa_key.public_key()).serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(rsa_key, hashes.SHA256())
    record = {'name': 'diagnostic', 'attachments': cert_bundle(rsa_key, [cert]).attachments}
    jks_blob = export_attachment(record, 'JKS', rsa_key, password)
    require(keys.fingerprint(import_items(jks_blob, password)[0]) == keys.fingerprint(rsa_key), 'JKS roundtrip failed')
    p12 = export_attachment(record, 'PKCS12', rsa_key, password)
    require(keys.fingerprint(keys.import_key(p12, password)) == keys.fingerprint(rsa_key), 'P12 roundtrip failed')
    # The temporary directory contains only this invocation's synthetic data.
    with tempfile.TemporaryDirectory(prefix='okv-selftest-', dir=Path(tempfile.gettempdir()).resolve()) as temporary:
        directory = Path(temporary)
        preferences = Preferences(directory / 'synthetic-preferences.json')
        preferences.save(directory)
        require(Preferences(preferences.path).export_directory() == str(directory), 'Export preferences failed')
        vault = Vault()
        try:
            path = directory / 'synthetic.okv'
            vault.create(path, password)
            rid, _ = vault.add(key, 'diagnostic', 'self-test', 'synthetic only')
            vault.export(rid, directory / 'encrypted.pem', 'PEM', True, password, changed)
            vault.change_password(password, changed)
            vault.close()
            vault.open(path, changed)
            require(len(vault.records()) == 1, 'Vault roundtrip failed')
            from .protection import DESTROY_CONFIRMATION
            recovery_password = secrets.token_urlsafe(32)
            factor = directory / 'synthetic.okvr'
            vault.configure_security(changed, 5, confirmation=DESTROY_CONFIRMATION,
                                     recovery_password=recovery_password, recovery_path=factor)
            vault.close()
            vault.recover(path, recovery_password, factor, password)
            require(len(vault.records()) == 1, 'Two-factor recovery failed')
            for _ in range(4):
                try:
                    vault.verify('synthetic wrong password')
                except AuthenticationError:
                    pass
                else:
                    raise RuntimeError('Invalid credential accepted')
            try:
                vault.verify('synthetic wrong password')
            except VaultDestroyed:
                pass
            else:
                raise RuntimeError('Synthetic destruction failed')
            require(not vault.unlocked, 'Destroyed vault remained open')
            try:
                vault.recover(path, recovery_password, factor, changed)
            except VaultDestroyed:
                pass
            else:
                raise RuntimeError('Destroyed vault recovered')
        finally:
            vault.close()
    window = tk.Tk()
    window.withdraw()
    app = Application(window)
    errors = []
    window.report_callback_exception = lambda *args: errors.append(True)
    window.update()
    app.quit()
    require(not errors, 'GUI callback failed')
    print(json.dumps({'ok': True, 'portable': portable, 'algorithms': len(keys.ALGORITHMS),
                      'ssh': True, 'ppk': True, 'jks': True, 'p12': True, 'pkcs11_module': PyKCS11 is not None, 'vault': True, 'two_factor_recovery': True, 'self_destruction': True, 'gui': True, 'key_pair_check': True, 'pair_password_diagnostic': True, 'export_preferences': True, 'network_blocked': True}))
