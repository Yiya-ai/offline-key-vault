# Offline Key Vault

**English** | [简体中文](README.zh-CN.md)

A local desktop application for generating, organizing, importing and exporting public/private keys. The current interface is in Chinese. The application stores records in an encrypted local vault and provides standalone public/private-key conversion and key-pair matching tools.

The application has no upload, telemetry, online update or automatic dependency-download feature. It does not run a web server or listen on a port. Native libraries and the operating system remain part of the trust boundary; see [Security and privacy](#security-and-privacy).

## Project status

Application icons are generated locally from the same artwork for Windows executables, shortcuts and windows, and for the macOS app bundle. Older installations need the updated package to receive these icons.

| Component | Status |
| --- | --- |
| Windows x64 | Locally tested with CPython 3.12 and Tk; intended for Windows 10/11 x64. Clean installations of every target OS have not been tested. |
| Windows portable package | Built and tested locally after extraction. The public standard profile excludes PyKCS11 and retains bundled license notices. |
| macOS 15+ | Separate Apple Silicon and Intel DMGs; native CI gates installation and self-tests before release. Ad-hoc signed, not Developer ID signed or notarized. |
| Hardware tokens | Generic PKCS#11 interface retained; standard Windows and macOS binaries omit PyKCS11. Offline source setup is required; no physical-device validation. |
| Security assurance | Local tests and source review, not an independent security audit or a guarantee against all vulnerabilities. |

## Features

- Generate a key pair and manage its name, tags and notes in an encrypted vault.
- Import supported key text or local files; recognize standard Base64 DER without PEM headers.
- Convert public- or private-key text to a file without creating or unlocking a vault.
- Export the private key belonging to the selected record. Public-only records cannot produce a private key.
- Check whether a public key and a private key match, including across supported encodings, without saving them to a vault.
- Use the record name as the default export filename and configure separate default vault, import and export directories. Existing files are not overwritten.
- Create encrypted backups, change the master passphrase and lock with Ctrl+L or after five minutes of inactivity.
- Optionally configure failed-attempt destruction and two-factor passphrase recovery.

## Supported algorithms and formats

Generation supports RSA-2048/3072/4096, ECDSA P-256/P-384/P-521/secp256k1, Ed25519/Ed448, X25519/X448, SM2 and an OpenPGP RSA-3072 primary key with an encryption subkey. The default is Ed25519. RSA-1024 is accepted only for legacy public-key import/conversion.

| Format | Scope and important restrictions |
| --- | --- |
| PEM / DER | SPKI public keys and PKCS#8 private keys; encrypted private-key export is supported. |
| Bare Base64 DER | Import/conversion of supported ASN.1 keys; not a separate key algorithm. |
| RSA PKCS#1 / EC SEC1 | Import/export for applicable algorithms; this application's private-key export requires explicit plaintext consent. |
| OpenSSH | Public and private keys for supported RSA, Ed25519 and NIST ECDSA keys; encrypted private-key export uses bcrypt. |
| JWK | One RSA, EC or OKP key; private JWK export is plaintext. No JWKS, symmetric keys or remote JKU/X5U fetching. |
| PKCS#12 / PFX | One private key with associated certificates; encrypted export, including private-key-only export. Multiple private keys are rejected. |
| OpenPGP | Supported v4 keys, identities and subkeys; ASCII/binary export. Not a byte-for-byte archive of every original signature. |
| PuTTY PPK | v2/v3 for supported keys; v2 is for legacy compatibility. |
| JKS | Private keys and trusted certificates, separate store/entry passphrases, certificate retention; legacy protection. No JCEKS/BKS. |
| X.509 and certificate collections | Preserve imported certificates; export certificate PEM, PEM collections or P7B. No issuance, trust-path construction or online revocation checks. |
| SSH certificates | Import, signature checking and original-certificate export. A valid signature does not establish CA trust. |
| X25519 raw Base64 / Base64url | Explicit raw 32-byte key mode; private raw export requires plaintext consent. |
| Legacy encrypted containers | Import traditional PEM encryption headers, supported PBES1/3DES and scrypt containers within resource limits. |
| PKCS#11 | Explicit local driver selection, public-key enumeration, RSA key generation and signing checks. Private token values are not exported. |

Not every algorithm is valid in every format. Unknown algorithms, DSA, RSA-1024 private keys, OpenPGP v5/v6, PPK v1 and excessive KDF parameters are rejected. A filename extension does not convert a format. See [COMPATIBILITY.md](COMPATIBILITY.md) (Chinese) for exact variants and limits.

## Run locally

### Windows portable build

If you have a trusted, locally built `dist/offline-key-vault-windows-x64.zip`, extract the entire archive into a normal local directory and launch `OfflineKeyVault.exe` or `launch.cmd`. The destination computer does not need Python, pip or administrator privileges. The launcher uses the Windows .NET Framework 4.x runtime.

Do not launch from inside the ZIP or store the application, vault or exports in a network share, linked directory or cloud-synced folder. Download verified assets from [GitHub Releases](https://github.com/Yiya-ai/offline-key-vault/releases).

- `self-test.cmd`: run offline checks using temporary synthetic keys.
- `verify.cmd`: verify package hashes. Hashes detect changes; they do not authenticate a publisher.
- To upgrade, extract a new copy and open the existing `.okv` vault. Preserve vaults and exports before removing an old application folder.

### Source setup

Use a trusted Windows x64 CPython 3.12 installation with Tk and the exact dependencies in [requirements.txt](requirements.txt). Prepare compatible wheels separately, then install only from a local wheel directory:

```powershell
python prepare_vendor.py .\wheelhouse
python -I -S launch.py
```

`wheelhouse` is a placeholder local folder you must populate. `prepare_vendor.py` uses pip with `--no-index`, `--no-deps` and binary-only inputs; it does not download missing packages. The runtime entry point disables automatic site initialization and installs its offline audit hook before importing application modules.

### Build a Windows portable package

With the local dependencies ready, run `build_portable.cmd` or:

```powershell
python -I -S build_portable.py
```

The builder copies allowlisted application files, the local Python/Tk runtime, selected dependencies and license notices. It does not download or upload anything. It tests the actual extracted package in a relocated path, checks runtime isolation and rejects corrupted or incomplete packages before writing the final ZIP to `dist/`.

For macOS 15+, download the matching arm64 or x86_64 DMG, open it and drag the app into Applications. No separate Python installation is needed. These builds are **not notarized**; see [MACOS.md](MACOS.md) for first-launch approval, native build checks and platform-specific security limits.

## Desktop installer and interaction improvements

The Windows standard installer uses bounded retries when creating a new output file temporarily returns access denied or a sharing error. It never overwrites an existing file, never retries a partially written stream, and fails if access remains denied. The earlier intermittent failure could not be reproduced consistently; no antivirus or system protection change is required. Published versions and verified download assets are listed in [GitHub Releases](https://github.com/Yiya-ai/offline-key-vault/releases).

On Windows, open `dist/offline-key-vault-setup.exe`. Choose a new local installation folder (typing or local directory browsing) and select whether to create desktop and Start menu shortcuts. Installation is offline and per-user, with no administrator requirement. Existing folders and shortcuts are never overwritten; upgrades use a new folder and reopen the existing vault. The installer does not launch the application automatically. To remove a version, first move any vaults/exports you placed inside it, then remove that application folder and its shortcuts. There is no system-service or registry installation.

Build the portable ZIP first, then run `python -I -S build_installer.py`, or use `build_installer.cmd` for both steps. The builder tests actual extraction, installed-runtime checks, shortcut targets and overwrite refusal inside an isolated test directory; it does not create real desktop shortcuts during verification. The installer is unsigned and retains the same third-party distribution-license requirements as the portable bundle.

The public standard package does **not** bundle PyKCS11. For hardware tokens, prepare the pinned dependency from trusted offline wheels and build a local portable version with `python -I -S build_portable.py --with-pkcs11`. It produces a separate `-local-pkcs11.zip` artifact; its GPL distribution obligations must be handled separately before sharing. Do not copy dependencies directly into an installed standard package: its integrity check rejects extra files. The application does not download optional dependencies.

Settings now provide separate vault, key-import and key-export directories. Path inputs refresh local directory listings after a short typing delay; no Go click is required. Saving a dialog always resolves the latest typed path. Password/PIN fields start masked and use an inline eye icon; moving focus outside the field and its eye control masks the value again. Mouse wheels scroll the control under the pointer or its surrounding form.

Primary actions use red, secondary buttons have subtle rounded surfaces, and destructive actions use a soft-red treatment. Input fields, focus indicators and scrollbars share the same styling, including the installer. Forms wrap descriptions and long names to the available width. Window resizing scales text, controls, icons and spacing by a uniform ratio; the client area retains its initial aspect ratio with no letterboxing. Resize from one of the four corners; side-only resizing and maximizing are disabled. The zoom floor is 80%; the dashboard uses 12 pt body/navigation text and a 10 pt minimum, while dense tool dialogs retain an 8 pt minimum. Sidebar footer information and detail actions use the available window height. Two-column tools stack in narrow windows; action buttons remain outside the scrolling form. Scrollbars appear only when content overflows; keyboard focus brings off-screen fields into view. Default paths use inline browse controls, and the hardware-token dialog groups connection, public-key and generation controls. Layout regression checks cover 100%, 150% and 200% Tk font scaling; native Mac CI covers Tk interaction; manual Retina, touchpad and all-display-scale acceptance remains outstanding.

The locked-screen **Key text to file** tool accepts public or private keys. Standard private-key output is encrypted by default; raw/plaintext output requires explicit consent. `Original` preserves the validated input bytes and their existing encryption state; it does not add a new passphrase.

Single-record imports now retain original input bytes inside the authenticated encrypted vault. **Export imported original** rechecks the master passphrase and restores those bytes, including line endings and existing encryption. Ordinary exports preserve key material but may change encoding or encrypted ciphertext. Old records and multi-record containers have no saved original; re-import a single original document if exact restoration is required. Imported-original records require this application version or newer; back up before upgrading and do not reopen them in older versions.

OpenSSH re-export also regenerates random check values, may change Base64 wrapping and padding, and currently drops the original SSH comment. These differences do not change the key pair. Choose **Export imported original** when byte-for-byte preservation is required; selecting the same format alone does not preserve the original file.

**View key contents** displays the stored public key. Revealing the normalized plaintext private key requires the master passphrase; it hides after 60 seconds and closes immediately when the vault locks. The application does not automatically copy it, but explicitly visible content can be selected/copied by the user or captured by other software.

## Basic workflow

1. Create a vault in a non-synced local directory and choose a strong master passphrase of at least 12 characters. Length alone does not guarantee strength.
2. Generate or import a key, assign a name/tags/notes, and let the application save it in the encrypted vault.
3. Export the selected public key or re-enter the master passphrase to export its corresponding private key. Encrypted private-key exports require a separate export passphrase.
4. For matching checks, supply the public and private key and the private file's export passphrase when encrypted. Parse/decryption failure means the match is undetermined, not that the keys differ. Private inputs and passphrases are cleared after the check.
5. Save encrypted backups to separate offline media. Historical backups retain their original passphrases and recovery settings.

Matching compares actual public-key parameters. Two OpenPGP inputs compare the primary key and the complete subkey set; cross-format OpenPGP comparisons cover the primary key only. Certificates supply public keys for comparison, not a trust decision. Ordinary fingerprints use SHA-256 of SPKI DER and differ from SSH wire-format fingerprints.

## Encrypted files can still be read and copied

A text editor can display an encrypted PEM file's header and Base64 ciphertext. Copying that text creates another encrypted copy; the original passphrase is still needed to recover the private key. Changing the extension or deleting `ENCRYPTED` from a header does not decrypt it.

For this application's PKCS#8 PEM exports, `BEGIN ENCRYPTED PRIVATE KEY` denotes encrypted output and `BEGIN PRIVATE KEY` denotes plaintext output. Other formats have different markers; their first line alone may not identify encryption.

**Selecting explicit plaintext export clears and disables the export-passphrase fields.** The UI requests confirmation, and the resulting file is unencrypted. JWK, raw private keys and this application's traditional PKCS#1/SEC1 exports require that option. Protect exported files separately; changing the vault passphrase cannot protect or revoke old exports.

## Failed-attempt protection and recovery

Both features must be configured after unlocking the vault. Destruction is off by default; enabling it requires confirmation and a threshold of 5–100 consecutive authentication failures. At the threshold, the current vault is replaced with a destruction marker and both credential wrappers are removed.

Recovery requires a **recovery passphrase plus an independent recovery file**, configured before access is lost and stored separately. Recovery sets a new master passphrase; it does not reveal the old one. This is two-factor recovery, not two-factor authentication on every normal unlock.

Saving security settings upgrades an OKV1 vault to OKV2; older application versions cannot open it. Destruction is logical removal from the current managed file, not secure erasure of SSD history, backups, snapshots or exports. Someone with filesystem access can copy/roll back the vault or attack a copy offline; failure counting cannot prevent that. Someone able to submit repeated wrong passphrases can deliberately trigger destruction. See [SECURITY_RECOVERY.md](SECURITY_RECOVERY.md) (Chinese).

## Security and privacy

- Vault records use AES-256-GCM, random salts/nonces and scrypt with fixed parameters. Encrypted PKCS#8 export uses PBKDF2-HMAC-SHA256 with 600,000 iterations and AES-256-CBC; that export format does not provide the vault's GCM authentication.
- Imports are limited to 128 KiB, vaults to 16 MiB / 1,000 records, and KDF work/memory parameters are bounded before expensive processing.
- Windows creates sensitive files with a protected current-user DACL and checks local volumes, links and path components. Targets without persistent ACL support are refused. macOS checks local volumes and removes inherited ACLs before writing sensitive files with mode 0600. POSIX path-race limits and remaining manual checks are documented in MACOS.md.
- The application does not log private keys, passphrases or PINs or automatically copy them to the clipboard. Python/Tcl/OpenSSL memory copies, a compromised OS, administrators and other processes are outside complete application control.
- The optional path preferences store only the selected vault, import and export directories in `.offline-key-vault-preferences.json`, with current-user file protection. Paths and export filenames can disclose personal or business information even when key contents are encrypted. Clear any directory field in Settings to restore its default. Old export-only settings are read automatically.
- No application upload or telemetry feature exists. Python audit hooks block covered network/process calls, but do not sandbox native code or stop a separate cloud-sync client. Strict offline operation requires a disconnected device or independently enforced OS isolation.
- PKCS#11 drivers are executable native code. Select only trusted local drivers; a digest alone is not publisher authentication. Windows holds checked driver and parent handles through loading to block replacement. Equivalent mandatory locking on macOS and real-device testing remain outstanding.

See [SECURITY.md](SECURITY.md) for bilingual reporting guidance. Do not send real keys, vaults, recovery files, passphrases, personal paths or sensitive screenshots in an issue or support request.

## Tests and source release checks

Full tests require local pytest (previously validated with 9.0.3), Tk and an interactive Windows desktop:

```powershell
python -I -S run_tests.py
python -I -S tools/release.py audit
python -I -S tools/release.py source
```

Tests generate synthetic keys under `test-results/`; never use real keys as fixtures. The source ZIP and SHA-256 file are written to `dist/`. Source packaging uses the exact allowlist in `tools/release_manifest.json`, not the entire working directory.

Before a release:

1. Review documentation, changes and dependency licenses; run the local test suite and actual portable-package checks where applicable.
2. Keep vaults, recovery files, exports, preferences, screenshots, logs, caches, dependencies and build/test outputs outside the published source. Ignore rules and the source allowlist enforce these exclusions.
3. In a local Git repository, use `python -I -S tools/release.py stage`, then `python -I -S tools/release.py audit --index` and `git diff --cached --check`. Review staged content and any existing history manually.
4. Confirm the exact destination and explicit publication authorization before any commit/push or upload. The tools do not commit, configure a remote or upload.

The push/PR workflow checks source privacy patterns, the index allowlist and Python syntax. A separate manually dispatched macOS workflow builds both native DMGs, runs cryptography/GUI regressions and installation self-tests, then produces artifacts for review. Public Releases are published separately. Pattern checks are not proof that every possible secret is absent. Further release details are in [RELEASING.md](RELEASING.md) (Chinese).

## Contributing and license

See the bilingual [contribution guide](CONTRIBUTING.md). Original project source and documentation are licensed under [MIT](LICENSE). Dependencies retain their own licenses.

**Optional PyKCS11 1.5.18 is GPL-2.0-or-later. Neither the Windows nor macOS public standard package bundles it.** A local token build that adds this dependency requires resolving combined-distribution obligations and providing the applicable complete corresponding source and notices before redistribution. A wheel or upstream link alone does not fulfill those obligations. Standard packages retain component-specific licenses; do not describe the entire bundle as MIT. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) (Chinese).
