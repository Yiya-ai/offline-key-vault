# Browser distribution dependencies

The website includes unchanged Pyodide 314.0.7 runtime assets (MPL-2.0) and its
CPython standard library (PSF license). The Pyodide loader is bundled with the
application; corresponding upstream source is available at
https://github.com/pyodide/pyodide/tree/314.0.7 and the published npm package
`pyodide@314.0.7`. Dependency versions, public URLs and SHA-256 digests are pinned
in `dependencies.lock.json` and `package-lock.json`.

Browser cryptography uses a locally built cryptography 50.0.2 wheel, statically
linked to OpenSSL 3.6.5 (Apache-2.0). Both official source archives and their
SHA-256 digests are recorded in `wasm-build/sources.json`; the build recipe is
published with this project. The browser verifies the loaded versions before
accepting keys. OpenSSL's license is included as `OpenSSL-LICENSE.txt`.
The remaining native dependencies use Pyodide's bcrypt, argon2-cffi and
PyCryptodome builds, with ASN1Crypto, PGPy, PyJKS, javaobj-py3, pyasn1,
pyasn1-modules and standard-imghdr. Package licenses are copied into this folder.
The pure Python source shipped to the browser is available in
`assets/python-code.zip`. PyJKS import statements are adapted from `Cryptodome`
to Pyodide's equivalent `Crypto` namespace by `build_web.py`; its algorithm code
is unchanged. PGPy compatibility aliases are confined to the browser adapter.

SM2 key derivation uses the custom Weierstrass interface of @noble/curves 2.4.0
(MIT) with the standard SM2 domain parameters. PKCS#12 compatibility uses the
PKCS#12 KDF from node-forge 1.4.2 (BSD-3-Clause / GPL-2.0 dual license; distributed
under BSD-3-Clause). No new elliptic-curve arithmetic or password KDF is authored
by this project. PyKCS11 is not included in the browser distribution.

This project's MIT license does not replace dependency licenses. Runtime files
are not fetched from third-party domains while the website is being used.
