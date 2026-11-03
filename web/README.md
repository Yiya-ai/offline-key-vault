# Browser Key Toolbox

[简体中文](README.zh-CN.md) · [Desktop application](../README.md)

A static, Chinese-language browser companion to Offline Key Vault. Generate,
inspect, convert, compare and download keys for the current session. There is
no vault, account, database, upload API or saved history. The desktop app stays
offline and does not depend on this website.

The previously identified WASM dependency blocker was resolved on 2026-11-03 by
building cryptography 50.0.2 against OpenSSL 3.6.5 from verified official sources.
All 15 Python runtime dependencies pass the advisory check at that date; the
gate remains enabled. This is not a guarantee against undiscovered vulnerabilities.
See the [security report](security_best_practices_report.md).

## Run and build

Use Python 3.12+, Node.js 22+ and Docker with Linux containers. From the repository root:

```sh
npm ci --prefix web --ignore-scripts
python web/build_wasm.py
python web/build_web.py --fetch
python web/verify_build.py
python -m http.server 8766 --bind 127.0.0.1 --directory web/dist
```

Open `http://127.0.0.1:8766/`. The first three commands download public development
dependencies only; subsequent builds can omit `--fetch`. Dependencies are pinned
in both lockfiles, and downloaded Python artifacts have SHA-256 checks. Build
output is exclusively `web/dist/`; the builder never reads vaults or settings.
The WASM build is required only when the reviewed wheel is not already cached.
It sends only the allowlisted public build context to Docker, never mounts the
repository or user directories, and verifies the resulting wheel's locked SHA-256.
See the [WASM build recipe](wasm-build/README.md).

Deploy **only the contents of `web/dist/`** to a trusted HTTPS static host. No
backend, environment secrets, database or server-side key parser is needed.
Do not deploy the repository, `web/.vendor`, tests, `node_modules` or local output.
Keep the asset directory and its manifest together when updating a deployment.
Do not inject analytics, CDN optimization scripts, service workers or third-party
widgets. Prefer a dedicated origin with no existing service workers. For a host
that supports response headers, add `frame-ancestors 'none'` and
`X-Content-Type-Options: nosniff`; the page already rejects framed operation.

The public runtime is approximately 18 MB. A fresh page must load it before key
input is enabled. Once ready, it can operate with the network disconnected.
This is not an installable offline PWA: closing the page discards its session.
Chrome/Edge desktop is the locally tested browser family; Firefox and Safari
still need native-browser validation. HTTPS or localhost is required.

For GitHub Pages, choose **Settings → Pages → Source → GitHub Actions**, then
manually run **Deploy browser toolbox (manual)** after the browser checks below.
The workflow audits source, builds and verifies only the static tree, and deploys
that artifact. It is never triggered automatically by an ordinary code push.
No remote publication is performed by the local build command.
The workflow builds the patched WASM wheel before assembling the static site.
Do not remove dependency checks or accept a new binary hash without review.

## Features and compatibility

- Generate RSA 2048/3072/4096, NIST ECDSA, secp256k1, Ed25519/Ed448,
  X25519/X448, SM2 and OpenPGP RSA-3072 keys.
- Import/export supported PEM, DER, headerless Base64 DER, PKCS#1, SEC1,
  OpenSSH, JWK, PPK v2/v3, OpenPGP and raw X25519 encodings.
- Inspect PKCS#12/PFX and JKS entries, export attached X.509 certificates,
  certificate collections, P7B and SSH certificates. JKS entries can be selected
  individually. JKS/PFX export preserves the certificates read with the key.
- Import bounded legacy PEM encryption, PBES1, 3DES, RC2 and scrypt containers.
- Compare derived public parameters, distinguish parse/password errors from a
  mismatch, preview public/private content and download with a chosen filename.
- Download the original input byte-for-byte. Re-encoding can change wrapping,
  comments, random check values, salts and ciphertext without changing the key.

Formats are algorithm-dependent. Traditional PKCS#1/SEC1, JWK and raw private
exports require an explicit plaintext choice. JKS and PPK v2 are compatibility
formats with weaker password protection; prefer encrypted PKCS#8 or PPK v3.
SM2 PFX support is limited to a single key without certificates; SM2 X.509
certificate parsing is not exposed by the cryptography runtime. Inputs are
limited to 128 KiB. Unknown/unsafe algorithms, oversized KDF parameters,
multi-private-key PFX and OpenPGP v5/v6 are rejected. No certificate issuance,
trust-chain building or online revocation checks are performed.
PFX must have a bounded SHA-family MAC with a correctly sized digest and salt.
Missing-MAC/PBMAC1 containers are refused before native parsing. MAC work counts
toward the cumulative KDF budget; some previously accepted containers now fail.

Vault management/recovery/destruction, arbitrary filesystem default paths and
native PKCS#11 drivers belong to the desktop app. A browser cannot load the
desktop's native token driver. Download locations are controlled by the browser.

## Privacy and security boundary

1. The disabled page loads public code from its own host and verifies runtime
   asset sizes/hashes. A restrictive CSP is then added **before** creating the
   calculation worker and enabling key input. No remote runtime/CDN requests
   are needed during use. A hash manifest detects inconsistent assets, not a
   compromised host that can change both the code and manifest.
2. The Blob worker inherits `connect-src 'none'`. Its fetch implementation serves
   only preloaded public bytes from memory, with no network fallback. Other
   network APIs are disabled. User input is JSON data passed to fixed functions,
   never executable Python. Cryptography runs in the worker's WASM memory.
3. No cookies, localStorage, sessionStorage, IndexedDB, OPFS or filesystem mounts
   persist keys, passwords or results. No analytics, telemetry or error uploads.
   The website host may still log IP addresses and initial static-asset requests.
4. Clear, page exit/refresh and five minutes of inactivity discard session state.
   Clear terminates the worker and revokes download URLs. Operations exceeding
   two minutes are terminated. Downloads are intentional local copies.
   Browser suspension can delay timers; focus, visibility and first activity
   check expiry before reuse. Blur/navigation conceals private previews and
   visible passwords. Sensitive fields disable spellchecking/autocorrection;
   browser extensions and cloud input methods remain outside this protection.
5. Managed memory and operating-system swap cannot be reliably physically erased
   by this page. Clipboard contents and downloaded files remain under user/OS
   control. Browser extensions, the browser, device, hosting account and delivered
   code remain trusted components. This is not an independently audited product.

Do not relax CSP to `unsafe-eval` for compatibility. If the runtime cannot start
or an asset fails validation, key input stays disabled. See [dependency notices](THIRD_PARTY.md).
An existing Service Worker controller also blocks startup. Controller changes
terminate the session without silently unregistering other applications.
After bootstrap, new stylesheets are blocked as well as network fetches.
Before enabling key input, the worker checks the actual cryptography/OpenSSL
versions loaded into WASM. Renaming an old wheel or changing its metadata does
not bypass that check. The deployment verifier also binds wheel bytes to the
reviewed dependency lock, independently of generated asset manifests.

Release checks (development network access only):

```sh
npm audit --prefix web --audit-level=low
python web/audit_dependencies.py --online
python web/verify_build.py
python web/tests/test_build_security.py
```

The OSV check sends only public package names and locked versions; it sends no
project content or key material. Any advisory, failed query or incomplete result
blocks release. It is not included in the deployed application. The complete
deployment manifest rejects extra nested files, changed bytes, and linked files;
it is an integrity check, not a signature authenticating the hosting provider.

## Verification

The scripts in `tests/` use disposable synthetic keys only. To reproduce browser
checks, serve `web` (instead of `web/dist`) on localhost port 8767, open `/dist/`
with Playwright CLI, and run these files in the same browser session:

```sh
python web/tests/make_fixtures.py
python -m http.server 8767 --bind 127.0.0.1 --directory web
# In another terminal:
npx --yes --package @playwright/cli playwright-cli -s=key-web open http://127.0.0.1:8767/dist/ --headed
npx --yes --package @playwright/cli playwright-cli -s=key-web run-code --filename=web/tests/browser-matrix.js
npx --yes --package @playwright/cli playwright-cli -s=key-web run-code --filename=web/tests/browser-runtime.js
npx --yes --package @playwright/cli playwright-cli -s=key-web run-code --filename=web/tests/browser-formats.js
npx --yes --package @playwright/cli playwright-cli -s=key-web run-code --filename=web/tests/browser-fixtures.js
npx --yes --package @playwright/cli playwright-cli -s=key-web run-code --filename=web/tests/browser-security.js
npx --yes --package @playwright/cli playwright-cli -s=key-web run-code --filename=web/tests/browser-layout.js
npx --yes --package @playwright/cli playwright-cli -s=key-web run-code --filename=web/tests/browser-lifecycle.js
npx --yes --package @playwright/cli playwright-cli -s=key-web run-code --filename=web/tests/browser-isolation.js
npx --yes --package @playwright/cli playwright-cli -s=key-web run-code --filename=web/tests/browser-audit.js
python web/tests/test_argon_adapter.py
```

The fixture generator uses the desktop development dependencies (`vendor` or
installed equivalents). `browser-matrix.js` installs a test-only Worker capture
hook; this hook is not part of the website. Results are available in the CLI's
console log and `window.__matrix`, `__formats`, `__fixtures`, `__security`.
The extended checks expose `__auditResults` and `__isolation` in the test page only.
`browser-runtime.js` downloads a hash-pinned public old wheel in the Node test
harness to verify rejection; no application input is sent. Its `__runtimeChecks`
summarizes actual version checks and downgrade rejection. This test is not shipped.
Stop the test server afterwards; never publish its synthetic fixture directory.
Any result with `ok:false` is a failure. Native Argon2 reference checks cover
all three variants and 1/2/4/16 lanes; the browser adapter preserves lanes while
executing with one native thread. See the [Argon2 binding API](https://argon2-cffi.readthedocs.io/en/stable/api.html#argon2.low_level.core).

The manual deployment workflow verifies build contents and dependency advisories;
it does not claim to replace the browser interaction checks above.
