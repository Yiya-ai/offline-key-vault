# Browser validation / 浏览器版验证

Local verification on 2026-11-03, Windows, Chromium browser. All key inputs were
generated synthetic fixtures; no user vault or real private key was used.

**Identified dependency blocker resolved / 已修复此前依赖阻断项。** The browser
loads source-built cryptography 50.0.2 with OpenSSL 3.6.5; all 15 Python runtime
packages pass the advisory check (exit 0). No advisory exceptions were added.
The workflow was not run remotely and no public deployment was performed.
See the [security report](security_best_practices_report.md).

| Check / 检查 | Result / 结果 |
| --- | --- |
| Algorithm generation → encrypted export → import → matching | 13/13 passed |
| Supported algorithm/format export and import combinations | 82/82 passed |
| Native fixtures, legacy encryption, certificates, JKS/PFX roundtrips, unsafe MAC/PGP rejection | 31/31 passed |
| Export/preview gates, matching, original preservation, network/storage, offline UI | 27/27 passed |
| Five views at 1440/1024/768/390/320 px | 25/25 without horizontal overflow |
| Idle clear, worker state removal, reload, tampered-asset refusal | 5/5 passed |
| New race, hidden-secret, suspended-clock, CSP, spellcheck and input-error regressions | 22/22 passed |
| Real iframe and Service Worker isolation / clear cannot bypass | 3/3 passed |
| Deployment contamination and advisory-response regressions | 9/9 passed |
| Actual binary versions / old binary renamed as new / incorrect OpenSSL policy | 4/4 passed |
| Source release allowlist regressions after adding isolated build recipe | 24/24 passed |
| Separate WASM source compilations | Identical SHA-256; documented in wasm-build/README.md |
| Native PFX MAC guard / budget checks | 9/9 passed (included in complete project suite) |
| Native Argon2 comparison | 12 variant/lane combinations matched; excessive work rejected |
| Native parser reads browser downloads | Ed25519 and SM2 encrypted PKCS#8 accepted; wrong password rejected |
| Complete project suite from initial audit (shared key implementation unchanged in WASM follow-up) | 348 passed, 4 platform skips |
| npm dependency advisory audit | 0 reported vulnerabilities at test time |
| Python dependency advisory audit (15 packages) | No matches after pyasn1 0.6.5 and cryptography 50.0.2 upgrades; exit 0 |
| Static package / source privacy audit | Passed; no test keys, runtime history or personal home paths in project source |

The source allowlist audit covers only explicitly listed source files. The built tree and nested runtime
archives were also scanned for this workstation's personal home-path identifiers:
no matches. Those identifiers, local browser logs and test data are not copied
into this public report. A clean build passes the static-tree verifier; this does
not override the separate dependency gate; both checks must pass.

Desktop and mobile screenshots were visually inspected locally, including
generation, conversion, comparison and password-eye controls. Screenshots,
browser logs and generated test keys are excluded from publication.

桌面与手机截图已本地查看，覆盖生成、转换、校对和密码小眼睛；截图、浏览器日志和测试密钥不发布。

These results are not an independent audit. Firefox, Safari, physical hardware
tokens and a live public hosting deployment were not tested in this local run.
The browser's SM2 PFX fallback handles single-key, certificate-free containers.
Memory clearing does not promise physical erasure of browser/OS memory or swap.

以上结果不等于独立安全审计。此次未实测 Firefox、Safari、实体硬件令牌或公网部署；
SM2 PFX 限于无证书的单密钥容器，清空不保证物理擦除浏览器/系统内存或交换区。
