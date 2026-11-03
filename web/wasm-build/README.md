# Patched browser cryptography / 浏览器加密库构建

Pyodide 314.0.7's official package set still contains cryptography 47.0.0.
This recipe builds **cryptography 50.0.2 + OpenSSL 3.6.5** from unchanged official
sources for its `cp314-abi3-pyemscripten_2026_0_wasm32` ABI. It follows the
[upstream Pyodide cryptography recipe](https://github.com/pyodide/pyodide-recipes/blob/main/packages/cryptography/meta.yaml),
using patched sources instead of the old versions.

## Build

From the repository root, with Docker's Linux container engine available:

```sh
python web/build_wasm.py
# Force the same build/check even when the verified wheel is cached:
python web/build_wasm.py --rebuild
python web/build_web.py --fetch
python web/verify_build.py
```

The first build downloads public toolchains and sources and needs several GB
of Docker disk space. Only `web/wasm-build` is sent as Docker build context, with
an explicit `.dockerignore` allowlist. No project/vault/user directory is mounted.
The final image contains only public artifacts; it is created for extraction,
never started. Generated wheels stay in ignored `web/.vendor/` and are not source
release files. The website needs no Docker and downloads no dependencies from
third-party services during key operations.

## Locked inputs and checks

- Python build base: 3.14.2-bookworm, pinned OCI digest in Dockerfile.
- Pyodide cross environment: 314.0.7; Emscripten 5.0.3; Rust 1.93.0.
- pyodide-build 0.39.3; Maturin/CFFI/setuptools constraints in `build-constraints.txt`.
- OpenSSL and cryptography source URLs/SHA-256: `sources.json`.
- Rust dependency versions/checksums: the upstream cryptography source's Cargo.lock.
- Fixed `SOURCE_DATE_EPOCH`; build paths are generic container paths.
- Reviewed output SHA-256: `dependencies.lock.json`.

Two separate compilations on 2026-11-03 produced the same wheel digest:

```text
ce1ef4e6f407cbfd7cae378d25ec07a272d1dc4b01578ac72482560d064ca806
```

This is evidence for these builds, not a promise that every future build-tool
environment is identical. The wrapper refuses an unexpected digest. Never update
the locked hash merely to silence failure: review the changed inputs, inspect the
wheel, run dependency checks and all browser regressions first.

At startup, the worker asks the loaded binary for its actual cryptography and
OpenSSL versions. A regression substitutes the old 47.0.0 wheel under the new
filename and recomputes test asset hashes: startup still refuses key input.
OpenSSL's license and cryptography's licenses ship with the static application.

## 中文说明

这是公开源码编译，不是改文件名或忽略安全通告。两个来源压缩包先检查固定摘要，
然后在 Docker 内交叉编译，最后再次核对 WASM 成品摘要。构建不接触用户密钥。
首次需要下载编译工具并占用数 GB Docker 空间；已有校验通过的缓存可复用。

页面开放输入前读取实际运行库版本，旧库即使改名并重新生成资源清单，也不能通过
启动检查。两次独立编译已得到相同摘要；未来环境漂移产生不同摘要时会停止，不会自动放行。
升级版本须同时更新源码锁定信息、运行版本策略和对应测试，并保留漏洞检查。
