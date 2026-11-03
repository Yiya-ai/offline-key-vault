#!/usr/bin/env bash
set -euo pipefail
# Match the upstream Pyodide recipe, using patched, hash-verified source releases.
source "$(pyodide config get emsdk_dir)/emsdk_env.sh"
cd /build/openssl-3.6.5
emconfigure ./Configure linux-generic32 \
  no-shared no-asm no-engine no-dso no-tests no-srtp no-cms \
  no-ui-console no-threads --cross-compile-prefix= \
  CC=emcc AR=emar RANLIB=emranlib --prefix=/opt/openssl-wasm
emmake make -s -j 4 install_dev
export OPENSSL_DIR=/opt/openssl-wasm
export OPENSSL_STATIC=1
export OPENSSL_NO_VENDOR=1
cd /build/cryptography-50.0.2
mkdir -p /output
pyodide build --outdir /output
cp /build/sources.json /output/sources.json
cp /build/openssl-3.6.5/LICENSE.txt /output/OpenSSL-LICENSE.txt
python -m pip freeze > /output/build-tools.txt
rustc --version > /output/rust-version.txt
emcc --version > /output/emscripten-version.txt
