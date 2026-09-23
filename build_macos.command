#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
# OKV_PYTHON can name a pre-installed, trusted CPython 3.12 interpreter.
"${OKV_PYTHON:-python3}" -I -S build_macos.py
