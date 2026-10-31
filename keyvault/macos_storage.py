"""Darwin volume and private-file ACL checks through the bundled SDK bridge."""
import ctypes
import os
from pathlib import Path
import sys
from functools import lru_cache


@lru_cache(maxsize=1)
def api():
    if sys.platform != 'darwin':
        raise RuntimeError('macOS storage bridge is only available on macOS')
    path = (Path(sys._MEIPASS) / 'libokv_storage.dylib' if getattr(sys, 'frozen', False)
            else Path(__file__).resolve().parents[1] / 'build/libokv_storage.dylib')
    if not path.is_file():
        raise ValueError('缺少 macOS 本地存储保护组件；请使用完整安装包或先运行 build_macos.py --prepare-only')
    lib = ctypes.CDLL(str(path), use_errno=True)
    lib.okv_local_path.argtypes = [ctypes.c_char_p]
    lib.okv_local_path.restype = ctypes.c_int
    for name in ('okv_local_fd', 'okv_private_fd'):
        method = getattr(lib, name); method.argtypes = [ctypes.c_int]; method.restype = ctypes.c_int
    return lib


def check_path(path):
    if api().okv_local_path(os.fsencode(path)) != 1:
        raise ValueError('仅允许 macOS 本地卷，拒绝网络卷和自动挂载目录')


def check_fd(fd):
    if api().okv_local_fd(fd) != 1:
        raise ValueError('文件句柄不属于本地卷')


def restrict_fd(fd):
    check_fd(fd)
    if api().okv_private_fd(fd) != 0:
        raise ValueError('无法设置当前用户专用权限或移除继承 ACL，未写入密钥')
