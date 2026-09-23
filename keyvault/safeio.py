"""Local-only, owner-restricted, non-overwriting file I/O."""
import ctypes
import hashlib
import hmac
import time
import os
from pathlib import Path, PureWindowsPath
from contextlib import contextmanager
import stat
import uuid


class StorageError(ValueError):
    pass


def _lexical_path(value):
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or any(ord(c) < 32 for c in raw):
        raise StorageError('路径为空或包含控制字符')
    normalized = raw.replace('/', chr(92)) if os.name == 'nt' else raw
    if normalized.startswith(chr(92) * 2) or raw.startswith('//'):
        raise StorageError('只允许本地磁盘路径，不允许网络共享或设备路径')
    if os.name == 'nt':
        pure = PureWindowsPath(normalized)
        for part in pure.parts:
            if part == pure.anchor or part in ('.', '..'):
                continue
            if part.endswith((' ', '.')) or any(c in part for c in '<>:"|?*') or PureWindowsPath(part).is_reserved():
                raise StorageError('不允许设备名称、备用数据流或含歧义的文件名')
    p = Path(os.path.abspath(raw))
    if os.name == 'nt':
        if str(p).startswith(chr(92) * 2) or ctypes.windll.kernel32.GetDriveTypeW(str(p.anchor)) not in (2, 3, 6):
            raise StorageError('只允许本地磁盘，不允许网络或设备路径')
    return p


def _check_path(value, directory=False):
    p = _lexical_path(value)
    exists = False
    # Parents must be checked BEFORE any access through a possible junction.
    for part in [*reversed(p.parents), p]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise StorageError('不允许符号链接或重解析点路径')
        if part == p and not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
            raise StorageError('请选择本地目录' if directory else '请选择普通文件')
        if part == p:
            exists = True
        if part == p and not directory and info.st_nlink > 1:
            raise StorageError('不允许硬链接文件，请使用独立的普通文件')
    if os.name == 'nt':
        # Different 8.3 aliases must acquire the SAME adjacent lock file.
        target = p if exists else p.parent
        long_path = ctypes.create_unicode_buffer(32768)
        size = ctypes.windll.kernel32.GetLongPathNameW(str(target), long_path, len(long_path))
        if not size or size >= len(long_path):
            raise StorageError('无法取得规范本地路径')
        return Path(long_path.value) if exists else Path(long_path.value) / p.name
    return p


def _win_api():
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
    kernel.CreateFileW.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    return kernel


def _check_handle(handle, directory=False):
    from ctypes import wintypes as w
    class Info(ctypes.Structure):
        _fields_ = [('attributes', w.DWORD), ('creation', w.FILETIME), ('access', w.FILETIME),
                    ('write', w.FILETIME), ('volume', w.DWORD), ('size_hi', w.DWORD),
                    ('size_lo', w.DWORD), ('links', w.DWORD), ('index_hi', w.DWORD), ('index_lo', w.DWORD)]
    kernel = _win_api()
    kernel.GetFileInformationByHandle.argtypes = [w.HANDLE, ctypes.POINTER(Info)]
    info = Info()
    if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    if info.attributes & 0x400 or bool(info.attributes & 0x10) != directory or (not directory and info.links != 1):
        raise StorageError('文件句柄类型不安全：链接、重解析点或文件类型不符')


@contextmanager
def pinned_path(value, directory=False):
    """Pin ancestors without FILE_SHARE_DELETE before accessing children."""
    p = _lexical_path(value)
    handles = []
    try:
        if os.name == 'nt':
            from ctypes import wintypes as w
            kernel = _win_api()
            ancestors = [*reversed(p.parents)] + ([p] if directory else [])
            for part in ancestors:
                # OPEN_REPARSE_POINT prevents following a replaced directory link.
                # FILE_LIST_DIRECTORY participates in delete sharing; attributes-only does not.
                handle = kernel.CreateFileW(str(part), 0x1, 3, None, 3, 0x02200000, None)
                if handle == w.HANDLE(-1).value:
                    raise ctypes.WinError(ctypes.get_last_error())
                handles.append(handle)
                _check_handle(handle, directory=True)
        yield _check_path(p, directory=directory)
    finally:
        if os.name == 'nt':
            kernel = _win_api()
            for handle in reversed(handles):
                kernel.CloseHandle(handle)


def local_path(value, directory=False):
    with pinned_path(value, directory=directory) as p:
        return p


def _require_acl_volume(path):
    from ctypes import wintypes as w
    kernel = _win_api()
    kernel.GetVolumeInformationW.argtypes = [w.LPCWSTR, w.LPWSTR, w.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(w.DWORD), w.LPWSTR, w.DWORD]
    flags = w.DWORD()
    if not kernel.GetVolumeInformationW(str(path.anchor), None, 0, None, None, ctypes.byref(flags), None, 0):
        raise ctypes.WinError(ctypes.get_last_error())
    if not flags.value & 8:  # FILE_PERSISTENT_ACLS
        raise StorageError('目标文件系统不支持访问权限保护，请使用 NTFS 等支持 ACL 的本地磁盘')


def _win_open_private(path, existing=False):
    from ctypes import wintypes as w
    import msvcrt
    _require_acl_volume(path)
    adv = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    adv.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
    adv.GetTokenInformation.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD)]
    adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(w.LPWSTR)]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR, w.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(w.DWORD)]
    token, count, sidtext, sd = w.HANDLE(), w.DWORD(), w.LPWSTR(), ctypes.c_void_p()
    if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(count))
        buf = ctypes.create_string_buffer(count.value)
        if not adv.GetTokenInformation(token, 1, buf, count, ctypes.byref(count)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        if not adv.ConvertSidToStringSidW(sid, ctypes.byref(sidtext)):
            raise ctypes.WinError(ctypes.get_last_error())
        sddl = 'D:P(A;;FA;;;' + sidtext.value + ')'
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(sd), None):
            raise ctypes.WinError(ctypes.get_last_error())

        class SA(ctypes.Structure):
            _fields_ = [('nLength', w.DWORD), ('lpSecurityDescriptor', ctypes.c_void_p), ('bInheritHandle', w.BOOL)]

        sa = SA(ctypes.sizeof(SA), sd, False)
        kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.POINTER(SA), w.DWORD, w.DWORD, w.HANDLE]
        kernel.CreateFileW.restype = w.HANDLE
        handle = kernel.CreateFileW(str(path), 0xC0000000, 3 if existing else 0, ctypes.byref(sa), 4 if existing else 1, 0x200080, None)
        if handle == w.HANDLE(-1).value:
            error = ctypes.get_last_error()
            if error in (80, 183):
                raise FileExistsError('目标文件已存在，请使用新文件名')
            raise ctypes.WinError(error)
        try:
            _check_handle(handle)
            return msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
        except BaseException:
            kernel.CloseHandle(handle)
            raise
    finally:
        if sd:
            kernel.LocalFree(sd)
        if sidtext:
            kernel.LocalFree(ctypes.cast(sidtext, ctypes.c_void_p))
        kernel.CloseHandle(token)


def private_fd(path, existing=False):
    with pinned_path(path) as p:
        if os.name == 'nt':
            return _win_open_private(p, existing)
        fd = os.open(p, os.O_RDWR | os.O_CREAT | (0 if existing else os.O_EXCL) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0), 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            os.close(fd)
            raise StorageError('不允许非普通文件或硬链接')
        return fd


def write_new(path, data):
    with pinned_path(path) as p:
        fd = private_fd(p)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            p.unlink(missing_ok=True)
            raise


def read_limited(path, limit):
    with pinned_path(path) as p:
        if os.name == 'nt':
            import msvcrt
            from ctypes import wintypes as w
            kernel = _win_api()
            handle = kernel.CreateFileW(str(p), 0x80000000, 1, None, 3, 0x200080, None)
            if handle == w.HANDLE(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                _check_handle(handle)
                fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            except BaseException:
                kernel.CloseHandle(handle)
                raise
        else:
            fd = os.open(p, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise StorageError('只允许独立的普通文件')
            data = stream.read(limit + 1)
    if len(data) > limit:
        raise StorageError('文件过大，已拒绝读取')
    return data


def atomic_replace(path, data, expected_digest=None):
    with pinned_path(path) as p:
        if expected_digest is None:
            expected_digest = hashlib.sha256(read_limited(p, 16 * 1024 * 1024)).digest()
        temp = p.with_name('.' + p.name + '.' + uuid.uuid4().hex + '.tmp')
        try:
            write_new(temp, data)
            for attempt in range(5):
                # Retry only transient Windows replace failures; keep parents pinned.
                # Revalidate both paths and the original contents on EVERY attempt.
                local_path(temp)
                current = hashlib.sha256(read_limited(p, 16 * 1024 * 1024)).digest()
                if not hmac.compare_digest(current, expected_digest):
                    raise StorageError('磁盘文件已被外部修改，未覆盖原文件')
                try:
                    os.replace(temp, p)
                    return
                except OSError as error:
                    if os.name != 'nt' or getattr(error, 'winerror', None) not in (5, 32, 33) or attempt == 4:
                        raise
                    time.sleep(0.03 * (2 ** attempt))
        finally:
            temp.unlink(missing_ok=True)


class FileLock:
    def __init__(self, path):
        path = local_path(path)
        self.fd = private_fd(str(path) + '.lock', existing=True)
        try:
            if os.fstat(self.fd).st_size == 0:
                os.write(self.fd, b'0')
            os.lseek(self.fd, 0, 0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self.fd)
            self.fd = None
            raise StorageError('密钥库已被另一窗口打开，或无法取得文件锁') from None

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
