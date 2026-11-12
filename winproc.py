"""ctypes Win32 helpers for process liveness, RSS, shared reads, and single-instance mutexes. No process termination APIs; minimal fallbacks support tests on other platforms."""
from __future__ import annotations

import ctypes
import os
import time
from ctypes import wintypes

IS_WIN = os.name == "nt"

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
STILL_ACTIVE = 259
ERROR_ACCESS_DENIED = 5
ERROR_ALREADY_EXISTS = 183
GENERIC_READ = 0x80000000
FILE_SHARE_ALL = 0x1 | 0x2 | 0x4  # READ | WRITE | DELETE
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
LIVE_CACHE_S = 10.0

if IS_WIN:
    import msvcrt

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _psapi = ctypes.WinDLL("psapi", use_last_error=True)
    _INVALID_HANDLE = wintypes.HANDLE(-1).value

    _OpenProcess = _kernel32.OpenProcess
    _OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    _OpenProcess.restype = wintypes.HANDLE

    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = (wintypes.HANDLE,)
    _CloseHandle.restype = wintypes.BOOL

    _GetExitCodeProcess = _kernel32.GetExitCodeProcess
    _GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    _GetExitCodeProcess.restype = wintypes.BOOL

    _GetProcessTimes = _kernel32.GetProcessTimes
    _GetProcessTimes.argtypes = (wintypes.HANDLE,) + (ctypes.POINTER(wintypes.FILETIME),) * 4
    _GetProcessTimes.restype = wintypes.BOOL

    _GetCurrentProcess = _kernel32.GetCurrentProcess
    _GetCurrentProcess.argtypes = ()
    _GetCurrentProcess.restype = wintypes.HANDLE

    _CreateFileW = _kernel32.CreateFileW
    _CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    _CreateFileW.restype = wintypes.HANDLE

    _CreateMutexW = _kernel32.CreateMutexW
    _CreateMutexW.argtypes = (wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR)
    _CreateMutexW.restype = wintypes.HANDLE

    class _PMC(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    _GetProcessMemoryInfo = _psapi.GetProcessMemoryInfo
    _GetProcessMemoryInfo.argtypes = (wintypes.HANDLE, ctypes.POINTER(_PMC), wintypes.DWORD)
    _GetProcessMemoryInfo.restype = wintypes.BOOL


def _ft_int(ft) -> int:
    return (ft.dwHighDateTime << 32) | ft.dwLowDateTime


def filetime_to_ms(ft: int) -> int:
    return ft // 10_000 - 11_644_473_600_000


def process_create_filetime(pid: int) -> int | None:
    """Creation time as FILETIME, or None if unavailable."""
    if not IS_WIN:
        return None
    h = _OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not h:
        return None
    try:
        c, e, k, u = (wintypes.FILETIME() for _ in range(4))
        if not _GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)):
            return None
        return _ft_int(c)
    finally:
        _CloseHandle(h)


def check_alive(pid: object, proc_start: object = None, started_at_ms: object = None) -> bool | None:
    """True for a matching live process; False for death or PID reuse; None for access denial."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    if not IS_WIN:
        return None
    h = _OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None if ctypes.get_last_error() == ERROR_ACCESS_DENIED else False
    try:
        code = wintypes.DWORD()
        if not _GetExitCodeProcess(h, ctypes.byref(code)):
            return None
        if code.value != STILL_ACTIVE:
            return False
        c, e, k, u = (wintypes.FILETIME() for _ in range(4))
        if not _GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)):
            return None
        created = _ft_int(c)
    finally:
        _CloseHandle(h)
    if proc_start not in (None, ""):
        try:
            return int(proc_start) == created
        except (TypeError, ValueError):
            pass
    if isinstance(started_at_ms, (int, float)) and started_at_ms > 0:
        return abs(filetime_to_ms(created) - int(started_at_ms)) <= 2000
    return True


class LivenessCache:
    """Ten-second cache per PID."""

    def __init__(self, ttl_s: float = LIVE_CACHE_S):
        self.ttl = ttl_s
        self._c: dict[tuple, tuple[float, bool | None]] = {}

    def check(self, pid, proc_start, started_at_ms) -> bool | None:
        key = (pid, proc_start)
        now = time.monotonic()
        hit = self._c.get(key)
        if hit and now - hit[0] < self.ttl:
            return hit[1]
        val = check_alive(pid, proc_start, started_at_ms)
        self._c[key] = (now, val)
        if len(self._c) > 512:
            self._c = {k: v for k, v in self._c.items() if now - v[0] < self.ttl}
        return val


def rss_mb() -> float | None:
    if not IS_WIN:
        return None
    pmc = _PMC()
    pmc.cb = ctypes.sizeof(_PMC)
    if not _GetProcessMemoryInfo(_GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
        return None
    return round(pmc.WorkingSetSize / (1024 * 1024), 1)


def peak_rss_mb() -> float | None:
    if not IS_WIN:
        return None
    pmc = _PMC()
    pmc.cb = ctypes.sizeof(_PMC)
    if not _GetProcessMemoryInfo(_GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
        return None
    return round(pmc.PeakWorkingSetSize / (1024 * 1024), 1)


def open_shared(path: object):
    """Read-only raw file with READ, WRITE, and DELETE sharing so atomic replacement remains possible. All source reads use this function; callers close promptly with a context manager."""
    if not IS_WIN:
        return open(path, "rb", buffering=0)
    h = _CreateFileW(str(path), GENERIC_READ, FILE_SHARE_ALL, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    if h is None or h == _INVALID_HANDLE:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(h, os.O_RDONLY | os.O_BINARY)
    except OSError:
        _CloseHandle(h)
        raise
    return os.fdopen(fd, "rb", buffering=0)


def acquire_single_instance(name: str):
    """Return None if already held; retain the handle for process lifetime."""
    if not IS_WIN:
        return object()
    h = _CreateMutexW(None, False, name)
    err = ctypes.get_last_error()
    if not h:
        return object()  # Continue if mutex creation fails; binding still detects collisions.
    if err == ERROR_ALREADY_EXISTS:
        _CloseHandle(h)
        return None
    return h
