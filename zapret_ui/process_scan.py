"""Read-only Windows process enumeration without spawning a helper process."""
from __future__ import annotations

import ctypes
from functools import lru_cache
import os


TH32CS_SNAPPROCESS = 0x00000002
ERROR_NO_MORE_FILES = 18
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_WINWS_NAMES = frozenset(("winws.exe", "winws2.exe"))


class PROCESSENTRY32W(ctypes.Structure):
    # DWORD/LONG remain 32-bit on Win64; ULONG_PTR follows the pointer size.
    _fields_ = [
        ("dwSize", ctypes.c_uint32),
        ("cntUsage", ctypes.c_uint32),
        ("th32ProcessID", ctypes.c_uint32),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", ctypes.c_uint32),
        ("cntThreads", ctypes.c_uint32),
        ("th32ParentProcessID", ctypes.c_uint32),
        ("pcPriClassBase", ctypes.c_int32),
        ("dwFlags", ctypes.c_uint32),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


class _Kernel32:
    def __init__(self):
        library = ctypes.WinDLL("kernel32", use_last_error=True)
        self.CreateToolhelp32Snapshot = library.CreateToolhelp32Snapshot
        self.CreateToolhelp32Snapshot.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
        self.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        for name in ("Process32FirstW", "Process32NextW"):
            function = getattr(library, name)
            function.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
            function.restype = ctypes.c_int32
            setattr(self, name, function)
        self.CloseHandle = library.CloseHandle
        self.CloseHandle.argtypes = [ctypes.c_void_p]
        self.CloseHandle.restype = ctypes.c_int32
        self.last_error = ctypes.get_last_error


@lru_cache(maxsize=1)
def _native_api():
    return _Kernel32()


def _error(operation, code):
    return OSError(code, f"Не удалось проверить процессы zapret: {operation} (Win32 {code}).")


def _read_snapshot(api, snapshot):
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    pids = []
    operation = "Process32FirstW"
    while True:
        if not getattr(api, operation)(snapshot, ctypes.byref(entry)):
            code = api.last_error()
            if code == ERROR_NO_MORE_FILES:
                return pids
            raise _error(operation, code)
        if entry.szExeFile.casefold() in _WINWS_NAMES:
            pids.append(int(entry.th32ProcessID))
        operation = "Process32NextW"


def _scan(api):
    snapshot = api.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot in (None, 0, INVALID_HANDLE_VALUE):
        raise _error("CreateToolhelp32Snapshot", api.last_error())
    try:
        pids = _read_snapshot(api, snapshot)
    except BaseException:
        # Keep the original enumeration error even if cleanup also fails.
        try:
            api.CloseHandle(snapshot)
        except Exception:
            pass
        raise
    if not api.CloseHandle(snapshot):
        raise _error("CloseHandle", api.last_error())
    return pids


def winws_process_ids() -> list[int]:
    """Return exact winws.exe/winws2.exe PIDs, or fail closed on a scan error."""
    if os.name != "nt":
        raise OSError("Перечисление процессов zapret поддерживается только в Windows.")
    return _scan(_native_api())
