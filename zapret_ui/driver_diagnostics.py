"""Read-only, narrowly scoped diagnostics for the bundled WinDivert driver."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import ntpath
import os
from pathlib import Path
import re
import stat

from .windows_service import NATIVE_HASHES, STATES


SERVICE_KEY = r"SYSTEM\CurrentControlSet\Services\WinDivert"
MAX_NATIVE_SIZE = 32 * 1024 * 1024


def _unknown(error):
    return {"status": "unknown", "error": str(error)[:1000]}


def _capture(operation):
    try:
        return operation()
    except FileNotFoundError:
        return {"status": "missing"}
    except Exception as exc:
        return _unknown(exc)


def normalize_driver_path(value, system_root=None):
    """Accept local absolute paths only; never expand arbitrary environment data."""
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        return None
    value = value.strip()
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    value = value.replace("/", "\\")
    for prefix in ("\\??\\", "\\\\?\\"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    for prefix in ("\\systemroot\\", "%systemroot%\\"):
        if value.lower().startswith(prefix):
            root = normalize_driver_path(system_root) if system_root else None
            if root is None:
                return None
            value = root.rstrip("\\") + "\\" + value[len(prefix):]
            break
    if (not re.match(r"^[A-Za-z]:\\", value) or any(ord(char) < 32 for char in value)
            or any(char in value for char in '%"<>|?*') or ":" in value[2:]):
        return None
    parts = value[3:].split("\\")
    if any(part in (".", "..") or part.endswith((".", " ")) for part in parts):
        return None
    return ntpath.normpath(value)


def probe_file(path: Path, expected_hash=None):
    result = {"path": str(path), "expectedSha256": expected_hash}
    try:
        if str(path).startswith(("\\\\", "//")):
            raise ValueError("Сетевые пути не проверяются.")
        if os.name == "nt":
            drive = ntpath.splitdrive(str(path))[0]
            if not re.fullmatch(r"[A-Za-z]:", drive):
                raise ValueError("Требуется локальный абсолютный путь.")
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
            kernel.GetDriveTypeW.restype = wintypes.UINT
            if kernel.GetDriveTypeW(drive + "\\") not in (2, 3, 5, 6):
                raise ValueError("Сетевой или недоступный диск не проверяется.")
        for parent in reversed((path, *path.parents)):
            info = parent.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("Путь содержит ссылку или reparse point; чтение пропущено.")
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Путь не является обычным файлом.")
        result.update(status="present", size=info.st_size,
                      fileAttributes=getattr(info, "st_file_attributes", None))
        if expected_hash is not None:
            if info.st_size > MAX_NATIVE_SIZE:
                raise ValueError("Файл превышает допустимый размер диагностики.")
            digest, total = hashlib.sha256(), 0
            with path.open("rb") as source:
                while chunk := source.read(65536):
                    total += len(chunk)
                    if total > MAX_NATIVE_SIZE:
                        raise ValueError("Файл вырос во время чтения.")
                    digest.update(chunk)
            result.update(sha256=digest.hexdigest(), matches=digest.hexdigest() == expected_hash)
    except FileNotFoundError:
        result.update(status="missing")
    except Exception as exc:
        result.update(_unknown(exc))
    return result


class _ServiceStatus(ctypes.Structure):
    _fields_ = [(name, wintypes.DWORD) for name in
                ("type", "state", "controls", "exitCode", "serviceExitCode", "checkpoint", "waitHint", "pid", "flags")]


class _SystemInfo(ctypes.Structure):
    _fields_ = [("architecture", wintypes.WORD), ("reserved", wintypes.WORD), ("pageSize", wintypes.DWORD),
                ("minimumAddress", ctypes.c_void_p), ("maximumAddress", ctypes.c_void_p),
                ("processorMask", ctypes.c_size_t), ("processorCount", wintypes.DWORD),
                ("processorType", wintypes.DWORD), ("allocationGranularity", wintypes.DWORD),
                ("processorLevel", wintypes.WORD), ("processorRevision", wintypes.WORD)]


class WindowsReader:
    """System APIs only. No bundled DLL load, device open or mutating API exists here."""
    def __init__(self):
        if os.name != "nt":
            raise OSError("Диагностика драйвера доступна только в Windows.")
        import winreg
        self.reg = winreg
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        for name, args, result in (
                ("OpenSCManagerW", [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD], wintypes.HANDLE),
                ("OpenServiceW", [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD], wintypes.HANDLE),
                ("QueryServiceStatusEx", [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
                ("CloseServiceHandle", [wintypes.HANDLE], wintypes.BOOL)):
            function = getattr(self.advapi, name)
            function.argtypes, function.restype = args, result
        self.kernel.QueryDosDeviceW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        self.kernel.QueryDosDeviceW.restype = wintypes.DWORD
        self.kernel.GetNativeSystemInfo.argtypes = [ctypes.POINTER(_SystemInfo)]
        self.kernel.GetNativeSystemInfo.restype = None
        self.kernel.GetWindowsDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
        self.kernel.GetWindowsDirectoryW.restype = wintypes.UINT

    def registry(self):
        reg, values = self.reg, {}
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, SERVICE_KEY, 0, reg.KEY_QUERY_VALUE | reg.KEY_WOW64_64KEY) as key:
            for name in ("ImagePath", "Start", "Type", "DeleteFlag"):
                def read():
                    value, kind = reg.QueryValueEx(key, name)
                    valid = (kind in (reg.REG_SZ, reg.REG_EXPAND_SZ) and isinstance(value, str) and len(value) <= 4096
                             if name == "ImagePath" else kind == reg.REG_DWORD and type(value) is int)
                    if not valid:
                        raise ValueError("Недопустимый тип или размер параметра " + name)
                    return {"status": "present", "value": value, "registryType": kind}
                values[name] = _capture(read)
        return {"status": "present", "values": values}

    def service(self):
        scm = self.advapi.OpenSCManagerW(None, None, 0x1)  # SC_MANAGER_CONNECT
        if not scm:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            handle = self.advapi.OpenServiceW(scm, "WinDivert", 0x4)  # SERVICE_QUERY_STATUS
            if not handle:
                error = ctypes.get_last_error()
                if error == 1060:
                    raise FileNotFoundError("WinDivert не зарегистрирован в SCM.")
                raise ctypes.WinError(error)
            try:
                status, needed = _ServiceStatus(), wintypes.DWORD()
                if not self.advapi.QueryServiceStatusEx(handle, 0, ctypes.byref(status), ctypes.sizeof(status), ctypes.byref(needed)):
                    raise ctypes.WinError(ctypes.get_last_error())
                return {"status": "present", "state": STATES.get(status.state, "unknown"),
                        "nativeState": status.state, "serviceType": status.type,
                        "exitCode": status.exitCode, "serviceExitCode": status.serviceExitCode}
            finally:
                self.advapi.CloseServiceHandle(handle)
        finally:
            self.advapi.CloseServiceHandle(scm)

    def dos_device(self):
        buffer = ctypes.create_unicode_buffer(4096)
        count = self.kernel.QueryDosDeviceW("WinDivert", buffer, len(buffer))
        if not count:
            raise ctypes.WinError(ctypes.get_last_error())
        return {"status": "present", "targets": [value for value in buffer[:count].split("\0") if value][:8]}

    def architecture(self):
        info = _SystemInfo()
        self.kernel.GetNativeSystemInfo(ctypes.byref(info))
        return {"status": "present", "native": {0: "x86", 9: "x64", 12: "arm64", 6: "ia64"}.get(info.architecture, "unknown"),
                "code": info.architecture}

    def system_root(self):
        buffer = ctypes.create_unicode_buffer(4096)
        count = self.kernel.GetWindowsDirectoryW(buffer, len(buffer))
        if not count or count >= len(buffer):
            raise OSError("Не удалось определить каталог Windows.")
        return {"status": "present", "path": buffer.value}


def collect_driver_diagnostics(bundle: Path, *, adapter=None):
    result = {"schema": 1, "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "files": {name: probe_file(Path(bundle) / "bin" / name, expected)
                        for name, expected in NATIVE_HASHES.items()}}
    try:
        adapter = WindowsReader() if adapter is None else adapter
    except Exception as exc:
        result.update({name: _unknown(exc) for name in ("registry", "service", "dosDevice", "architecture", "systemRoot")})
    else:
        for key, operation in (("registry", adapter.registry), ("service", adapter.service),
                               ("dosDevice", adapter.dos_device), ("architecture", adapter.architecture),
                               ("systemRoot", adapter.system_root)):
            result[key] = _capture(operation)
    image = result["registry"].get("values", {}).get("ImagePath", {})
    registered = normalize_driver_path(image.get("value"), result["systemRoot"].get("path"))
    result["registeredDriverFile"] = (probe_file(Path(registered)) if registered and registered.lower().endswith(".sys") else
                                      _unknown("ImagePath недоступен или не является допустимым локальным абсолютным путём."))
    return result


def explain_driver_diagnostics(snapshot):
    facts = []
    for name, info in snapshot.get("files", {}).items():
        if info.get("status") == "missing":
            facts.append(f"В комплекте отсутствует {name}: {info.get('path', '')}.")
        elif info.get("status") == "present" and info.get("matches") is False:
            facts.append(f"Контрольная сумма {name} отличается от проверенной версии.")
    registered = snapshot.get("registeredDriverFile", {})
    if registered.get("status") == "missing":
        facts.append(f"В регистрации WinDivert указан отсутствующий файл: {registered.get('path', '')}.")
    if not facts:
        facts.append("Причина отказа WinDivert пока не подтверждена; нужны сведения из диагностики.")
    return " ".join(facts)
