"""Prepare an existing installation for replacement, without killing processes.

This entry point also works with the authenticated loopback API in version 0.2.
It never constructs a Controller, starts the engine, or changes Windows services.
"""
from __future__ import annotations

import ctypes
import hashlib
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import re
import socket
import struct
import time

from .process_scan import PROCESSENTRY32W, INVALID_HANDLE_VALUE, _native_api

APP_EXE = "ZapretByNerd3n.exe"
MAX_RESPONSE = 2 * 1024 * 1024


class UpdateError(RuntimeError):
    pass


class UpdateBlocked(UpdateError):
    pass


def _canonical(path: Path | str) -> str:
    return os.path.normcase(str(Path(path).resolve()))


def _process_paths() -> dict[int, str]:
    """Limited query access works across elevation levels, without termination rights."""
    api = _native_api()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int32, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                               ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32)]
    kernel.QueryFullProcessImageNameW.restype = ctypes.c_int32
    snapshot = api.CreateToolhelp32Snapshot(2, 0)
    if snapshot in (None, 0, INVALID_HANDLE_VALUE):
        raise ctypes.WinError(api.last_error())
    paths = {}
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        operation = api.Process32FirstW
        while operation(snapshot, ctypes.byref(entry)):
            if entry.szExeFile.casefold() == APP_EXE.casefold():
                handle = kernel.OpenProcess(0x1000, False, entry.th32ProcessID)
                if handle:
                    try:
                        buffer = ctypes.create_unicode_buffer(32768)
                        length = ctypes.c_uint32(len(buffer))
                        if kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(length)):
                            paths[int(entry.th32ProcessID)] = _canonical(buffer.value)
                    finally:
                        api.CloseHandle(handle)
                # A denied/disappeared process is never sent a shutdown request.
                # If it holds target files, the replacement probe fails closed.
            operation = api.Process32NextW
        if api.last_error() != 18:  # ERROR_NO_MORE_FILES
            raise ctypes.WinError(api.last_error())
    finally:
        api.CloseHandle(snapshot)
    return paths


def _listener_rows() -> list[tuple[int, int]]:
    api = ctypes.WinDLL("iphlpapi", use_last_error=True).GetExtendedTcpTable
    api.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_int32,
                    ctypes.c_uint32, ctypes.c_int32, ctypes.c_uint32]
    api.restype = ctypes.c_uint32
    size = ctypes.c_uint32()
    # AF_INET, TCP_TABLE_OWNER_PID_LISTENER; the table may grow between calls.
    for _ in range(4):
        buffer = ctypes.create_string_buffer(size.value) if size.value else None
        code = api(buffer, ctypes.byref(size), False, 2, 3, 0)
        if code == 122 and 4 <= size.value <= 16 * 1024 * 1024:
            continue
        if code != 0 or buffer is None:
            raise UpdateError(f"Не удалось прочитать TCP-порты: Win32 {code}.")
        data = buffer.raw
        count, = struct.unpack_from("<I", data)
        if 4 + count * 24 > len(data):
            raise UpdateError("Неполная таблица TCP-портов.")
        rows = []
        for index in range(count):
            state, address, port, _, _, pid = struct.unpack_from("<6I", data, 4 + index * 24)
            if state == 2 and struct.pack("<I", address) == b"\x7f\x00\x00\x01":
                rows.append((pid, socket.ntohs(port & 0xFFFF)))
        return rows
    raise UpdateError("Таблица TCP-портов изменяется; повторите установку.")


def candidate_ports(app_dir: Path) -> list[int]:
    expected = _canonical(app_dir / APP_EXE)
    processes = _process_paths()
    return sorted({port for pid, port in _listener_rows() if processes.get(pid) == expected})


def _request(port, method, path, token=None, timeout=2.0):
    # HTTPConnection connects directly: no environment proxy and no redirects.
    connection = HTTPConnection("127.0.0.1", port, timeout=timeout)
    headers = {"Origin": f"http://127.0.0.1:{port}"}
    body = None
    if method == "POST":
        body = b"{}"
        headers.update({"Content-Type": "application/json", "X-Zapret-Token": token})
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        if response.status != 200:
            raise UpdateError(f"Локальное приложение ответило HTTP {response.status}.")
        data = response.read(MAX_RESPONSE + 1)
        if len(data) > MAX_RESPONSE:
            raise UpdateError("Слишком большой ответ локального приложения.")
        value = json.loads(data)
        if not isinstance(value, dict):
            raise UpdateError("Некорректный ответ локального приложения.")
        return value
    finally:
        connection.close()


def request_exit(port: int, app_dir: Path, timeout=2.0) -> bool:
    state = _request(port, "GET", "/api/state", timeout=timeout)
    bundle = state.get("bundlePath")
    if not isinstance(bundle, str) or not Path(bundle).is_absolute():
        return False
    if _canonical(bundle) != _canonical(app_dir / "bundle"):
        return False
    session = _request(port, "GET", "/api/session", timeout=timeout)
    token = session.get("token")
    if not isinstance(token, str) or not 16 <= len(token) <= 512 or not token.isascii():
        raise UpdateError("Не удалось получить сеанс приложения для обновления.")
    _request(port, "POST", "/api/exit", token=token, timeout=timeout)
    return True


def _replacement_error(path: Path) -> int:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                   ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    kernel.CreateFileW.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int32
    # Request write/delete access but perform neither operation. A mapped EXE
    # can allow DELETE alone, hence GENERIC_WRITE is required for this probe.
    handle = kernel.CreateFileW(str(path), 0x40010000, 0, None, 3, 0, None)
    if handle == INVALID_HANDLE_VALUE:
        code = ctypes.get_last_error()
        return 0 if code in (2, 3) else code
    if not kernel.CloseHandle(handle):
        raise ctypes.WinError(ctypes.get_last_error())
    return 0


def blocked_files(app_dir: Path) -> list[tuple[Path, int]]:
    paths = {app_dir / APP_EXE}
    binary_dir = app_dir / "bundle" / "bin"
    if binary_dir.exists():
        paths.update(path for path in binary_dir.iterdir() if path.suffix.lower() in (".exe", ".dll", ".sys"))
    return [(path, code) for path in sorted(paths) if (code := _replacement_error(path))]


def _driver_matches(app_dir: Path, expected: str) -> bool:
    """Only an identical packaged driver may stay loaded during an upgrade."""
    try:
        with (app_dir / "bundle" / "bin" / "WinDivert64.sys").open("rb") as stream:
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(65536), b""):
                digest.update(chunk)
            return digest.hexdigest() == expected.lower()
    except OSError:
        return False


def prepare_update(app_dir: Path, timeout=60.0, driver_sha256=None) -> None:
    if os.name != "nt" or not app_dir.is_absolute():
        raise UpdateError("Для обновления нужен абсолютный путь установки в Windows.")
    if driver_sha256 is not None and (not isinstance(driver_sha256, str)
                                      or not re.fullmatch(r"[0-9a-fA-F]{64}", driver_sha256)):
        raise UpdateError("Некорректная контрольная сумма поставляемого драйвера.")
    app_dir = app_dir.resolve()
    deadline = time.monotonic() + timeout
    requested = set()
    while True:
        for port in candidate_ports(app_dir):
            remaining = deadline - time.monotonic()
            if port in requested or remaining <= 0:
                continue
            try:
                if request_exit(port, app_dir, timeout=min(2.0, remaining / 3)):
                    requested.add(port)
            except (OSError, ValueError, UpdateError):
                # Shutdown can close the connection before its response reaches
                # us. File availability, not HTTP 200, decides whether to proceed.
                pass
        blocked = blocked_files(app_dir)
        if driver_sha256 is not None and _driver_matches(app_dir, driver_sha256):
            # Windows may retain the driver after all application handles close.
            # Setup independently uses the SAME package hash to skip this file.
            driver = app_dir / "bundle" / "bin" / "WinDivert64.sys"
            blocked = [(path, code) for path, code in blocked if path != driver]
        if not blocked:
            return
        if time.monotonic() >= deadline:
            raise UpdateBlocked("Файлы заняты или недоступны: " + ", ".join(path.name for path, _ in blocked))
        time.sleep(min(0.5, max(0, deadline - time.monotonic())))


def run_update_helper(path: str, driver_sha256=None) -> int:
    """Return an exit code to Inno; never display a hidden, blocking error dialog."""
    try:
        if driver_sha256 is None:
            prepare_update(Path(path))
        else:
            prepare_update(Path(path), driver_sha256=driver_sha256)
        return 0
    except UpdateBlocked:
        return 10
    except Exception:
        return 11
