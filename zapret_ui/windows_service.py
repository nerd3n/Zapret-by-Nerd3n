"""An independently owned SCM service, backed by an administrator-only snapshot.

No batch files, command shells, shared WinDivert services or external processes
are managed here. The injected adapter keeps lifecycle tests away from the SCM.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import threading
import time
import uuid

from .strategies import catalog

SERVICE_NAME = "ZapretByNerd3n"
DISPLAY_NAME = "zapret by nerd3n"
OWNER = "zapret-by-nerd3n/scm-v1"
REGISTRY_VALUE = "ZapretByNerd3nOwnership"
STATES = {1: "stopped", 2: "start_pending", 3: "stop_pending", 4: "running",
          5: "continue_pending", 6: "pause_pending", 7: "paused"}
_SNAPSHOT_NAME = re.compile(r"snapshot-[0-9a-f]{32}\Z")
_STRATEGY_ID = re.compile(r"(?:stock|experiment)-[a-z0-9-]{1,160}\Z")
_PATH_OPTIONS = {
    "--hostlist", "--hostlist-exclude", "--ipset", "--ipset-exclude",
    "--dpi-desync-fake-discord", "--dpi-desync-fake-http", "--dpi-desync-fake-quic",
    "--dpi-desync-fake-stun", "--dpi-desync-fake-tls", "--dpi-desync-fake-unknown",
    "--dpi-desync-fake-unknown-udp", "--dpi-desync-fakedsplit-pattern",
    "--dpi-desync-split-seqovl-pattern",
}
# Executable code is pinned, including its DLL search directory dependencies.
NATIVE_HASHES = {
    "winws.exe": "affb4f69d2ea302a7abccd5325d81826e140ddae014f1e070bc4a6c0dd555188",
    "WinDivert.dll": "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2",
    "WinDivert64.sys": "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2",
    "cygwin1.dll": "103104a52e5293ce418944725df19e2bf81ad9269b9a120d71d39028e821499b",
}
FILE_SDDL = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
KEY_SDDL = "O:BAG:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)"


class ServiceError(RuntimeError):
    """The operation failed without permission to modify unrelated services."""


class _MarkedForDeletion(ServiceError):
    """Another SCM client still holds a handle after DeleteService."""


def _plain_path(path: Path) -> Path:
    """Reject links/junctions before resolving, including every existing ancestor."""
    path = Path(os.path.abspath(path))
    for part in reversed((path, *path.parents)):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ServiceError(f"Ссылки и reparse points недопустимы: {part}")
    return path


def _bundle_files(source: Path) -> list[Path]:
    source = _plain_path(source)
    for dirname in ("bin", "lists"):
        _plain_path(source / dirname)
    files = list(source.glob("general*.bat"))
    files += [source / "bin" / name for name in NATIVE_HASHES]
    files += list((source / "bin").glob("*.bin"))
    files += list((source / "lists").glob("*.txt"))
    files = sorted(set(files))
    total = 0
    if not files or len(files) > 512:
        raise ServiceError("Недопустимое количество файлов комплекта.")
    for path in files:
        _plain_path(path)
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ServiceError(f"Требуется обычный файл без hard links: {path.name}")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. ()-]{0,150}", path.name):
            raise ServiceError(f"Недопустимое имя файла комплекта: {path.name}")
        total += info.st_size
        if info.st_size > 32 * 1024 * 1024 or total > 128 * 1024 * 1024:
            raise ServiceError("Комплект превышает допустимый размер.")
    return files


def _check_native_hashes(bundle: Path):
    for name, expected in NATIVE_HASHES.items():
        path = _plain_path(bundle / "bin" / name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ServiceError(f"Файл {name} отличается от проверенной версии. Установка службы отменена.")


def remap_argv(argv: list[str], source: Path, snapshot: Path) -> list[str]:
    """Only a catalog's executable and known file arguments may contain paths."""
    source, snapshot = Path(source).resolve(), Path(snapshot).resolve()
    if not argv or Path(argv[0]).resolve() != source / "bin" / "winws.exe":
        raise ServiceError("В стратегии указан посторонний исполняемый файл.")
    result = [str(snapshot / "bin" / "winws.exe")]
    for argument in argv[1:]:
        option, separator, value = argument.partition("=")
        if option in _PATH_OPTIONS and separator and value != "!" and not value.startswith("0x"):
            try:
                relative = Path(value).resolve().relative_to(source)
            except ValueError as exc:
                raise ServiceError("Путь аргумента выходит за пределы комплекта.") from exc
            if relative.parts[0] not in {"bin", "lists"} or len(relative.parts) != 2:
                raise ServiceError("Недопустимое расположение файла стратегии.")
            result.append(option + "=" + str(snapshot / relative))
        else:
            if str(source).casefold() in argument.casefold():
                raise ServiceError("Неизвестный аргумент содержит путь к исходной папке.")
            result.append(argument)
    return result


class ServiceManager:
    """Public interface: status, install(strategy_id), start, stop and remove.

    Mutations require elevation. install also starts the service; reinstallation
    is deliberately rejected. No destructor or UI shutdown hook stops it.
    """

    def __init__(self, base: Path, *, adapter=None, timeout: float = 20.0):
        self.base = Path(os.path.abspath(base))
        self.adapter = adapter if adapter is not None else (WindowsAdapter() if os.name == "nt" else None)
        self.timeout = max(0.1, min(float(timeout), 60.0))
        self.lock = threading.RLock()

    def _supported(self):
        return self.adapter is not None and self.adapter.supported

    def _owned(self, raw: dict) -> bool:
        meta = raw.get("metadata")
        if not isinstance(meta, dict) or meta.get("owner") != OWNER or meta.get("schema") != 1:
            return False
        try:
            snapshot = Path(meta["snapshot"])
            expected_root = Path(self.adapter.snapshot_root)
            if snapshot.parent != expected_root or not _SNAPSHOT_NAME.fullmatch(snapshot.name):
                return False
            if not _STRATEGY_ID.fullmatch(meta["strategyId"]):
                return False
            command = raw["imagePath"]
            expected_exe = subprocess.list2cmdline([str(snapshot / "bin" / "winws.exe")])
            return (raw.get("serviceType") == 16 and raw.get("account", "").lower() == "localsystem"
                    and command.startswith(expected_exe + " ")
                    and hashlib.sha256(command.encode("utf-8")).hexdigest() == meta.get("imageSha256"))
        except (KeyError, TypeError, ValueError, AttributeError):
            return False

    def status(self) -> dict:
        result = {"supported": self._supported(), "installed": False, "owned": False,
                  "running": False, "status": "unsupported", "state": "unsupported", "pid": None,
                  "strategyId": None, "strategyName": None, "startType": None, "path": None, "error": None}
        if not self._supported():
            return result
        try:
            raw = self.adapter.query()
            if raw is None:
                result.update(status="not_installed", state="not_installed")
                return result
            owned = self._owned(raw)
            state = raw.get("state", "unknown")
            meta = raw.get("metadata") or {}
            result.update(installed=True, owned=owned, running=state == "running", status=state, state=state,
                          pid=raw.get("pid") or None, startType=raw.get("startType"), path=raw.get("imagePath"),
                          strategyId=meta.get("strategyId") if owned else None,
                          strategyName=meta.get("strategyName") if owned else None,
                          error=None if owned else "Служба с этим именем не принадлежит приложению; изменения запрещены.")
        except (OSError, ServiceError, ValueError) as exc:
            result.update(status="unknown", state="unknown", error=str(exc))
        return result

    def _authorize(self):
        if not self._supported():
            raise ServiceError("Службы поддерживаются только в Windows x64.")
        if not self.adapter.is_admin():
            raise ServiceError("Для управления службой нужны права администратора.")

    def _existing(self) -> dict:
        raw = self.adapter.query()
        if raw is None:
            raise ServiceError("Служба не установлена.")
        if not self._owned(raw):
            raise ServiceError("Владение службой не подтверждено. Чужая служба не изменена.")
        return raw

    def _wait(self, state: str, *, deleted: bool = False):
        deadline = self.adapter.monotonic() + self.timeout
        while True:
            try:
                raw = self.adapter.query()
            except _MarkedForDeletion:
                if not deleted:
                    raise
                if self.adapter.monotonic() >= deadline:
                    raise ServiceError("Служба помечена для удаления. Закройте оснастку «Службы» и повторите проверку.")
                self.adapter.sleep(0.15)
                continue
            if deleted and raw is None:
                return
            if raw is None or not self._owned(raw):
                raise ServiceError("Служба исчезла или изменила владельца во время операции.")
            if raw.get("state") == state:
                return
            if state == "running" and raw.get("state") == "stopped":
                raise ServiceError(f"Служба завершилась при запуске (код {raw.get('exitCode', 0)}).")
            if self.adapter.monotonic() >= deadline:
                raise ServiceError("Истекло время ожидания службы. Состояние проверьте повторно.")
            self.adapter.sleep(0.15)

    def _start(self):
        raw = self._existing()
        self.adapter.validate_snapshot(Path(raw["metadata"]["snapshot"]))
        if raw["state"] == "running":
            return
        if raw["state"] == "stop_pending":
            self._wait("stopped")
        elif raw["state"] == "start_pending":
            self._wait("running")
            self._confirm_running()
            return
        elif raw["state"] != "stopped":
            raise ServiceError("Сначала остановите службу перед повторным запуском.")
        self._existing()
        self.adapter.start()
        self._wait("running")
        self._confirm_running()

    def _confirm_running(self):
        # winws reports SERVICE_RUNNING before parsing options and opening the
        # driver. Do not report installation success if it immediately exits.
        deadline = self.adapter.monotonic() + min(3.0, self.timeout)
        first_pid = None
        while True:
            raw = self._existing()
            if raw["state"] != "running":
                raise ServiceError(f"Служба завершилась сразу после запуска (код {raw.get('exitCode', 0)}).")
            if not isinstance(raw.get("pid"), int) or raw["pid"] <= 0:
                raise ServiceError("Windows не сообщила процесс запущенной службы.")
            if first_pid is None:
                first_pid = raw.get("pid")
            elif raw.get("pid") != first_pid:
                raise ServiceError("Процесс службы изменился во время проверки запуска.")
            remaining = deadline - self.adapter.monotonic()
            if remaining <= 0:
                return
            self.adapter.sleep(min(0.15, remaining))

    def _stop(self):
        raw = self._existing()
        if raw["state"] == "stopped":
            return
        if raw["state"] == "start_pending":
            self._wait("running")
            raw = self._existing()
        if raw["state"] != "stop_pending":
            self.adapter.stop()
        self._wait("stopped")

    def install(self, strategy_id: str) -> dict:
        with self.lock:
            self._authorize()
            if self.adapter.query() is not None:
                raise ServiceError("Служба уже существует. Для смены стратегии сначала удалите её через приложение.")
            if self.adapter.legacy_exists():
                raise ServiceError("Найдена старая служба zapret. Удалите её через service.bat старого комплекта "
                                   "(Remove Services), затем установите автозапуск здесь. Старая служба не изменена.")
            if not isinstance(strategy_id, str) or not _STRATEGY_ID.fullmatch(strategy_id):
                raise ServiceError("Недопустимый идентификатор стратегии.")
            source = _plain_path(self.base / "bundle")
            _bundle_files(source)
            choice = next((item for item in catalog(source) if item["id"] == strategy_id), None)
            if choice is None:
                raise ServiceError("Стратегия не найдена в комплекте приложения.")
            snapshot = None
            created = False
            command = None
            try:
                snapshot = self.adapter.snapshot(source)
                copied = next((item for item in catalog(snapshot) if item["id"] == strategy_id), None)
                if copied is None or copied["argv"] != remap_argv(choice["argv"], source, snapshot):
                    raise ServiceError("Стратегия изменилась во время копирования. Установка отменена.")
                self.adapter.validate_snapshot(snapshot)
                command = subprocess.list2cmdline(copied["argv"])
                if len(command.encode("utf-16-le")) // 2 >= 32767:
                    raise ServiceError("Командная строка службы превышает ограничение Windows.")
                metadata = {"owner": OWNER, "schema": 1, "snapshot": str(snapshot),
                            "strategyId": strategy_id, "strategyName": copied["name"],
                            "imageSha256": hashlib.sha256(command.encode("utf-8")).hexdigest()}
                self.adapter.create(command, metadata)
                created = True
                self._start()
                return self.status()
            except Exception as original:
                cleanup_error = None
                if created:
                    try:
                        self._stop()
                        self._existing()
                        self.adapter.delete()
                        self._wait("", deleted=True)
                    except Exception as exc:
                        cleanup_error = exc
                if snapshot is not None and cleanup_error is None:
                    try:
                        remaining = self.adapter.query()
                        # Keep executable files if a partially created service still refers to them.
                        if remaining and remaining.get("imagePath") == command:
                            raise ServiceError("Служба ещё ссылается на защищённую копию; копия сохранена.")
                        self.adapter.cleanup_snapshot(snapshot)
                    except Exception as exc:
                        cleanup_error = exc
                message = str(original)
                if cleanup_error:
                    message += f" Откат не завершён: {cleanup_error}"
                raise ServiceError(message) from original

    def start(self) -> dict:
        with self.lock:
            self._authorize()
            self._start()
            return self.status()

    def stop(self) -> dict:
        with self.lock:
            self._authorize()
            self._stop()
            return self.status()

    def remove(self) -> dict:
        with self.lock:
            self._authorize()
            raw = self._existing()
            snapshot = Path(raw["metadata"]["snapshot"])
            self._stop()
            self._existing()
            self.adapter.delete()
            self._wait("", deleted=True)
            self.adapter.cleanup_snapshot(snapshot)
            return self.status()


class _Status(ctypes.Structure):
    _fields_ = [(name, wintypes.DWORD) for name in
                ("serviceType", "state", "controls", "exitCode", "specificExitCode", "checkpoint", "waitHint")]


class _StatusProcess(ctypes.Structure):
    _fields_ = _Status._fields_ + [("pid", wintypes.DWORD), ("flags", wintypes.DWORD)]


class _Config(ctypes.Structure):
    _fields_ = [("serviceType", wintypes.DWORD), ("startType", wintypes.DWORD), ("errorControl", wintypes.DWORD),
                ("binaryPath", wintypes.LPWSTR), ("loadGroup", wintypes.LPWSTR), ("tag", wintypes.DWORD),
                ("dependencies", wintypes.LPWSTR), ("account", wintypes.LPWSTR), ("displayName", wintypes.LPWSTR)]


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p), ("inherit", wintypes.BOOL)]


class _FileInfo(ctypes.Structure):
    _fields_ = [("attributes", wintypes.DWORD), ("creation", wintypes.FILETIME), ("access", wintypes.FILETIME),
                ("write", wintypes.FILETIME), ("volume", wintypes.DWORD), ("sizeHigh", wintypes.DWORD),
                ("sizeLow", wintypes.DWORD), ("links", wintypes.DWORD), ("indexHigh", wintypes.DWORD), ("indexLow", wintypes.DWORD)]


class WindowsAdapter:
    """Native SCM/security adapter. Constructing it and query() are read-only."""

    supported = True
    monotonic = staticmethod(time.monotonic)
    sleep = staticmethod(time.sleep)

    def __init__(self):
        if os.name != "nt":
            raise ServiceError("Требуется Windows.")
        import winreg
        self.reg = winreg
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.shell = ctypes.WinDLL("shell32", use_last_error=True)
        self._bind()
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            program_files, _ = winreg.QueryValueEx(key, "ProgramFilesDir")
        self.snapshot_root = Path(program_files) / "ZapretByNerd3n-Service"
        self.key_path = rf"SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}"

    def _bind(self):
        d, p, w, h, b = wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, wintypes.HANDLE, wintypes.BOOL
        signatures = {
            "OpenSCManagerW": ([w, w, d], h), "OpenServiceW": ([h, w, d], h),
            "CloseServiceHandle": ([h], b), "QueryServiceStatusEx": ([h, d, p, d, ctypes.POINTER(d)], b),
            "QueryServiceConfigW": ([h, p, d, ctypes.POINTER(d)], b),
            "CreateServiceW": ([h, w, w, d, d, d, d, w, w, p, w, w, w], h),
            "ChangeServiceConfigW": ([h, d, d, d, w, w, p, w, w, w, w], b),
            "StartServiceW": ([h, d, p], b), "ControlService": ([h, d, p], b), "DeleteService": ([h], b),
            "ConvertStringSecurityDescriptorToSecurityDescriptorW": ([w, d, ctypes.POINTER(p), p], b),
            "GetNamedSecurityInfoW": ([w, d, d, ctypes.POINTER(p), p, ctypes.POINTER(p), p, ctypes.POINTER(p)], d),
            "GetSecurityDescriptorDacl": ([p, ctypes.POINTER(b), ctypes.POINTER(p), ctypes.POINTER(b)], b),
            "GetSecurityDescriptorOwner": ([p, ctypes.POINTER(p), ctypes.POINTER(b)], b),
            "GetSecurityDescriptorControl": ([p, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(d)], b),
            "GetAce": ([p, d, ctypes.POINTER(p)], b),
            "ConvertSidToStringSidW": ([p, ctypes.POINTER(p)], b),
            "RegSetKeySecurity": ([h, d, p], wintypes.LONG),
            "RegGetKeySecurity": ([h, d, p, ctypes.POINTER(d)], wintypes.LONG),
        }
        for name, (args, result) in signatures.items():
            fn = getattr(self.advapi, name)
            fn.argtypes, fn.restype = args, result
        for name, args, result in [
            ("CreateDirectoryW", [w, p], b), ("CreateFileW", [w, d, d, p, d, d, h], h),
            ("GetFileInformationByHandle", [h, p], b), ("CloseHandle", [h], b),
            ("ReadFile", [h, p, d, ctypes.POINTER(d), p], b),
            ("WriteFile", [h, p, d, ctypes.POINTER(d), p], b), ("FlushFileBuffers", [h], b),
            ("LocalFree", [p], p),
        ]:
            fn = getattr(self.kernel, name)
            fn.argtypes, fn.restype = args, result
        self.shell.IsUserAnAdmin.argtypes, self.shell.IsUserAnAdmin.restype = [], b

    def is_admin(self):
        return bool(self.shell.IsUserAnAdmin())

    @staticmethod
    def _error(action):
        code = ctypes.get_last_error()
        return ServiceError(f"{action}: {ctypes.FormatError(code).strip()} (Windows {code})")

    @contextmanager
    def _scm(self, rights=1):
        handle = self.advapi.OpenSCManagerW(None, None, rights)
        if not handle:
            raise self._error("Не удалось открыть диспетчер служб")
        try:
            yield handle
        finally:
            self.advapi.CloseServiceHandle(handle)

    @contextmanager
    def _service(self, rights):
        with self._scm() as scm:
            handle = self.advapi.OpenServiceW(scm, SERVICE_NAME, rights)
            if not handle:
                raise self._error("Не удалось открыть службу")
            try:
                yield handle
            finally:
                self.advapi.CloseServiceHandle(handle)

    @contextmanager
    def _descriptor(self, text):
        descriptor = ctypes.c_void_p()
        if not self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(text, 1, ctypes.byref(descriptor), None):
            raise self._error("Не удалось подготовить ACL")
        try:
            yield descriptor
        finally:
            self.kernel.LocalFree(descriptor)

    def _sid(self, pointer):
        text = ctypes.c_void_p()
        if not self.advapi.ConvertSidToStringSidW(pointer, ctypes.byref(text)):
            raise self._error("Не удалось проверить владельца")
        try:
            return ctypes.wstring_at(text)
        finally:
            self.kernel.LocalFree(text)

    def _check_descriptor(self, descriptor, *, registry=False):
        owner, acl = ctypes.c_void_p(), ctypes.c_void_p()
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        control, revision = wintypes.WORD(), wintypes.DWORD()
        if not self.advapi.GetSecurityDescriptorOwner(descriptor, ctypes.byref(owner), ctypes.byref(defaulted)):
            raise self._error("Не удалось проверить владельца")
        if self._sid(owner) not in {"S-1-5-18", "S-1-5-32-544"}:
            raise ServiceError("Владелец защищённой копии должен быть SYSTEM или Administrators.")
        if not self.advapi.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(acl), ctypes.byref(defaulted)):
            raise self._error("Не удалось проверить ACL")
        if not present.value or not acl.value:
            raise ServiceError("Отсутствует защищённый ACL.")
        if not self.advapi.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise self._error("Не удалось проверить наследование ACL")
        if not control.value & 0x1000:
            raise ServiceError("ACL защищённой копии не изолирован от наследования.")
        count = ctypes.c_ushort.from_address(acl.value + 4).value
        allowed = {"S-1-5-18": 0xF003F if registry else 0x1F01FF,
                   "S-1-5-32-544": 0xF003F if registry else 0x1F01FF,
                   "S-1-5-32-545": 0x20019 if registry else 0x1200A9}
        found = {}
        for index in range(count):
            ace = ctypes.c_void_p()
            if not self.advapi.GetAce(acl, index, ctypes.byref(ace)):
                raise self._error("Не удалось прочитать ACL")
            if ctypes.c_ubyte.from_address(ace.value).value != 0:
                raise ServiceError("Неожиданный тип разрешения в ACL.")
            mask = ctypes.c_uint32.from_address(ace.value + 4).value
            sid = self._sid(ctypes.c_void_p(ace.value + 8))
            if sid not in allowed or mask != allowed[sid] or sid in found:
                raise ServiceError("ACL разрешает неожиданный доступ; операция отменена.")
            found[sid] = mask
        if found != allowed:
            raise ServiceError("ACL защищённой копии неполон.")

    def _secure_acl(self, path):
        owner, acl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        error = self.advapi.GetNamedSecurityInfoW(str(path), 1, 0x5, ctypes.byref(owner), None,
                                                ctypes.byref(acl), None, ctypes.byref(descriptor))
        if error:
            raise ServiceError(f"Не удалось прочитать ACL {path}: Windows {error}")
        try:
            self._check_descriptor(descriptor)
        finally:
            self.kernel.LocalFree(descriptor)

    def _mkdir(self, path):
        with self._descriptor(FILE_SDDL) as descriptor:
            attrs = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
            if not self.kernel.CreateDirectoryW(str(path), ctypes.byref(attrs)) and ctypes.get_last_error() != 183:
                raise self._error("Не удалось создать защищённую папку")
        _plain_path(path)
        self._secure_acl(path)

    @contextmanager
    def _file_handle(self, path, *, directory=False, create=False):
        with self._descriptor(FILE_SDDL) as descriptor:
            attrs = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
            handle = self.kernel.CreateFileW(str(path), 0x40000000 if create else (0x80 if directory else 0x80000000),
                                             0x3 if directory else 0x1, ctypes.byref(attrs) if create else None,
                                             1 if create else 3, 0x00200000 | (0x02000000 if directory else 0), None)
        if handle == ctypes.c_void_p(-1).value:
            raise self._error(f"Не удалось открыть {path.name}")
        try:
            info = _FileInfo()
            if not self.kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
                raise self._error("Не удалось проверить файл")
            if info.attributes & 0x400 or bool(info.attributes & 0x10) != directory:
                raise ServiceError("Обнаружена ссылка или неожиданный тип файла.")
            if not directory and info.links != 1:
                raise ServiceError("Hard links в копии службы запрещены.")
            yield handle
        finally:
            self.kernel.CloseHandle(handle)

    def snapshot(self, source: Path) -> Path:
        files = _bundle_files(source)
        _plain_path(self.snapshot_root.parent)
        self._mkdir(self.snapshot_root)
        destination = self.snapshot_root / ("snapshot-" + uuid.uuid4().hex)
        self._mkdir(destination)
        try:
            self._mkdir(destination / "bin")
            self._mkdir(destination / "lists")
            with ExitStack() as locks:
                directories = set(source.parents) | {source, source / "bin", source / "lists"}
                for directory in sorted(directories, key=lambda p: len(p.parts)):
                    locks.enter_context(self._file_handle(directory, directory=True))
                copied_total = 0
                for original in files:
                    target = destination / original.relative_to(source)
                    with self._file_handle(original) as reader, self._file_handle(target, create=True) as writer:
                        buffer, read, written = ctypes.create_string_buffer(65536), wintypes.DWORD(), wintypes.DWORD()
                        total = 0
                        while True:
                            if not self.kernel.ReadFile(reader, buffer, len(buffer), ctypes.byref(read), None):
                                raise self._error("Ошибка чтения комплекта")
                            if not read.value:
                                break
                            total += read.value
                            copied_total += read.value
                            if total > 32 * 1024 * 1024 or copied_total > 128 * 1024 * 1024:
                                raise ServiceError("Файл вырос во время копирования.")
                            if not self.kernel.WriteFile(writer, buffer, read.value, ctypes.byref(written), None) or written.value != read.value:
                                raise self._error("Ошибка записи защищённой копии")
                        if not self.kernel.FlushFileBuffers(writer):
                            raise self._error("Не удалось сохранить защищённую копию")
            self.validate_snapshot(destination)
            return destination
        except Exception as original:
            try:
                self.cleanup_snapshot(destination)
            except Exception as cleanup_error:
                raise ServiceError(f"{original} Не удалось очистить незавершённую копию: {cleanup_error}") from original
            raise

    def validate_snapshot(self, path: Path):
        if path.parent != self.snapshot_root or not _SNAPSHOT_NAME.fullmatch(path.name):
            raise ServiceError("Некорректный путь защищённой копии.")
        _plain_path(path)
        self._secure_acl(self.snapshot_root)
        for item in self._snapshot_items(path):
            _plain_path(item)
            self._secure_acl(item)
            if item.is_file() and item.stat().st_nlink != 1:
                raise ServiceError("Hard links в защищённой копии запрещены.")
        _check_native_hashes(path)

    @staticmethod
    def _snapshot_items(path):
        """Inspect every directory before descending; never traverse a junction."""
        pending = [path]
        while pending:
            item = pending.pop()
            _plain_path(item)
            yield item
            if item.is_dir():
                pending.extend(item.iterdir())

    def cleanup_snapshot(self, path: Path):
        if path.parent != self.snapshot_root or not _SNAPSHOT_NAME.fullmatch(path.name):
            raise ServiceError("Очистка посторонней папки запрещена.")
        if not path.exists():
            return
        _plain_path(path)
        self._secure_acl(self.snapshot_root)
        # The parent and every object are administrator-owned, so an ordinary
        # user cannot exchange a checked object for a junction before deletion.
        for item in self._snapshot_items(path):
            _plain_path(item)
            self._secure_acl(item)
        shutil.rmtree(path)

    def _metadata(self):
        reg = self.reg
        try:
            with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, self.key_path, 0, reg.KEY_READ | reg.KEY_WOW64_64KEY) as key:
                size = wintypes.DWORD()
                self.advapi.RegGetKeySecurity(int(key), 0x5, None, ctypes.byref(size))
                if not size.value or size.value > 65536:
                    return None
                descriptor = ctypes.create_string_buffer(size.value)
                if self.advapi.RegGetKeySecurity(int(key), 0x5, descriptor, ctypes.byref(size)):
                    return None
                self._check_descriptor(descriptor, registry=True)
                text, kind = reg.QueryValueEx(key, REGISTRY_VALUE)
                if kind != reg.REG_SZ or not isinstance(text, str) or len(text) > 8192:
                    return None
                return json.loads(text)
        except (OSError, ValueError, ServiceError):
            return None

    def _registry_config(self):
        """Recovery for our old oversized ImagePath, never a general SCM fallback."""
        metadata = self._metadata()  # Includes the protected registry ACL check.
        if not isinstance(metadata, dict) or metadata.get("owner") != OWNER or metadata.get("schema") != 1:
            raise ServiceError("Конфигурация службы недоступна; защищённое владение не подтверждено.")
        reg = self.reg
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, self.key_path, 0, reg.KEY_READ | reg.KEY_WOW64_64KEY) as key:
            values = {}
            for name, types in (("ImagePath", (reg.REG_SZ, reg.REG_EXPAND_SZ)),
                                ("Type", (reg.REG_DWORD,)), ("Start", (reg.REG_DWORD,)),
                                ("ObjectName", (reg.REG_SZ,))):
                value, kind = reg.QueryValueEx(key, name)
                if kind not in types:
                    raise ServiceError("Некорректный тип параметра службы: " + name)
                values[name] = value
        command = values["ImagePath"]
        if (not isinstance(command, str) or not command or "\0" in command
                or len(command.encode("utf-16-le")) > 65532
                or "%" in command or values["Type"] != 16 or values["Start"] not in (2, 3, 4)
                or not isinstance(values["ObjectName"], str)
                or values["ObjectName"].lower() != "localsystem"
                or hashlib.sha256(command.encode("utf-8")).hexdigest() != metadata.get("imageSha256")):
            raise ServiceError("Параметры службы не совпадают с защищённой записью приложения.")
        return {"serviceType": values["Type"], "startType": {2: "automatic", 3: "manual", 4: "disabled"}[values["Start"]],
                "account": values["ObjectName"], "imagePath": command, "metadata": metadata,
                "configSource": "registry"}

    def _query_config(self, handle):
        # QueryServiceConfigW has an 8 KiB RPC response limit. Passing a larger
        # buffer does not lift it and returns RPC_X_BAD_STUB_DATA (1783).
        buffer, needed = ctypes.create_string_buffer(8192), wintypes.DWORD()
        if not self.advapi.QueryServiceConfigW(handle, buffer, len(buffer), ctypes.byref(needed)):
            code = ctypes.get_last_error()
            if code in (1734, 1783) or (code == 122 and needed.value > len(buffer)):
                return self._registry_config()
            raise self._error("Не удалось прочитать конфигурацию службы")
        config = ctypes.cast(buffer, ctypes.POINTER(_Config)).contents
        return {"serviceType": config.serviceType,
                "startType": "automatic" if config.startType == 2 else "manual" if config.startType == 3 else "disabled",
                "account": config.account or "", "imagePath": config.binaryPath or "", "metadata": self._metadata()}

    def query(self):
        with self._scm() as scm:
            handle = self.advapi.OpenServiceW(scm, SERVICE_NAME, 0x5)
            if not handle:
                code = ctypes.get_last_error()
                if code == 1060:
                    return None
                if code == 1072:
                    raise _MarkedForDeletion("Служба помечена для удаления; дождитесь закрытия её дескрипторов.")
                raise self._error("Не удалось прочитать состояние службы")
            try:
                status, needed = _StatusProcess(), wintypes.DWORD()
                if not self.advapi.QueryServiceStatusEx(handle, 0, ctypes.byref(status), ctypes.sizeof(status), ctypes.byref(needed)):
                    raise self._error("Не удалось прочитать состояние службы")
                config = self._query_config(handle)
                return {"state": STATES.get(status.state, "unknown"), "pid": status.pid,
                        "exitCode": status.exitCode, **config}
            finally:
                self.advapi.CloseServiceHandle(handle)

    def legacy_exists(self):
        """Presence alone blocks installation, even if the old service is stopped."""
        with self._scm() as scm:
            handle = self.advapi.OpenServiceW(scm, "zapret", 0x4)
            if handle:
                self.advapi.CloseServiceHandle(handle)
                return True
            code = ctypes.get_last_error()
            if code == 1060:
                return False
            if code == 1072:
                return True
            raise self._error("Не удалось проверить старую службу zapret")

    def create(self, command: str, metadata: dict):
        with self._scm(0x3) as scm:
            # Initially disabled: incomplete registration cannot start at boot.
            handle = self.advapi.CreateServiceW(scm, SERVICE_NAME, DISPLAY_NAME, 0xF01FF,
                                                16, 4, 1, command, None, None, None, None, None)
            if not handle:
                raise self._error("Не удалось создать службу")
            try:
                reg = self.reg
                with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, self.key_path, 0, reg.KEY_ALL_ACCESS | reg.KEY_WOW64_64KEY) as key:
                    with self._descriptor(KEY_SDDL) as descriptor:
                        error = self.advapi.RegSetKeySecurity(int(key), 0x80000005, descriptor)
                        if error:
                            raise ServiceError(f"Не удалось защитить ownership marker: Windows {error}")
                    reg.SetValueEx(key, REGISTRY_VALUE, 0, reg.REG_SZ, json.dumps(metadata, ensure_ascii=False))
                if self._metadata() != metadata:
                    raise ServiceError("Не удалось проверить сохранённый ownership marker.")
                if not self.advapi.ChangeServiceConfigW(handle, 0xFFFFFFFF, 2, 0xFFFFFFFF,
                                                        None, None, None, None, None, None, None):
                    raise self._error("Не удалось включить автоматический запуск службы")
            except Exception as original:
                if not self.advapi.DeleteService(handle):
                    raise ServiceError(f"{original} Не удалось удалить незавершённую службу; копия сохранена.") from original
                raise
            finally:
                self.advapi.CloseServiceHandle(handle)

    def start(self):
        with self._service(0x10) as handle:
            if not self.advapi.StartServiceW(handle, 0, None) and ctypes.get_last_error() != 1056:
                raise self._error("Не удалось запустить службу")

    def stop(self):
        with self._service(0x20) as handle:
            status = _Status()
            if not self.advapi.ControlService(handle, 1, ctypes.byref(status)) and ctypes.get_last_error() != 1062:
                raise self._error("Не удалось остановить службу")

    def delete(self):
        with self._service(0x10000) as handle:
            if not self.advapi.DeleteService(handle):
                raise self._error("Не удалось удалить службу")
