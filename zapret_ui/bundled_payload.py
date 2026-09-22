"""Validate the embedded distribution and restore missing persistent files only.

The whole ZIP is verified before touching the destination. Windows directory
handles prevent renames; write guards keep publication directories nonempty so
they cannot become junctions. Complete files are published atomically without
replacing an existing name, including when the launcher is elevated.
"""
from __future__ import annotations

from contextlib import AbstractContextManager
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid
import zipfile


MAX_FILES = 256
MAX_FILE_SIZE = 32 * 1024 * 1024
MAX_TOTAL_SIZE = 128 * 1024 * 1024
MAX_MANIFEST_SIZE = 256 * 1024
NATIVE_HASHES = {
    "bundle/bin/winws.exe": "affb4f69d2ea302a7abccd5325d81826e140ddae014f1e070bc4a6c0dd555188",
    "bundle/bin/windivert.dll": "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2",
    "bundle/bin/windivert64.sys": "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2",
    "bundle/bin/cygwin1.dll": "103104a52e5293ce418944725df19e2bf81ad9269b9a120d71d39028e821499b",
}
_RESERVED = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)", re.I)


def _invalid(message: str):
    raise RuntimeError(f"Встроенный комплект повреждён: {message}")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _invalid("повторяющееся поле manifest.json.")
        result[key] = value
    return result


def _parts(name) -> tuple[str, ...]:
    if not isinstance(name, str) or len(name) > 240:
        _invalid("недопустимый путь файла.")
    parts = tuple(name.split("/"))
    if len(parts) < 2 or len(parts) > 8 or parts[0] not in {"bundle", "profiles", "licenses"}:
        _invalid(f"недопустимый путь {name!r}.")
    for part in parts:
        if (not part or part in {".", ".."} or len(part) > 160
                or part[-1] in ". " or _RESERVED.match(part)
                or any(ord(c) < 32 or c in '\\:<>"|?*' for c in part)):
            _invalid(f"недопустимый путь {name!r}.")
    return parts


def _read_payload(source: Path) -> list[tuple[tuple[str, ...], bytes]]:
    try:
        with zipfile.ZipFile(source) as archive:
            entries = archive.infolist()
            if not 2 <= len(entries) <= MAX_FILES + 1:
                _invalid("недопустимое количество файлов.")
            names = set()
            for entry in entries:
                mode = entry.external_attr >> 16
                if (entry.filename != entry.orig_filename or entry.filename in names or entry.flag_bits & 1 or entry.is_dir()
                        or stat.S_IFMT(mode) not in {0, stat.S_IFREG}
                        or entry.external_attr & 0x400):
                    _invalid("повторяющаяся, зашифрованная или небезопасная ZIP-запись.")
                names.add(entry.filename)
            if "manifest.json" not in names:
                _invalid("нет manifest.json.")
            manifest_info = archive.getinfo("manifest.json")
            if manifest_info.file_size > MAX_MANIFEST_SIZE:
                _invalid("слишком большой manifest.json.")
            manifest = json.loads(archive.read(manifest_info), object_pairs_hook=_object)
            if (not isinstance(manifest, dict) or set(manifest) != {"schema", "files"}
                    or type(manifest["schema"]) is not int or manifest["schema"] != 1
                    or not isinstance(manifest["files"], list)
                    or not 1 <= len(manifest["files"]) <= MAX_FILES):
                _invalid("неподдерживаемый manifest.json.")
            planned, seen, total = [], set(), 0
            for record in manifest["files"]:
                if not isinstance(record, dict) or set(record) != {"path", "sha256", "size"}:
                    _invalid("недопустимое описание файла.")
                name, digest, size = record["path"], record["sha256"], record["size"]
                parts = _parts(name)
                key = name.casefold()
                if key in seen or name not in names:
                    _invalid("повторяющийся или отсутствующий файл.")
                seen.add(key)
                if (type(size) is not int or not 0 <= size <= MAX_FILE_SIZE
                        or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                    _invalid(f"недопустимый размер или SHA-256: {name}.")
                total += size
                if total > MAX_TOTAL_SIZE:
                    _invalid("превышен допустимый размер комплекта.")
                if archive.getinfo(name).file_size != size:
                    _invalid(f"размер файла не совпадает: {name}.")
                expected_native = NATIVE_HASHES.get(key)
                if expected_native and digest != expected_native:
                    _invalid(f"неподтверждённая версия нативного файла: {name}.")
                planned.append((name, parts, digest))
            if names != {"manifest.json", *(name for name, _, _ in planned)}:
                _invalid("в ZIP есть файлы, не указанные в manifest.json.")
            for _, parts, _ in planned:
                if any("/".join(parts[:n]).casefold() in seen for n in range(1, len(parts))):
                    _invalid("конфликт имени файла и каталога.")
            payload = []
            for name, parts, digest in planned:
                data = archive.read(name)
                if hashlib.sha256(data).hexdigest() != digest:
                    _invalid(f"SHA-256 файла не совпадает: {name}.")
                payload.append((parts, data))
            return payload
    except FileNotFoundError as exc:
        raise RuntimeError("В приложении отсутствует payload.zip. Скачайте EXE заново.") from exc
    except (zipfile.BadZipFile, UnicodeError, json.JSONDecodeError, NotImplementedError, EOFError) as exc:
        raise RuntimeError("Встроенный комплект повреждён. Скачайте EXE заново.") from exc


def _safe_info(info, path: Path, *, directory: bool):
    if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise RuntimeError(f"Небезопасный путь комплекта (ссылка или неподходящий тип): {path}")


class _AttributeTagInfo(ctypes.Structure):
    _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]


class _Destination(AbstractContextManager):
    def __init__(self):
        self.directories = {}
        self.guards = {}
        self.windows = os.name == "nt"
        if self.windows:
            self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            self.kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                                ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
            self.kernel.CreateFileW.restype = wintypes.HANDLE
            self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            self.kernel.CloseHandle.restype = wintypes.BOOL
            self.kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                                 ctypes.c_void_p, wintypes.DWORD]
            self.kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
            self.kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                               ctypes.c_void_p, wintypes.DWORD]
            self.kernel.SetFileInformationByHandle.restype = wintypes.BOOL

    def __exit__(self, exc_type, *_):
        cleanup_error = None
        try:
            for handle in self.guards.values():
                try:
                    self._delete_windows(handle)
                except OSError as error:
                    if cleanup_error is None:
                        cleanup_error = error
                finally:
                    self.kernel.CloseHandle(handle)
        finally:
            for handle in reversed(list(self.directories.values())):
                self.kernel.CloseHandle(handle) if self.windows else os.close(handle)
        if cleanup_error is not None and exc_type is None:
            raise cleanup_error

    def _open_windows(self, path: Path, *, directory: bool, allow_write=False):
        # FILE_LIST_DIRECTORY is required: attribute-only handles do not participate
        # in Windows share checks. No WRITE/DELETE sharing protects reparse data and names.
        handle = self.kernel.CreateFileW(str(path), 0x81 if directory else 0xC0010000,
                                        0x3 if allow_write else 0x1, None, 3 if directory else 1,
                                        0x00200000 | (0x02000000 if directory else 0), None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        info = _AttributeTagInfo()
        try:
            if not self.kernel.GetFileInformationByHandleEx(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            if info.attributes & 0x400 or bool(info.attributes & 0x10) != directory:
                raise RuntimeError(f"Ссылки и reparse points недопустимы: {path}")
        except BaseException:
            self.kernel.CloseHandle(handle)
            raise
        return handle

    def _guard_windows_directory(self, path: Path):
        if path in self.guards:
            return
        # The strong directory handle blocks a concurrent reparse mutation while
        # this guard is created. Its non-deletable file keeps the directory nonempty
        # until ALL publications finish, so it cannot be turned into a junction.
        guard = self._open_windows(path / (".zapret-payload-guard-" + uuid.uuid4().hex), directory=False)
        try:
            replacement = self._open_windows(path, directory=True, allow_write=True)
        except BaseException:
            self._delete_windows(guard)
            self.kernel.CloseHandle(guard)
            raise
        old = self.directories[path]
        self.directories[path] = replacement
        self.guards[path] = guard
        self.kernel.CloseHandle(old)

    def directory(self, path: Path, *, create: bool):
        if path in self.directories:
            return self.directories[path]
        parent = None if path.parent == path else self.directory(path.parent, create=create)
        if parent is None and path.parent != path:
            return None
        try:
            if self.windows:
                handle = self._open_windows(path, directory=True)
            else:
                handle = os.open(str(path) if parent is None else path.name,
                                 os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        except FileNotFoundError:
            if not create:
                return None
            try:
                os.mkdir(path if self.windows else path.name, dir_fd=None if self.windows else parent)
            except FileExistsError:
                pass  # Another launcher may have created it. Opening below still checks its type.
            return self.directory(path, create=False)
        self.directories[path] = handle
        return handle

    def existing(self, path: Path, parent) -> bool:
        try:
            info = (path.lstat() if self.windows else
                    os.stat(path.name, dir_fd=parent, follow_symlinks=False))
        except FileNotFoundError:
            return False
        _safe_info(info, path, directory=False)
        return True

    def _rename_windows(self, handle, path: Path):
        name = str(path)
        encoded_name = name.encode("utf-16-le")
        # FileRenameInfo with ReplaceIfExists=False is an atomic, exclusive publish.
        class RenameInfo(ctypes.Structure):
            _fields_ = [("replace", wintypes.BOOLEAN), ("root", wintypes.HANDLE),
                        ("length", wintypes.DWORD), ("name", wintypes.WCHAR * (len(encoded_name) // 2 + 1))]
        info = RenameInfo(False, None, len(encoded_name), name)
        if not self.kernel.SetFileInformationByHandle(handle, 3, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())

    def _delete_windows(self, handle):
        # Delete the opened temporary file, never a name another process could replace.
        delete = wintypes.BOOL(True)
        if not self.kernel.SetFileInformationByHandle(handle, 4, ctypes.byref(delete), ctypes.sizeof(delete)):
            raise ctypes.WinError(ctypes.get_last_error())

    def publish(self, path: Path, parent, data: bytes):
        if self.existing(path, parent):
            return
        temporary = ".zapret-payload-" + uuid.uuid4().hex
        if self.windows:
            import msvcrt
            self._guard_windows_directory(path.parent)
            handle = self._open_windows(path.parent / temporary, directory=False)
            try:
                fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
            except BaseException:
                self._delete_windows(handle)
                self.kernel.CloseHandle(handle)
                raise
            published = False
            with os.fdopen(fd, "w+b") as output:
                try:
                    self._write(output, data)
                    deadline = time.monotonic() + 3.0
                    while True:
                        try:
                            self._rename_windows(handle, path)
                            published = True
                            break
                        except OSError as exc:
                            if self.existing(path, parent):
                                break  # Another launcher/user installed the final name.
                            # Another launcher can briefly hold a strong directory
                            # handle while installing its own non-deletable guard.
                            if exc.winerror != 32 or time.monotonic() >= deadline:
                                raise
                            time.sleep(0.025)
                finally:
                    if not published:
                        self._delete_windows(handle)
        else:
            # A private staging directory also prevents a different UID swapping the
            # source name. All operations use anchored descriptors, never followed paths.
            os.mkdir(temporary, 0o700, dir_fd=parent)
            staging = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                fd = os.open("file", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=staging)
                with os.fdopen(fd, "w+b") as output:
                    self._write(output, data)
                    try:
                        os.link("file", path.name, src_dir_fd=staging, dst_dir_fd=parent, follow_symlinks=False)
                    except FileExistsError:
                        self.existing(path, parent)
            finally:
                try:
                    os.unlink("file", dir_fd=staging)
                except FileNotFoundError:
                    pass
                os.close(staging)
                os.rmdir(temporary, dir_fd=parent)

    @staticmethod
    def _write(output, data: bytes):
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def ensure_embedded_payload(base: Path, resource_root: Path) -> None:
    """Restore missing files beside the EXE; preserve every existing regular file."""
    base = Path(os.path.abspath(base))
    resource_root = Path(os.path.abspath(resource_root))
    if (base == resource_root or resource_root in base.parents
            or any(part.upper().startswith("_MEI") for part in base.parts)):
        raise RuntimeError("Комплект должен храниться рядом с EXE, вне временной папки PyInstaller.")
    payload = _read_payload(resource_root / "payload.zip")
    try:
        with _Destination() as destination:
            # Check all existing destinations before creating even the first directory.
            for parts, _ in payload:
                path = base.joinpath(*parts)
                parent = destination.directory(path.parent, create=False)
                if parent is not None:
                    destination.existing(path, parent)
            for parts, data in payload:
                path = base.joinpath(*parts)
                parent = destination.directory(path.parent, create=True)
                if parent is None:
                    raise RuntimeError(f"Каталог комплекта исчез во время записи: {path.parent}")
                destination.publish(path, parent, data)
    except OSError as exc:
        raise RuntimeError(
            f"Не удалось подготовить комплект рядом с EXE: {base}. "
            "Проверьте права записи и свободное место; переместите EXE в доступную папку. "
            f"Причина: {exc}"
        ) from exc
