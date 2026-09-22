import concurrent.futures
import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from zapret_ui import bundled_payload as payload


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.resources = self.root / "embedded"
        self.resources.mkdir()
        self.base = self.root / "portable"
        self.files = {
            "bundle/lists/list-general.txt": b"youtube.com\ndiscord.com\n",
            "bundle/bin/ACTIVE_DISCORD_UDP.bin": b"default-payload",
            "profiles/infolink-shchelkovo.json": b'{"provider":"Infolink"}',
            "licenses/zapret.txt": b"license text",
        }

    def archive(self, files=None, *, transform=None, extras=None):
        files = self.files if files is None else files
        manifest = {"schema": 1, "files": [
            {"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
            for name, data in files.items()
        ]}
        if transform:
            transform(manifest)
        with zipfile.ZipFile(self.resources / "payload.zip", "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps(manifest))
            for name, data in files.items():
                archive.writestr(name, data)
            for name, data in (extras or {}).items():
                archive.writestr(name, data)

    def install(self):
        payload.ensure_embedded_payload(self.base, self.resources)

    def assert_no_staging(self):
        self.assertFalse(list(self.base.rglob(".zapret-payload-*")))

    def set_junction(self, directory, elsewhere):
        with payload._Destination() as destination:
            handle = destination.kernel.CreateFileW(str(directory), 0x40000000,
                                                     7, None, 3, 0x02200000, None)
            self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
            try:
                substitute = ("\\??\\" + str(elsewhere)).encode("utf-16-le")
                display = str(elsewhere).encode("utf-16-le")
                names = substitute + b"\0\0" + display + b"\0\0"
                buffer = struct.pack("<IHHHHHH", 0xA0000003, 8 + len(names), 0,
                                     0, len(substitute), len(substitute) + 2, len(display)) + names
                ioctl = destination.kernel.DeviceIoControl
                ioctl.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
                                  ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
                ioctl.restype = ctypes.c_int
                transferred = ctypes.c_ulong()
                succeeded = ioctl(handle, 0x900A4, buffer, len(buffer), None, 0,
                                  ctypes.byref(transferred), None)
                return 0 if succeeded else ctypes.get_last_error()
            finally:
                destination.kernel.CloseHandle(handle)

    def test_fresh_extraction_is_persistent_and_idempotent(self):
        self.archive()
        self.install()
        before = {name: (self.base / name).stat().st_mtime_ns for name in self.files}
        with patch.object(payload._Destination, "_write", side_effect=AssertionError("must not write")):
            self.install()
        for name, data in self.files.items():
            self.assertEqual((self.base / name).read_bytes(), data)
            self.assertEqual((self.base / name).stat().st_mtime_ns, before[name])
        self.assert_no_staging()

    def test_existing_lists_payloads_and_unrelated_files_are_preserved(self):
        self.archive()
        self.install()
        changed = {
            "bundle/lists/list-general.txt": b"user.example\n",
            "bundle/bin/ACTIVE_DISCORD_UDP.bin": b"user-payload",
            "profiles/infolink-shchelkovo.json": b"user-profile",
            "licenses/zapret.txt": b"existing-license",
            "bundle/lists/user-extra.txt": b"another-file",
        }
        for name, data in changed.items():
            (self.base / name).write_bytes(data)
        self.install()
        for name, data in changed.items():
            self.assertEqual((self.base / name).read_bytes(), data)

    def test_missing_files_are_repaired_without_touching_existing_files(self):
        self.archive()
        self.install()
        removed = "bundle/bin/ACTIVE_DISCORD_UDP.bin"
        (self.base / removed).unlink()
        (self.base / "bundle/lists/list-general.txt").write_bytes(b"custom")
        self.install()
        self.assertEqual((self.base / removed).read_bytes(), self.files[removed])
        self.assertEqual((self.base / "bundle/lists/list-general.txt").read_bytes(), b"custom")

    def test_non_bmp_unicode_directory_is_supported(self):
        self.base = self.root / "Запрет 🦊"
        self.archive()
        self.install()
        for name, data in self.files.items():
            self.assertEqual((self.base / name).read_bytes(), data)
        self.assert_no_staging()

    def test_missing_or_malformed_archive_fails_before_any_destination_write(self):
        for data in (None, b"not a zip"):
            with self.subTest(data=data):
                if data is not None:
                    (self.resources / "payload.zip").write_bytes(data)
                with self.assertRaises(RuntimeError):
                    self.install()
                self.assertFalse(self.base.exists())

    def test_bad_hash_in_last_file_fails_before_writing_first_file(self):
        self.archive(transform=lambda manifest: manifest["files"][-1].update(sha256="0" * 64))
        with self.assertRaisesRegex(RuntimeError, "SHA-256"):
            self.install()
        self.assertFalse(self.base.exists())

    def test_native_hash_is_pinned_independently_of_manifest(self):
        self.archive({"bundle/bin/winws.exe": b"untrusted executable"})
        with self.assertRaisesRegex(RuntimeError, "нативного"):
            self.install()
        self.assertFalse(self.base.exists())

    def test_unsafe_paths_are_rejected_before_writes(self):
        names = ["../escape", "/bundle/file", "C:/bundle/file", "bundle/../escape",
                 "bundle/./file", "bundle//file", "bundle\\file", "bundle/file:stream",
                 "bundle/CON.txt", "bundle/LPT1", "bundle/file.", "bundle/file ",
                 "other/file", "bundle/a\x01b", "bundle/COM¹.txt"]
        for name in names:
            with self.subTest(name=name):
                self.archive({name: b"x"})
                with self.assertRaises(RuntimeError):
                    self.install()
                self.assertFalse(self.base.exists())

    def test_case_collisions_and_file_directory_conflicts_are_rejected(self):
        for names in (("bundle/a", "bundle/A"), ("bundle/file", "bundle/file/child")):
            with self.subTest(names=names):
                self.archive(dict.fromkeys(names, b"x"))
                with self.assertRaises(RuntimeError):
                    self.install()
                self.assertFalse(self.base.exists())

    def test_unlisted_archive_entries_are_rejected(self):
        self.archive(extras={"bundle/unexpected.exe": b"x"})
        with self.assertRaises(RuntimeError):
            self.install()
        self.assertFalse(self.base.exists())

    def test_symlink_zip_entry_is_rejected(self):
        self.archive({"bundle/file": b"x"})
        with zipfile.ZipFile(self.resources / "payload.zip", "a") as archive:
            link = zipfile.ZipInfo("bundle/link")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, "file")
        with self.assertRaises(RuntimeError):
            self.install()
        self.assertFalse(self.base.exists())

    def test_manifest_limits_and_types_are_checked(self):
        transforms = [
            lambda m: m.update(schema=True),
            lambda m: m["files"][0].update(size=True),
            lambda m: m["files"][0].update(size=payload.MAX_FILE_SIZE + 1),
            lambda m: m["files"][0].update(size=0),
            lambda m: m["files"][0].update(sha256="not a hash"),
            lambda m: m.update(files=m["files"] * payload.MAX_FILES),
        ]
        for transform in transforms:
            with self.subTest(transform=transform):
                self.archive(transform=transform)
                with self.assertRaises(RuntimeError):
                    self.install()
                self.assertFalse(self.base.exists())

    def test_resource_directory_is_never_used_as_persistent_destination(self):
        self.archive()
        for destination in (self.resources, self.resources / "subdirectory", self.root / "_MEI12345"):
            with self.subTest(destination=destination):
                with self.assertRaisesRegex(RuntimeError, "PyInstaller"):
                    payload.ensure_embedded_payload(destination, self.resources)

    def test_existing_directory_instead_of_a_file_fails_before_other_files_written(self):
        self.archive()
        (self.base / "licenses/zapret.txt").mkdir(parents=True)
        with self.assertRaises(RuntimeError):
            self.install()
        self.assertFalse((self.base / "bundle").exists())

    def test_failed_stage_write_never_exposes_partial_target(self):
        self.archive({"bundle/file.txt": b"complete contents"})
        def partial_then_fail(output, data):
            output.write(data[:3])
            output.flush()
            raise OSError("simulated disk failure")
        with patch.object(payload._Destination, "_write", side_effect=partial_then_fail):
            with self.assertRaisesRegex(RuntimeError, "Проверьте права записи"):
                self.install()
        self.assertFalse((self.base / "bundle/file.txt").exists())
        self.assert_no_staging()

    def test_write_permission_error_is_actionable(self):
        self.archive()
        with patch.object(payload._Destination, "publish", side_effect=PermissionError("denied")):
            with self.assertRaisesRegex(RuntimeError, "Проверьте права записи"):
                self.install()

    def test_parallel_launchers_publish_complete_files(self):
        self.archive()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(lambda _: self.install(), range(8)))
        self.assertEqual(results, [None] * 8)
        for name, data in self.files.items():
            self.assertEqual((self.base / name).read_bytes(), data)
        self.assert_no_staging()

    @unittest.skipUnless(os.name == "nt", "Windows handle guarantees")
    def test_file_created_by_other_launcher_before_publish_is_preserved(self):
        self.archive({"bundle/file.txt": b"embedded"})
        original = payload._Destination._rename_windows
        def concurrent_publish(destination, handle, path):
            path.write_bytes(b"other launcher or user")
            return original(destination, handle, path)
        with patch.object(payload._Destination, "_rename_windows", concurrent_publish):
            self.install()
        self.assertEqual((self.base / "bundle/file.txt").read_bytes(), b"other launcher or user")
        self.assert_no_staging()

    @unittest.skipUnless(os.name == "nt", "Windows handle guarantees")
    def test_directory_cannot_be_replaced_while_payload_is_written(self):
        self.archive({"bundle/file.txt": b"complete"})
        original = payload._Destination._write
        def attempt_directory_swap(output, data):
            with self.assertRaises(OSError):
                (self.base / "bundle").rename(self.base / "replaced")
            original(output, data)
        with patch.object(payload._Destination, "_write", side_effect=attempt_directory_swap):
            self.install()
        self.assertEqual((self.base / "bundle/file.txt").read_bytes(), b"complete")

    @unittest.skipUnless(os.name == "nt", "Windows junction guarantees")
    def test_junction_in_destination_or_ancestor_is_rejected(self):
        self.archive({"bundle/file.txt": b"embedded"})
        self.base.mkdir()
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        link = self.base / "junction"
        subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(elsewhere)],
                       check=True, capture_output=True)
        # Both the base itself and a parent of a not-yet-created base are rejected.
        for destination in (link, link / "child"):
            with self.subTest(destination=destination):
                with self.assertRaisesRegex(RuntimeError, "reparse"):
                    payload.ensure_embedded_payload(destination, self.resources)
                self.assertEqual(list(elsewhere.iterdir()), [])

    @unittest.skipUnless(os.name == "nt", "Windows directory sharing guarantees")
    def test_directory_cannot_become_junction_during_write(self):
        self.archive({"bundle/file.txt": b"complete"})
        original = payload._Destination._write
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        def attempt_reparse_write(output, data):
            self.assertEqual(self.set_junction(self.base / "bundle", elsewhere), 145)
            original(output, data)
        with patch.object(payload._Destination, "_write", side_effect=attempt_reparse_write):
            self.install()
        self.assertEqual((self.base / "bundle/file.txt").read_bytes(), b"complete")
        self.assertEqual(list(elsewhere.iterdir()), [])

    @unittest.skipUnless(os.name == "nt", "Windows directory sharing guarantees")
    def test_guard_survives_between_publications_when_completed_file_is_removed(self):
        self.archive({"bundle/first.txt": b"first", "bundle/second.txt": b"second"})
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        # The same native mutation succeeds on an empty directory in this environment.
        empty = self.root / "empty"
        empty.mkdir()
        self.assertEqual(self.set_junction(empty, elsewhere), 0)
        original = payload._Destination.publish
        def attempt_between_files(destination, path, parent, data):
            original(destination, path, parent, data)
            if path.name == "first.txt":
                path.unlink()
                self.assertEqual(self.set_junction(path.parent, elsewhere), 145)
        with patch.object(payload._Destination, "publish", attempt_between_files):
            self.install()
        self.assertEqual((self.base / "bundle/second.txt").read_bytes(), b"second")
        self.assertEqual(list(elsewhere.iterdir()), [])
        self.assert_no_staging()

    @unittest.skipUnless(os.name == "nt", "Windows handle cleanup")
    def test_cleanup_error_closes_all_guards_and_directories(self):
        destination = payload._Destination()
        for name in ("first", "second"):
            directory = self.root / name
            directory.mkdir()
            destination.directory(directory, create=False)
            destination._guard_windows_directory(directory)
        expected = list(destination.guards.values()) + list(destination.directories.values())
        original_delete = destination._delete_windows
        original_close = destination.kernel.CloseHandle
        deleted, closed = [], []
        def delete_then_fail_once(handle):
            original_delete(handle)
            deleted.append(handle)
            if len(deleted) == 1:
                raise OSError("simulated cleanup failure")
        def close(handle):
            closed.append(handle)
            return original_close(handle)
        with patch.object(destination, "_delete_windows", side_effect=delete_then_fail_once), \
                patch.object(destination.kernel, "CloseHandle", side_effect=close):
            with self.assertRaisesRegex(OSError, "cleanup failure"):
                destination.__exit__(None, None, None)
        self.assertEqual(len(deleted), 2)
        self.assertCountEqual(closed, expected)

    def test_existing_symlink_parent_is_rejected(self):
        self.archive({"bundle/file.txt": b"embedded"})
        self.base.mkdir()
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        try:
            (self.base / "bundle").symlink_to(elsewhere, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"Symlink permission unavailable: {exc}")
        with self.assertRaises(RuntimeError):
            self.install()
        self.assertFalse((elsewhere / "file.txt").exists())


if __name__ == "__main__":
    unittest.main()
