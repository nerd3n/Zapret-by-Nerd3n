"""SCM lifecycle tests use an injected adapter; no real services are changed."""
from __future__ import annotations

import copy
import ctypes
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from zapret_ui import windows_service as service
from zapret_ui.strategies import catalog


class FakeAdapter:
    supported = True

    def __init__(self, root):
        self.snapshot_root = root / "Program Files mock" / "ZapretByNerd3n-Service"
        self.admin = True
        self.raw = None
        self.legacy = False
        self.events = []
        self.clock = 0.0
        self.start_failure = self.stop_failure = self.delete_failure = False
        self.hang_start = self.hang_stop = False
        self.fail_validation = False
        self.mutate_copy = False
        self.delete_pending = 0
        self.read_error = False

    def is_admin(self):
        return self.admin

    def monotonic(self):
        return self.clock

    def sleep(self, seconds):
        self.clock += seconds

    def query(self):
        if self.read_error:
            raise service.ServiceError("SCM inaccessible")
        if self.raw is None and self.delete_pending:
            self.delete_pending -= 1
            raise service._MarkedForDeletion("pending")
        return copy.deepcopy(self.raw)

    def legacy_exists(self):
        return self.legacy

    def snapshot(self, source):
        destination = self.snapshot_root / ("snapshot-" + "a" * 32)
        self.events.append("snapshot")
        shutil.copytree(source, destination)
        if self.mutate_copy:
            path = destination / "general.bat"
            path.write_text(path.read_text(encoding="utf-8").replace("split-pos=1", "split-pos=2"), encoding="utf-8")
        return destination

    def validate_snapshot(self, path):
        if self.fail_validation:
            raise service.ServiceError("insecure snapshot")
        if path.parent != self.snapshot_root or not path.exists():
            raise service.ServiceError("missing snapshot")

    def cleanup_snapshot(self, path):
        self.events.append("cleanup")
        shutil.rmtree(path)

    def create(self, command, metadata):
        self.events.append("create")
        self.raw = {"state": "stopped", "pid": 0, "exitCode": 0, "serviceType": 16,
                    "startType": "automatic", "account": "LocalSystem", "imagePath": command,
                    "metadata": copy.deepcopy(metadata)}

    def start(self):
        self.events.append("start")
        if self.start_failure:
            raise service.ServiceError("start failed")
        self.raw.update(state="start_pending" if self.hang_start else "running", pid=1234)

    def stop(self):
        self.events.append("stop")
        if self.stop_failure:
            raise service.ServiceError("stop failed")
        self.raw.update(state="stop_pending" if self.hang_stop else "stopped", pid=0)

    def delete(self):
        self.events.append("delete")
        if self.delete_failure:
            raise service.ServiceError("delete failed")
        self.raw = None


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zapret service test ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.base = self.root / "app with spaces & кириллица"
        self.bundle = self.base / "bundle"
        (self.bundle / "bin").mkdir(parents=True)
        (self.bundle / "lists").mkdir()
        for name in service.NATIVE_HASHES:
            (self.bundle / "bin" / name).write_bytes(b"MZ-fixture-no-executable-code")
        for name in ("quic_initial_steamcommunity_com.bin", "quic_initial_4pda_to.bin"):
            (self.bundle / "bin" / name).write_bytes(b"fake-payload")
        (self.bundle / "lists" / "list-general.txt").write_text("youtube.com\n", encoding="ascii")
        (self.bundle / "general.bat").write_text(
            '@echo off\nstart "zapret" /min "%BIN%winws.exe" '
            '--wf-tcp=80,443,%GameFilterTCP% --wf-udp=443,%GameFilterUDP% '
            '--filter-tcp=443 --hostlist="%LISTS%list-general.txt" '
            '--dpi-desync=fake,multisplit --dpi-desync-split-pos=1 '
            '--dpi-desync-repeats=6 --dpi-desync-fake-tls=^!\n', encoding="utf-8")
        self.adapter = FakeAdapter(self.root)
        self.manager = service.ServiceManager(self.base, adapter=self.adapter, timeout=0.4)

    def install(self):
        return self.manager.install("stock-general")

    def test_install_uses_catalog_snapshot_and_automatic_service(self):
        result = self.install()
        self.assertTrue(result["installed"])
        self.assertTrue(result["owned"])
        self.assertTrue(result["running"])
        self.assertEqual(result["strategyId"], "stock-general")
        self.assertEqual(result["startType"], "automatic")
        self.assertEqual(self.adapter.events, ["snapshot", "create", "start"])
        self.assertNotIn(str(self.bundle), result["path"])
        snapshot = Path(self.adapter.raw["metadata"]["snapshot"])
        expected = next(item for item in catalog(snapshot) if item["id"] == "stock-general")
        self.assertEqual(result["path"], subprocess.list2cmdline(expected["argv"]))
        self.assertNotIn("--service", result["path"])
        self.assertTrue(result["path"].startswith('"'))

    def test_experimental_strategy_id_is_validated_through_catalog(self):
        result = self.manager.install("experiment-general-split-pos-2")
        self.assertEqual(result["strategyId"], "experiment-general-split-pos-2")
        self.assertIn("--dpi-desync-split-pos=2", result["path"])

    def test_start_rejects_exit_during_running_confirmation(self):
        self.install()
        self.manager.stop()
        self.adapter.events.clear()
        self.adapter.clock = 0
        self.manager.timeout = 5
        query = self.adapter.query

        def crash_after_running():
            if self.adapter.raw["state"] == "running" and self.adapter.clock >= 1:
                self.adapter.raw.update(state="stopped", pid=0, exitCode=87)
            return query()

        with patch.object(self.adapter, "query", side_effect=crash_after_running):
            with self.assertRaisesRegex(service.ServiceError, "сразу после запуска"):
                self.manager.start()
        self.assertEqual(self.adapter.events, ["start"])
        self.assertEqual(self.manager.status()["state"], "stopped")
        self.assertLess(self.adapter.clock, 3)

    def test_start_rejects_pid_change_during_running_confirmation(self):
        self.install()
        self.manager.stop()
        self.adapter.events.clear()
        self.adapter.clock = 0
        query = self.adapter.query

        def changed_pid():
            if self.adapter.raw["state"] == "running" and self.adapter.clock >= 0.15:
                self.adapter.raw["pid"] = 5678
            return query()

        with patch.object(self.adapter, "query", side_effect=changed_pid):
            with self.assertRaisesRegex(service.ServiceError, "Процесс службы изменился"):
                self.manager.start()
        self.assertEqual(self.adapter.events, ["start"])

    def test_start_pending_also_requires_stable_running_confirmation(self):
        self.install()
        self.adapter.raw.update(state="start_pending", pid=0)
        self.adapter.events.clear()
        self.adapter.clock = 0
        query = self.adapter.query

        def pending_then_running_then_crash():
            if self.adapter.clock >= 0.3:
                self.adapter.raw.update(state="stopped", pid=0, exitCode=87)
            elif self.adapter.clock >= 0.15:
                self.adapter.raw.update(state="running", pid=1234)
            return query()

        with patch.object(self.adapter, "query", side_effect=pending_then_running_then_crash):
            with self.assertRaisesRegex(service.ServiceError, "сразу после запуска"):
                self.manager.start()
        self.assertEqual(self.adapter.events, [])

    def test_successful_start_confirmation_is_bounded_to_three_seconds(self):
        self.manager.timeout = 30
        result = self.install()
        self.assertTrue(result["running"])
        self.assertAlmostEqual(self.adapter.clock, 3.0)

    def test_running_confirmation_rejects_missing_or_invalid_pid(self):
        self.install()
        for pid in (None, 0, -1, "1234"):
            with self.subTest(pid=pid):
                self.adapter.raw.update(state="running", pid=pid)
                with self.assertRaisesRegex(service.ServiceError, "не сообщила процесс"):
                    self.manager._confirm_running()

    def test_readonly_status_does_not_require_admin(self):
        self.install()
        self.adapter.admin = False
        before = self.adapter.events[:]
        self.assertTrue(self.manager.status()["running"])
        self.assertEqual(self.adapter.events, before)
        for operation in (self.install, self.manager.start, self.manager.stop, self.manager.remove):
            with self.assertRaisesRegex(service.ServiceError, "администратора"):
                operation()
        self.assertEqual(self.adapter.events, before)

    def test_existing_owned_service_cannot_be_reinstalled(self):
        self.install()
        before = copy.deepcopy(self.adapter.raw)
        self.adapter.events.clear()
        with self.assertRaisesRegex(service.ServiceError, "уже существует"):
            self.install()
        self.assertEqual(self.adapter.raw, before)
        self.assertEqual(self.adapter.events, [])

    def test_existing_legacy_service_blocks_install_even_if_stopped(self):
        self.adapter.legacy = True
        with self.assertRaisesRegex(service.ServiceError, "service.bat"):
            self.install()
        self.assertEqual(self.adapter.events, [])

    def test_legacy_service_never_blocks_removal_of_our_service(self):
        self.install()
        self.adapter.legacy = True
        result = self.manager.remove()
        self.assertFalse(result["installed"])
        self.assertTrue(self.adapter.legacy)

    def test_user_cannot_supply_commands_or_unknown_strategy(self):
        for value in ("calc.exe", "stock-general & whoami", "stock-general\x00", "stock-unknown", [], None):
            with self.subTest(value=value), self.assertRaises(service.ServiceError):
                self.manager.install(value)
        self.assertEqual(self.adapter.events, [])

    def test_snapshot_catalog_must_match_source_arguments(self):
        self.adapter.mutate_copy = True
        with self.assertRaisesRegex(service.ServiceError, "изменилась"):
            self.install()
        self.assertEqual(self.adapter.events, ["snapshot", "cleanup"])
        self.assertIsNone(self.adapter.raw)

    def test_snapshot_validation_failure_cleans_without_registering(self):
        self.adapter.fail_validation = True
        with self.assertRaisesRegex(service.ServiceError, "insecure"):
            self.install()
        self.assertEqual(self.adapter.events, ["snapshot", "cleanup"])

    def test_start_failure_rolls_back_service_and_snapshot(self):
        self.adapter.start_failure = True
        with self.assertRaisesRegex(service.ServiceError, "start failed"):
            self.install()
        self.assertEqual(self.adapter.events, ["snapshot", "create", "start", "delete", "cleanup"])
        self.assertFalse(self.manager.status()["installed"])

    def test_failed_rollback_keeps_executable_files_referenced_by_service(self):
        self.adapter.start_failure = self.adapter.delete_failure = True
        with self.assertRaisesRegex(service.ServiceError, "Откат не завершён"):
            self.install()
        self.assertTrue(Path(self.adapter.raw["metadata"]["snapshot"]).exists())
        self.assertNotIn("cleanup", self.adapter.events)
        self.assertTrue(self.manager.status()["owned"])

    def test_bounded_start_wait_and_failed_rollback_preserve_service(self):
        self.adapter.hang_start = True
        with self.assertRaisesRegex(service.ServiceError, "время ожидания"):
            self.install()
        self.assertLess(self.adapter.clock, 2.0)
        self.assertEqual(self.manager.status()["state"], "start_pending")
        self.assertNotIn("delete", self.adapter.events)
        self.assertNotIn("cleanup", self.adapter.events)

    def test_stop_timeout_does_not_delete_service_or_snapshot(self):
        self.install()
        self.adapter.hang_stop = True
        with self.assertRaisesRegex(service.ServiceError, "время ожидания"):
            self.manager.remove()
        self.assertEqual(self.manager.status()["state"], "stop_pending")
        self.assertNotIn("delete", self.adapter.events)
        self.assertNotIn("cleanup", self.adapter.events)

    def test_start_stop_are_idempotent_and_remove_waits_for_handles(self):
        self.install()
        self.manager.start()
        self.assertEqual(self.adapter.events.count("start"), 1)
        self.manager.stop()
        self.manager.stop()
        self.assertEqual(self.adapter.events.count("stop"), 1)
        self.manager.start()
        self.adapter.delete_pending = 2
        result = self.manager.remove()
        self.assertEqual(result["state"], "not_installed")
        self.assertEqual(self.adapter.events[-3:], ["stop", "delete", "cleanup"])

    def test_foreign_or_tampered_service_cannot_be_mutated(self):
        self.install()
        valid = copy.deepcopy(self.adapter.raw)
        changes = [lambda raw: raw.update(metadata=None),
                   lambda raw: raw["metadata"].update(owner="another-app"),
                   lambda raw: raw["metadata"].update(snapshot=str(self.base)),
                   lambda raw: raw["metadata"].update(strategyId="& calc"),
                   lambda raw: raw.update(imagePath=raw["imagePath"] + " --debug"),
                   lambda raw: raw.update(serviceType=32),
                   lambda raw: raw.update(account="SomeUser")]
        for change in changes:
            self.adapter.raw = copy.deepcopy(valid)
            change(self.adapter.raw)
            self.adapter.events.clear()
            with self.subTest(change=change):
                state = self.manager.status()
                self.assertTrue(state["installed"])
                self.assertFalse(state["owned"])
                self.assertIsNotNone(state["error"])
                for operation in (self.manager.start, self.manager.stop, self.manager.remove):
                    with self.assertRaisesRegex(service.ServiceError, "Владение"):
                        operation()
                self.assertEqual(self.adapter.events, [])

    def test_start_refuses_snapshot_with_changed_acl_or_content(self):
        self.install()
        self.manager.stop()
        self.adapter.events.clear()
        self.adapter.fail_validation = True
        with self.assertRaisesRegex(service.ServiceError, "insecure"):
            self.manager.start()
        self.assertEqual(self.adapter.events, [])
        # Removing our stopped service remains possible if its copy is damaged.
        self.manager.remove()

    def test_read_failure_is_visible_and_never_treated_as_success(self):
        self.adapter.read_error = True
        result = self.manager.status()
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["error"], "SCM inaccessible")
        with self.assertRaises(service.ServiceError):
            self.install()
        self.assertEqual(self.adapter.events, [])

    def test_unsupported_platform_has_readonly_status_and_refuses_changes(self):
        self.adapter.supported = False
        self.assertEqual(self.manager.status()["state"], "unsupported")
        for operation in (self.install, self.manager.start, self.manager.stop, self.manager.remove):
            with self.assertRaisesRegex(service.ServiceError, "Windows"):
                operation()
        self.assertEqual(self.adapter.events, [])

    def test_marked_for_deletion_wait_is_bounded_and_keeps_snapshot(self):
        self.install()
        snapshot = Path(self.adapter.raw["metadata"]["snapshot"])
        self.adapter.delete_pending = 100
        with self.assertRaisesRegex(service.ServiceError, "помечена для удаления"):
            self.manager.remove()
        self.assertLess(self.adapter.clock, 1.0)
        self.assertTrue(snapshot.exists())
        self.assertNotIn("cleanup", self.adapter.events)

    def test_reparse_attribute_is_rejected_without_symlink_privileges(self):
        real_lstat = Path.lstat
        source_bin = self.bundle / "bin"

        def lstat(path):
            actual = real_lstat(path)
            if path == source_bin:
                class Junction:
                    st_mode = actual.st_mode
                    st_file_attributes = 0x400
                return Junction()
            return actual

        with patch.object(Path, "lstat", lstat):
            with self.assertRaisesRegex(service.ServiceError, "reparse"):
                self.install()
        self.assertEqual(self.adapter.events, [])

    def test_arg_paths_are_remapped_only_inside_bundle(self):
        target = self.root / "snapshot"
        exe = str(self.bundle / "bin" / "winws.exe")
        for argument in ("--hostlist=" + str(self.root / "outside.txt"),
                         "--hostlist=" + str(self.bundle / "lists" / ".." / ".." / "outside.txt"),
                         "--hostlist=" + str(self.bundle / "lists" / "deep" / "list.txt"),
                         "--unknown=" + str(self.bundle / "lists" / "list-general.txt")):
            with self.subTest(argument=argument), self.assertRaises(service.ServiceError):
                service.remap_argv([exe, argument], self.bundle, target)
        with self.assertRaises(service.ServiceError):
            service.remap_argv([str(self.base / "other.exe")], self.bundle, target)
        result = service.remap_argv([exe, "--dpi-desync-fake-tls=!", "--dpi-desync-fake-quic=0x00"], self.bundle, target)
        self.assertEqual(result[1:], ["--dpi-desync-fake-tls=!", "--dpi-desync-fake-quic=0x00"])

    def test_hardlinks_are_rejected_before_catalog_or_snapshot(self):
        original = self.bundle / "lists" / "list-general.txt"
        linked = self.root / "linked.txt"
        try:
            os.link(original, linked)
        except OSError as exc:
            self.skipTest(str(exc))
        with self.assertRaisesRegex(service.ServiceError, "hard links"):
            self.install()
        self.assertEqual(self.adapter.events, [])

    def test_symlink_bundle_is_rejected_before_snapshot(self):
        original = self.bundle / "lists" / "list-general.txt"
        linked = self.bundle / "lists" / "link.txt"
        try:
            linked.symlink_to(original)
        except OSError as exc:
            self.skipTest(str(exc))
        with self.assertRaisesRegex(service.ServiceError, "reparse"):
            self.install()
        self.assertEqual(self.adapter.events, [])

    def test_native_hash_mismatch_rejects_any_modified_binary(self):
        hashes = {name: hashlib.sha256((self.bundle / "bin" / name).read_bytes()).hexdigest()
                  for name in service.NATIVE_HASHES}
        with patch.object(service, "NATIVE_HASHES", hashes):
            service._check_native_hashes(self.bundle)
            (self.bundle / "bin" / "WinDivert.dll").write_bytes(b"replacement")
            with self.assertRaisesRegex(service.ServiceError, "WinDivert.dll"):
                service._check_native_hashes(self.bundle)


@unittest.skipUnless(os.name == "nt", "Native security descriptors require Windows")
class NativeReadonlyTests(unittest.TestCase):
    """Only parse descriptors in memory/read HKLM; never create any SCM objects."""

    def setUp(self):
        self.adapter = service.WindowsAdapter()

    def test_file_and_registry_security_descriptors_have_expected_permissions(self):
        for text, registry in ((service.FILE_SDDL, False), (service.KEY_SDDL, True)):
            with self.subTest(registry=registry), self.adapter._descriptor(text) as descriptor:
                self.adapter._check_descriptor(descriptor, registry=registry)

    def test_writable_users_unprotected_or_wrong_owner_descriptors_are_rejected(self):
        descriptors = [service.FILE_SDDL.replace("0x1200a9", "FA"),
                       service.FILE_SDDL.replace("D:P", "D:"),
                       service.FILE_SDDL.replace("O:BA", "O:BU"),
                       service.FILE_SDDL + "(A;OICI;FA;;;WD)",
                       service.FILE_SDDL.replace("(A;OICI;FA;;;SY)", "")]
        for text in descriptors:
            with self.subTest(text=text), self.adapter._descriptor(text) as descriptor:
                with self.assertRaises(service.ServiceError):
                    self.adapter._check_descriptor(descriptor)

    def test_windows_command_line_round_trips_spaces_unicode_and_bang(self):
        # CommandLineToArgvW has the same escaping rules used for these arguments.
        shell = ctypes.WinDLL("shell32", use_last_error=True)
        shell.CommandLineToArgvW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
        shell.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
        args = [r"C:\Program Files\ZapretByNerd3n-Service\bin\winws.exe", "--wf-tcp=443",
                r"--hostlist=C:\Program Files\тест & списки\lists\list-general.txt", "--dpi-desync-fake-tls=!"]
        count = ctypes.c_int()
        pointer = shell.CommandLineToArgvW(subprocess.list2cmdline(args), ctypes.byref(count))
        self.assertTrue(pointer)
        try:
            self.assertEqual([pointer[index] for index in range(count.value)], args)
        finally:
            self.adapter.kernel.LocalFree(pointer)

    def test_native_reader_checks_handle_without_mutating_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.txt"
            path.write_bytes(b"readonly fixture")
            with self.adapter._file_handle(Path(directory), directory=True):
                with self.adapter._file_handle(path) as handle:
                    buffer, count = ctypes.create_string_buffer(64), ctypes.wintypes.DWORD()
                    self.assertTrue(self.adapter.kernel.ReadFile(handle, buffer, len(buffer), ctypes.byref(count), None))
                    self.assertEqual(buffer.raw[:count.value], b"readonly fixture")
            self.assertEqual(path.read_bytes(), b"readonly fixture")


class PinnedBundleTests(unittest.TestCase):
    def test_real_bundle_native_hashes_and_all_catalog_argument_remaps(self):
        bundle = Path(__file__).resolve().parents[1] / "bundle"
        if not bundle.is_dir():
            self.skipTest("The pinned bundle is absent from this source-only checkout")
        service._bundle_files(bundle)
        service._check_native_hashes(bundle)
        strategies = catalog(bundle)
        self.assertGreaterEqual(len(strategies), 28)
        destination = bundle.parent / "service snapshot fixture"
        for strategy in strategies:
            with self.subTest(strategy=strategy["id"]):
                args = service.remap_argv(strategy["argv"], bundle, destination)
                self.assertEqual(Path(args[0]), destination / "bin" / "winws.exe")
                self.assertNotIn(str(bundle), subprocess.list2cmdline(args))


if __name__ == "__main__":
    unittest.main()
