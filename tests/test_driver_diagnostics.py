"""Read-only diagnostics tests: fake registry/SCM, never load a driver or bundled DLL."""
from contextlib import contextmanager
import ctypes
import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from zapret_ui import driver_diagnostics as diagnostics


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.adapter = SimpleNamespace(
            registry=Mock(return_value={"status": "present", "values": {
                "ImagePath": {"status": "present", "value": r"\??\C:\Old Zapret\WinDivert64.sys"}}}),
            service=Mock(return_value={"status": "present", "state": "stopped"}),
            dos_device=Mock(side_effect=FileNotFoundError("no target device")),
            architecture=Mock(return_value={"status": "present", "native": "x64"}),
            system_root=Mock(return_value={"status": "present", "path": r"C:\Windows"}))
        self.file_probe = patch.object(diagnostics, "probe_file", return_value={"status": "present", "matches": True})
        self.probe = self.file_probe.start()
        self.addCleanup(self.file_probe.stop)

    def collect(self):
        return diagnostics.collect_driver_diagnostics(Path(r"C:\Application\bundle"), adapter=self.adapter)

    def test_snapshot_queries_only_four_pinned_files_and_registered_sys(self):
        snapshot = self.collect()
        self.assertEqual(set(snapshot["files"]), set(diagnostics.NATIVE_HASHES))
        self.assertEqual(self.probe.call_count, 5)
        for call, (name, expected) in zip(self.probe.call_args_list, diagnostics.NATIVE_HASHES.items()):
            self.assertEqual(call.args[0].name, name)
            self.assertEqual(call.args[1], expected)
        self.assertEqual(str(self.probe.call_args_list[-1].args[0]), r"C:\Old Zapret\WinDivert64.sys")
        self.assertEqual(snapshot["dosDevice"]["status"], "missing")
        self.assertEqual(snapshot["service"]["state"], "stopped")
        self.assertEqual(snapshot["architecture"]["native"], "x64")

    def test_one_denied_query_is_unknown_and_does_not_hide_other_results(self):
        self.adapter.registry.side_effect = PermissionError("denied")
        snapshot = self.collect()
        self.assertEqual(snapshot["registry"]["status"], "unknown")
        self.assertEqual(snapshot["registeredDriverFile"]["status"], "unknown")
        self.assertEqual(snapshot["architecture"]["native"], "x64")
        self.assertEqual(self.probe.call_count, 4)
        self.assertNotIn("отсутствует", diagnostics.explain_driver_diagnostics(snapshot))

    def test_unc_device_and_relative_registration_never_reach_file_probe(self):
        for path in (r"\\server\share\driver.sys", r"\??\UNC\server\share\driver.sys",
                     r"\\?\UNC\server\share\driver.sys", r"\Device\HarddiskVolume1\driver.sys",
                     r"System32\drivers\driver.sys", r"%TEMP%\driver.sys", r"C:\private.txt"):
            with self.subTest(path=path):
                self.probe.reset_mock()
                self.adapter.registry.return_value["values"]["ImagePath"]["value"] = path
                snapshot = self.collect()
                self.assertEqual(self.probe.call_count, 4)
                self.assertEqual(snapshot["registeredDriverFile"]["status"], "unknown")

    def test_confirmed_missing_driver_and_stale_registration_are_explained(self):
        snapshot = {"files": {"WinDivert64.sys": {"status": "missing", "path": r"C:\bundle\bin\WinDivert64.sys"}},
                    "registeredDriverFile": {"status": "missing", "path": r"C:\old\WinDivert64.sys"}}
        message = diagnostics.explain_driver_diagnostics(snapshot)
        self.assertIn("В комплекте отсутствует WinDivert64.sys", message)
        self.assertIn("В регистрации WinDivert указан отсутствующий файл", message)

    def test_hash_mismatch_is_reported_without_guessing_a_cause(self):
        snapshot = {"files": {"WinDivert.dll": {"status": "present", "matches": False}}}
        message = diagnostics.explain_driver_diagnostics(snapshot)
        self.assertIn("Контрольная сумма WinDivert.dll отличается", message)
        self.assertNotIn("антивирус", message)


class PathNormalizationTests(unittest.TestCase):
    def test_supported_local_prefixes(self):
        for original in (r"C:\Windows\System32\drivers\WinDivert64.sys",
                         r"\??\C:\Windows\System32\drivers\WinDivert64.sys",
                         r"\\?\C:\Windows\System32\drivers\WinDivert64.sys",
                         r"\SystemRoot\System32\drivers\WinDivert64.sys",
                         r"%SYSTEMROOT%\System32\drivers\WinDivert64.sys",
                         '"C:\\Windows\\System32\\drivers\\WinDivert64.sys"'):
            with self.subTest(original=original):
                self.assertEqual(diagnostics.normalize_driver_path(original, r"C:\Windows"),
                                 r"C:\Windows\System32\drivers\WinDivert64.sys")

    def test_unsafe_or_ambiguous_paths_are_not_expanded(self):
        for value in (r"C:relative.sys", r"\??\UNC\server\share\driver.sys", r"\\.\WinDivert",
                      r"%windir%\driver.sys", r"C:\dir\..\driver.sys", r"C:\dir\driver.sys:stream",
                      '"C:\\dir\\driver.sys" --argument', r"C:\dir.\driver.sys", "C:\\bad\0.sys"):
            with self.subTest(value=value):
                self.assertIsNone(diagnostics.normalize_driver_path(value, r"C:\Windows"))
        self.assertIsNone(diagnostics.normalize_driver_path(r"\SystemRoot\driver.sys", r"\\server\Windows"))


class ProbeTests(unittest.TestCase):
    def test_file_hash_size_and_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "WinDivert64.sys"
            path.write_bytes(b"fixture")
            matched = diagnostics.probe_file(path, hashlib.sha256(b"fixture").hexdigest())
            self.assertEqual(matched["status"], "present")
            self.assertEqual(matched["size"], 7)
            self.assertEqual(matched["fileAttributes"], getattr(path.stat(), "st_file_attributes", None))
            self.assertTrue(matched["matches"])
            self.assertFalse(diagnostics.probe_file(path, "0" * 64)["matches"])

    def test_denied_stat_is_unknown_not_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "WinDivert64.sys"
            with patch.object(Path, "lstat", side_effect=PermissionError("denied")):
                result = diagnostics.probe_file(path)
            self.assertEqual(result["status"], "unknown")
            self.assertNotIn("matches", result)

    def test_missing_local_file_is_confirmed(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(diagnostics.probe_file(Path(directory) / "missing.sys")["status"], "missing")

    def test_unc_paths_are_rejected_without_filesystem_access(self):
        with patch.object(Path, "lstat", side_effect=AssertionError("No UNC access")):
            self.assertEqual(diagnostics.probe_file(Path(r"\\host\share\driver.sys"))["status"], "unknown")

    @unittest.skipUnless(os.name == "nt", "Windows mapped drive detection")
    def test_mapped_network_drive_is_rejected_without_filesystem_access(self):
        kernel = SimpleNamespace(GetDriveTypeW=Mock(return_value=4))
        with patch.object(diagnostics.ctypes, "WinDLL", return_value=kernel), \
                patch.object(Path, "lstat", side_effect=AssertionError("No network filesystem access")):
            result = diagnostics.probe_file(Path(r"Z:\driver.sys"))
        self.assertEqual(result["status"], "unknown")


class RegistryAndScmTests(unittest.TestCase):
    def setUp(self):
        self.reader = diagnostics.WindowsReader.__new__(diagnostics.WindowsReader)
        self.advapi = SimpleNamespace(OpenSCManagerW=Mock(return_value=11), OpenServiceW=Mock(return_value=22),
                                     QueryServiceStatusEx=Mock(), CloseServiceHandle=Mock())
        self.reader.advapi = self.advapi

    def test_scm_requests_only_connect_and_query_status_and_closes_handles(self):
        def query(handle, info_class, buffer, size, needed):
            status = ctypes.cast(buffer, ctypes.POINTER(diagnostics._ServiceStatus)).contents
            status.type, status.state, status.exitCode = 1, 4, 0
            return True
        self.advapi.QueryServiceStatusEx.side_effect = query
        result = self.reader.service()
        self.assertEqual(result["state"], "running")
        self.advapi.OpenSCManagerW.assert_called_once_with(None, None, 1)
        self.advapi.OpenServiceW.assert_called_once_with(11, "WinDivert", 4)
        self.assertEqual([call.args[0] for call in self.advapi.CloseServiceHandle.call_args_list], [22, 11])

    @unittest.skipUnless(os.name == "nt", "Windows error conversion")
    def test_missing_service_differs_from_access_denied(self):
        self.advapi.OpenServiceW.return_value = 0
        with patch.object(diagnostics.ctypes, "get_last_error", return_value=1060):
            self.assertEqual(diagnostics._capture(self.reader.service)["status"], "missing")
        with patch.object(diagnostics.ctypes, "get_last_error", return_value=5):
            self.assertEqual(diagnostics._capture(self.reader.service)["status"], "unknown")

    def test_registry_only_reads_four_typed_values_and_isolates_missing_value(self):
        requested = []
        @contextmanager
        def open_key(hive, key, reserved, access):
            self.assertEqual(key, diagnostics.SERVICE_KEY)
            self.assertEqual(access, 0x101)  # QUERY_VALUE | WOW64_64KEY
            yield 1
        def query(key, name):
            requested.append(name)
            if name == "ImagePath":
                return r"\SystemRoot\driver.sys", 2
            if name == "DeleteFlag":
                raise FileNotFoundError(name)
            return 3 if name == "Start" else 1, 4
        self.reader.reg = SimpleNamespace(HKEY_LOCAL_MACHINE=0, KEY_QUERY_VALUE=1, KEY_WOW64_64KEY=0x100,
                                          REG_SZ=1, REG_EXPAND_SZ=2, REG_DWORD=4,
                                          OpenKey=open_key, QueryValueEx=query)
        result = self.reader.registry()
        self.assertEqual(requested, ["ImagePath", "Start", "Type", "DeleteFlag"])
        self.assertEqual(result["values"]["DeleteFlag"]["status"], "missing")
        self.assertEqual(result["values"]["ImagePath"]["value"], r"\SystemRoot\driver.sys")

    def test_dos_device_is_targeted_and_bounded_and_native_architecture_is_used(self):
        def query(name, buffer, size):
            self.assertEqual(name, "WinDivert")
            self.assertEqual(size, 4096)
            value = "\\Device\\WinDivert\0\0"
            buffer[:len(value)] = value
            return len(value)
        def architecture(pointer):
            ctypes.cast(pointer, ctypes.POINTER(diagnostics._SystemInfo)).contents.architecture = 12
        self.reader.kernel = SimpleNamespace(QueryDosDeviceW=query, GetNativeSystemInfo=architecture)
        self.assertEqual(self.reader.dos_device()["targets"], [r"\Device\WinDivert"])
        self.assertEqual(self.reader.architecture()["native"], "arm64")


if __name__ == "__main__":
    unittest.main()
