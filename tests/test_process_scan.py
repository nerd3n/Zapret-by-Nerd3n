import ctypes
import os
import unittest
from unittest.mock import Mock, patch

from zapret_ui import process_scan as scan
from zapret_ui.controller import Controller


class FakeNative:
    def __init__(self, records=(), *, snapshot=0x123456789, fail_at=None,
                 error=5, close_ok=True):
        self.records = list(records)
        self.snapshot = snapshot
        self.fail_at = fail_at
        self.error = error
        self.close_ok = close_ok
        self.closed = []
        self.calls = []
        self.position = 0
        self.code = error

    def CreateToolhelp32Snapshot(self, flags, pid):
        self.calls.append(("snapshot", flags, pid))
        return self.snapshot

    def _advance(self, name, handle, pointer):
        self.calls.append((name, handle))
        entry = ctypes.cast(pointer, ctypes.POINTER(scan.PROCESSENTRY32W)).contents
        if entry.dwSize != ctypes.sizeof(scan.PROCESSENTRY32W):
            raise AssertionError("PROCESSENTRY32W.dwSize must be initialized")
        if self.position == self.fail_at:
            self.code = self.error
            return False
        if self.position >= len(self.records):
            self.code = scan.ERROR_NO_MORE_FILES
            return False
        entry.th32ProcessID, entry.szExeFile = self.records[self.position]
        self.position += 1
        return True

    def Process32FirstW(self, handle, pointer):
        return self._advance("first", handle, pointer)

    def Process32NextW(self, handle, pointer):
        return self._advance("next", handle, pointer)

    def CloseHandle(self, handle):
        self.closed.append(handle)
        self.code = 6
        return self.close_ok

    def last_error(self):
        return self.code


class ProcessScanTests(unittest.TestCase):
    def test_exact_case_insensitive_executable_names_and_full_handle(self):
        api = FakeNative([(101, "winws.exe"), (102, "WINWS2.EXE"),
                          (103, "WiNwS.ExE"), (104, "winws.exe.old"),
                          (105, "mywinws.exe"), (106, "winws3.exe"),
                          (107, "notepad.exe"), (108, "Система")])
        self.assertEqual(scan._scan(api), [101, 102, 103])
        self.assertEqual(api.closed, [0x123456789])
        self.assertEqual(api.calls[0], ("snapshot", scan.TH32CS_SNAPPROCESS, 0))
        self.assertEqual(api.calls[1], ("first", api.snapshot))
        self.assertTrue(all(call == ("next", api.snapshot) for call in api.calls[2:]))

    def test_empty_snapshot_closes_handle(self):
        api = FakeNative()
        self.assertEqual(scan._scan(api), [])
        self.assertEqual(api.closed, [api.snapshot])

    def test_invalid_snapshot_never_closed(self):
        for handle in (None, 0, scan.INVALID_HANDLE_VALUE):
            with self.subTest(handle=handle):
                api = FakeNative(snapshot=handle)
                with self.assertRaisesRegex(OSError, "CreateToolhelp32Snapshot"):
                    scan._scan(api)
                self.assertEqual(api.closed, [])

    def test_first_failure_is_not_an_empty_process_list(self):
        api = FakeNative(fail_at=0)
        with self.assertRaisesRegex(OSError, "Process32FirstW") as raised:
            scan._scan(api)
        self.assertEqual(raised.exception.errno, 5)
        self.assertEqual(api.closed, [api.snapshot])

    def test_next_failure_rejects_partial_results_and_closes(self):
        api = FakeNative([(101, "winws.exe")], fail_at=1)
        with self.assertRaisesRegex(OSError, "Process32NextW"):
            scan._scan(api)
        self.assertEqual(api.closed, [api.snapshot])

    def test_failure_without_last_error_is_still_failure(self):
        api = FakeNative(fail_at=0, error=0)
        with self.assertRaises(OSError):
            scan._scan(api)
        self.assertEqual(api.closed, [api.snapshot])

    def test_close_failure_is_reported(self):
        api = FakeNative(close_ok=False)
        with self.assertRaisesRegex(OSError, "CloseHandle"):
            scan._scan(api)
        self.assertEqual(api.closed, [api.snapshot])

    def test_original_error_survives_failed_cleanup(self):
        api = FakeNative(fail_at=0, error=5, close_ok=False)
        with self.assertRaisesRegex(OSError, "Process32FirstW") as raised:
            scan._scan(api)
        self.assertEqual(raised.exception.errno, 5)
        self.assertEqual(api.closed, [api.snapshot])

    def test_python_enumeration_exception_closes_handle(self):
        api = FakeNative()
        api.Process32FirstW = Mock(side_effect=ValueError("bad native data"))
        with self.assertRaisesRegex(ValueError, "bad native data"):
            scan._scan(api)
        self.assertEqual(api.closed, [api.snapshot])

    @unittest.skipUnless(os.name == "nt", "Windows Unicode ABI")
    def test_native_layout_and_function_types(self):
        is_64 = ctypes.sizeof(ctypes.c_void_p) == 8
        self.assertEqual(ctypes.sizeof(ctypes.c_wchar), 2)
        self.assertEqual(ctypes.sizeof(scan.PROCESSENTRY32W), 568 if is_64 else 556)
        self.assertEqual(scan.PROCESSENTRY32W.th32DefaultHeapID.offset, 16 if is_64 else 12)
        self.assertEqual(scan.PROCESSENTRY32W.szExeFile.offset, 44 if is_64 else 36)
        api = scan._Kernel32()
        self.assertIs(api.CreateToolhelp32Snapshot.restype, ctypes.c_void_p)
        self.assertEqual(api.CreateToolhelp32Snapshot.argtypes, [ctypes.c_uint32, ctypes.c_uint32])
        for function in (api.Process32FirstW, api.Process32NextW):
            self.assertEqual(function.argtypes, [ctypes.c_void_p, ctypes.POINTER(scan.PROCESSENTRY32W)])
            self.assertIs(function.restype, ctypes.c_int32)
        self.assertEqual(api.CloseHandle.argtypes, [ctypes.c_void_p])
        self.assertIs(api.CloseHandle.restype, ctypes.c_int32)

    def test_public_function_uses_scan(self):
        api = FakeNative([(42, "winws.exe")])
        with patch.object(scan.os, "name", "nt"), patch.object(scan, "_native_api", return_value=api):
            self.assertEqual(scan.winws_process_ids(), [42])

    def test_public_function_rejects_unsupported_platform(self):
        with patch.object(scan.os, "name", "posix"), patch.object(scan, "_native_api") as native:
            with self.assertRaises(OSError):
                scan.winws_process_ids()
            native.assert_not_called()


class ControllerProcessScanTests(unittest.TestCase):
    def controller(self, service=None, running=True):
        controller = Controller.__new__(Controller)
        controller.external_checked = 0
        controller.external_pids = []
        controller.proc = Mock(pid=101)
        controller.proc.poll.return_value = None if running else 1
        controller.refresh_service = Mock(return_value=service or {})
        return controller

    def test_excludes_only_running_owned_session_and_service(self):
        controller = self.controller({"owned": True, "running": True, "pid": 102})
        with patch("zapret_ui.controller.os.name", "nt"), \
                patch("zapret_ui.controller.winws_process_ids", return_value=[101, 102, 103]), \
                patch("zapret_ui.controller.subprocess.run") as run:
            result = controller.external_processes()
        self.assertEqual(result, [103])
        self.assertEqual(controller.external_pids, [103])
        self.assertIsNot(result, controller.external_pids)
        self.assertGreater(controller.external_checked, 0)
        run.assert_not_called()

    def test_foreign_or_stopped_service_is_not_excluded(self):
        for service in ({"owned": False, "running": True, "pid": 102},
                        {"owned": True, "running": False, "pid": 102}):
            with self.subTest(service=service):
                controller = self.controller(service, running=False)
                with patch("zapret_ui.controller.os.name", "nt"), \
                        patch("zapret_ui.controller.winws_process_ids", return_value=[101, 102]):
                    self.assertEqual(controller.external_processes(), [101, 102])

    def test_failed_scan_propagates_instead_of_reporting_no_conflicts(self):
        controller = self.controller()
        with patch("zapret_ui.controller.os.name", "nt"), \
                patch("zapret_ui.controller.winws_process_ids", side_effect=OSError("snapshot failed")):
            with self.assertRaises(OSError):
                controller.external_processes()
        self.assertGreater(controller.external_checked, 0)
        controller.refresh_service.assert_not_called()


if __name__ == "__main__":
    unittest.main()
