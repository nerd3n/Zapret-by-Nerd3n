"""Update preflight regressions; only fixture servers and temporary files.

No test contacts a user's running UI or stops an engine/service.
"""
from contextlib import ExitStack
import importlib
import hashlib
import json
import os
from pathlib import Path
import runpy
import socket
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import Mock, patch


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.requests.append((self.command, self.path, dict(self.headers), body))
        status, payload, headers = self.server.responses.get(self.path, (404, {"error": "fixture route missing"}, {}))
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass


class FixtureServer:
    def __init__(self, responses):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        self.server.daemon_threads = True
        self.server.responses = responses
        self.server.requests = []
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self.server

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class UpdateHttpTests(unittest.TestCase):
    def setUp(self):
        self.helper = importlib.import_module("zapret_ui.update_helper")
        self.temporary = tempfile.TemporaryDirectory(prefix="zapret update test ")
        self.addCleanup(self.temporary.cleanup)
        self.app = Path(self.temporary.name) / "app with spaces"
        self.app.mkdir()
        self.responses = {
            "/api/state": (200, {"bundlePath": str(self.app / "bundle")}, {}),
            "/api/session": (200, {"token": "fixture-token-01234567890123456789"}, {}),
            "/api/exit": (200, {"ok": True}, {}),
        }

    def test_verified_directory_and_custom_port_send_authenticated_exit(self):
        with FixtureServer(self.responses) as server:
            self.assertTrue(self.helper.request_exit(server.server_port, self.app))
        self.assertEqual([(row[0], row[1]) for row in server.requests],
                         [("GET", "/api/state"), ("GET", "/api/session"), ("POST", "/api/exit")])
        method, path, headers, body = server.requests[-1]
        self.assertEqual(headers.get("Host"), f"127.0.0.1:{server.server_port}")
        self.assertEqual(headers.get("Origin"), f"http://127.0.0.1:{server.server_port}")
        self.assertEqual(headers.get("X-Zapret-Token"), "fixture-token-01234567890123456789")
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertEqual(json.loads(body), {})

    def test_different_directory_never_fetches_session_or_posts_exit(self):
        self.responses["/api/state"] = (200, {"bundlePath": str(self.app.parent / "another-app" / "bundle")}, {})
        with FixtureServer(self.responses) as server:
            self.assertFalse(self.helper.request_exit(server.server_port, self.app))
        self.assertEqual([(row[0], row[1]) for row in server.requests], [("GET", "/api/state")])

    def test_similar_directory_prefix_does_not_count_as_same_installation(self):
        self.responses["/api/state"] = (200, {"bundlePath": str(self.app.parent / (self.app.name + "-other") / "bundle")}, {})
        with FixtureServer(self.responses) as server:
            self.assertFalse(self.helper.request_exit(server.server_port, self.app))
        self.assertFalse(any(row[0] == "POST" for row in server.requests))

    def test_environment_proxy_cannot_intercept_loopback_request(self):
        proxy = "http://127.0.0.1:1"
        with FixtureServer(self.responses) as server, patch.dict(os.environ, {
                "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "ALL_PROXY": proxy,
                "http_proxy": proxy, "https_proxy": proxy, "all_proxy": proxy, "NO_PROXY": "", "no_proxy": ""}):
            result = self.helper._request(server.server_port, "GET", "/api/state")
        self.assertEqual(result["bundlePath"], str(self.app / "bundle"))
        self.assertEqual(len(server.requests), 1)

    def test_redirect_is_an_error_and_never_followed(self):
        responses = {"/api/state": (302, {}, {"Location": "/must-not-follow"}),
                     "/must-not-follow": (200, {"bundlePath": str(self.app / "bundle")}, {})}
        with FixtureServer(responses) as server:
            with self.assertRaises((self.helper.UpdateError, ValueError)):
                self.helper._request(server.server_port, "GET", "/api/state")
        self.assertEqual([row[1] for row in server.requests], ["/api/state"])

    def test_http_errors_and_malformed_json_never_return_success_objects(self):
        for status, payload in ((403, {"error": "denied"}), (500, {"error": "server error"}),
                                (200, b"not json"), (200, []), (200, None)):
            with self.subTest(status=status, payload=payload), \
                    FixtureServer({"/api/state": (status, payload, {})}) as server:
                with self.assertRaises((self.helper.UpdateError, ValueError)):
                    self.helper._request(server.server_port, "GET", "/api/state")


    def test_invalid_or_missing_bundle_path_never_posts_exit(self):
        for value in (None, "bundle", [], 42, ""):
            with self.subTest(value=value):
                self.responses["/api/state"] = (200, {"bundlePath": value}, {})
                with FixtureServer(self.responses) as server:
                    self.assertFalse(self.helper.request_exit(server.server_port, self.app))
                self.assertEqual([row[1] for row in server.requests], ["/api/state"])

    def test_missing_invalid_or_header_injection_token_never_posts_exit(self):
        for value in (None, "short", "x" * 513, "токен" * 5, "x" * 20 + "\r\nInjected: value"):
            with self.subTest(value=value):
                self.responses["/api/session"] = (200, {"token": value}, {})
                with FixtureServer(self.responses) as server:
                    with self.assertRaises((self.helper.UpdateError, ValueError)):
                        self.helper.request_exit(server.server_port, self.app)
                self.assertFalse(any(row[0] == "POST" for row in server.requests))

    def test_exit_http_denial_is_not_reported_as_success(self):
        self.responses["/api/exit"] = (403, {"error": "invalid session"}, {})
        with FixtureServer(self.responses) as server:
            with self.assertRaises(self.helper.UpdateError):
                self.helper.request_exit(server.server_port, self.app)
        self.assertEqual(server.requests[-1][1], "/api/exit")

    def test_response_limit_rejects_oversize_before_parsing(self):
        body = b" " * (self.helper.MAX_RESPONSE + 1)
        with FixtureServer({"/api/state": (200, body, {})}) as server:
            with self.assertRaisesRegex(self.helper.UpdateError, "большой"):
                self.helper._request(server.server_port, "GET", "/api/state")

    def test_timeout_closes_connection_and_preserves_exception(self):
        connection = Mock()
        connection.getresponse.side_effect = TimeoutError("fixture timeout")
        with patch.object(self.helper, "HTTPConnection", return_value=connection) as create:
            with self.assertRaises(TimeoutError):
                self.helper._request(19443, "GET", "/api/state", timeout=0.125)
        create.assert_called_once_with("127.0.0.1", 19443, timeout=0.125)
        connection.close.assert_called_once()


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.helper = importlib.import_module("zapret_ui.update_helper")
        self.temp = tempfile.TemporaryDirectory(prefix="zapret discovery ")
        self.addCleanup(self.temp.cleanup)
        self.app = Path(self.temp.name) / "installed app"
        self.app.mkdir()

    def test_candidate_ports_require_exact_executable_path_and_owner_pid(self):
        canonical = self.helper._canonical
        paths = {101: canonical(self.app / self.helper.APP_EXE),
                 102: canonical(self.app.parent / "another" / self.helper.APP_EXE),
                 103: canonical(self.app / "Other.exe"),
                 104: canonical(self.app.parent / (self.app.name + "-other") / self.helper.APP_EXE)}
        listeners = [(101, 19321), (101, 17842), (101, 19321), (102, 17841),
                     (103, 19444), (104, 19555), (999, 19666)]
        with patch.object(self.helper, "_process_paths", return_value=paths), \
                patch.object(self.helper, "_listener_rows", return_value=listeners):
            self.assertEqual(self.helper.candidate_ports(self.app), [17842, 19321])

    def test_no_named_process_means_no_candidate_ports(self):
        with patch.object(self.helper, "_process_paths", return_value={}), \
                patch.object(self.helper, "_listener_rows", return_value=[(999, 17841)]):
            self.assertEqual(self.helper.candidate_ports(self.app), [])

    @unittest.skipUnless(os.name == "nt", "Windows native ctypes")
    def test_tcp_reader_keeps_only_ipv4_loopback_listeners_and_decodes_port(self):
        import ctypes
        import struct
        def row(state, ip, port, pid):
            address, = struct.unpack("<I", socket.inet_aton(ip))
            return struct.pack("<6I", state, address, socket.htons(port), 0, 0, pid)
        rows = [row(2, "127.0.0.1", 17841, 101), row(2, "127.0.0.1", 54321, 102),
                row(5, "127.0.0.1", 11111, 103), row(2, "0.0.0.0", 22222, 104),
                row(2, "127.0.0.2", 33333, 105), row(2, "192.0.2.1", 44444, 106)]
        data = struct.pack("<I", len(rows)) + b"".join(rows)
        calls = []
        def table(buffer, size, ordered, family, kind, reserved):
            calls.append((family, kind, reserved))
            size._obj.value = len(data)
            if buffer is None:
                return 122
            ctypes.memmove(buffer, data, len(data))
            return 0
        function = Mock(side_effect=table)
        with patch.object(self.helper.ctypes, "WinDLL", return_value=SimpleNamespace(GetExtendedTcpTable=function)):
            self.assertEqual(self.helper._listener_rows(), [(101, 17841), (102, 54321)])
        self.assertEqual(calls, [(2, 3, 0), (2, 3, 0)])
        self.assertIs(function.restype, ctypes.c_uint32)

    @unittest.skipUnless(os.name == "nt", "Windows native ctypes")
    def test_tcp_table_errors_and_unbounded_growth_fail_closed(self):
        def growing(buffer, size, *args):
            size._obj.value = 128
            return 122
        for side_effect in (lambda *args: 5, growing):
            function = Mock(side_effect=side_effect)
            with self.subTest(side_effect=side_effect), \
                    patch.object(self.helper.ctypes, "WinDLL", return_value=SimpleNamespace(GetExtendedTcpTable=function)):
                with self.assertRaises(self.helper.UpdateError):
                    self.helper._listener_rows()
            self.assertLessEqual(function.call_count, 4)

    @unittest.skipUnless(os.name == "nt", "Windows native ctypes")
    def test_process_discovery_queries_only_exact_name_and_closes_all_handles(self):
        import ctypes
        records = [(101, "ZAPRETBYNERD3N.EXE"), (102, "ZapretByNerd3n.exe.old"),
                   (103, "Other.exe"), (104, "ZapretByNerd3n.exe")]
        position = 0
        def advance(snapshot, pointer):
            nonlocal position
            if position == len(records):
                return False
            entry = ctypes.cast(pointer, ctypes.POINTER(self.helper.PROCESSENTRY32W)).contents
            self.assertEqual(entry.dwSize, ctypes.sizeof(entry))
            entry.th32ProcessID, entry.szExeFile = records[position]
            position += 1
            return True
        api = SimpleNamespace(CreateToolhelp32Snapshot=Mock(return_value=12345678901),
                              Process32FirstW=Mock(side_effect=advance), Process32NextW=Mock(side_effect=advance),
                              last_error=Mock(return_value=18), CloseHandle=Mock(return_value=True))
        def query(handle, flags, buffer, length):
            self.assertEqual(handle, 777)
            buffer.value = str(self.app / self.helper.APP_EXE)
            length._obj.value = len(buffer.value)
            return True
        kernel = SimpleNamespace(OpenProcess=Mock(side_effect=[777, None]), QueryFullProcessImageNameW=Mock(side_effect=query))
        with patch.object(self.helper, "_native_api", return_value=api), patch.object(self.helper.ctypes, "WinDLL", return_value=kernel):
            self.assertEqual(self.helper._process_paths(), {101: self.helper._canonical(self.app / self.helper.APP_EXE)})
        self.assertEqual([call.args for call in kernel.OpenProcess.call_args_list], [(0x1000, False, 101), (0x1000, False, 104)])
        self.assertEqual([call.args[0] for call in api.CloseHandle.call_args_list], [777, 12345678901])
        self.assertIs(kernel.OpenProcess.restype, ctypes.c_void_p)

    @unittest.skipUnless(os.name == "nt", "Windows native ctypes")
    def test_process_query_exception_still_closes_process_and_snapshot(self):
        import ctypes
        def first(snapshot, pointer):
            entry = ctypes.cast(pointer, ctypes.POINTER(self.helper.PROCESSENTRY32W)).contents
            entry.th32ProcessID, entry.szExeFile = 101, self.helper.APP_EXE
            return True
        api = SimpleNamespace(CreateToolhelp32Snapshot=Mock(return_value=555), Process32FirstW=Mock(side_effect=first),
                              Process32NextW=Mock(), CloseHandle=Mock(return_value=True), last_error=Mock(return_value=5))
        kernel = SimpleNamespace(OpenProcess=Mock(return_value=777), QueryFullProcessImageNameW=Mock(side_effect=OSError("query failed")))
        with patch.object(self.helper, "_native_api", return_value=api), patch.object(self.helper.ctypes, "WinDLL", return_value=kernel):
            with self.assertRaises(OSError):
                self.helper._process_paths()
        self.assertEqual([call.args[0] for call in api.CloseHandle.call_args_list], [777, 555])


class LockProbeTests(unittest.TestCase):
    def setUp(self):
        self.helper = importlib.import_module("zapret_ui.update_helper")

    @unittest.skipUnless(os.name == "nt", "Windows native ctypes")
    def test_replacement_probe_uses_open_existing_and_never_mutates_file(self):
        import ctypes
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.exe"
            path.write_bytes(b"fixture contents must survive")
            kernel = SimpleNamespace(CreateFileW=Mock(return_value=0x123456789), CloseHandle=Mock(return_value=True))
            with patch.object(self.helper.ctypes, "WinDLL", return_value=kernel):
                self.assertEqual(self.helper._replacement_error(path), 0)
            kernel.CreateFileW.assert_called_once_with(str(path), 0x40010000, 0, None, 3, 0, None)
            kernel.CloseHandle.assert_called_once_with(0x123456789)
            self.assertIs(kernel.CreateFileW.restype, ctypes.c_void_p)
            self.assertEqual(path.read_bytes(), b"fixture contents must survive")

    @unittest.skipUnless(os.name == "nt", "Windows native ctypes")
    def test_missing_files_are_clear_but_sharing_and_permission_errors_are_preserved(self):
        for code in (2, 3, 5, 32, 33):
            kernel = SimpleNamespace(CreateFileW=Mock(return_value=self.helper.INVALID_HANDLE_VALUE), CloseHandle=Mock())
            with self.subTest(code=code), patch.object(self.helper.ctypes, "WinDLL", return_value=kernel), \
                    patch.object(self.helper.ctypes, "get_last_error", return_value=code):
                self.assertEqual(self.helper._replacement_error(Path("fixture.exe")), 0 if code in (2, 3) else code)
            kernel.CloseHandle.assert_not_called()

    def test_blocked_files_cover_executable_and_native_bundle_binaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "bundle/bin"
            binary.mkdir(parents=True)
            for name in ("winws.exe", "WinDivert64.sys", "WinDivert.dll", "README.txt"):
                (binary / name).write_bytes(b"fixture")
            with patch.object(self.helper, "_replacement_error", side_effect=lambda path: 32 if path.suffix.lower() == ".exe" else 0) as probe:
                blocked = self.helper.blocked_files(root)
            checked = {call.args[0] for call in probe.call_args_list}
            self.assertEqual(checked, {root / self.helper.APP_EXE, binary / "winws.exe", binary / "WinDivert64.sys", binary / "WinDivert.dll"})
            self.assertEqual(set(blocked), {(root / self.helper.APP_EXE, 32), (binary / "winws.exe", 32)})


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        if seconds <= 0:
            raise AssertionError("busy-wait")
        self.sleeps.append(seconds)
        self.now += seconds


class PrepareUpdateTests(unittest.TestCase):
    def setUp(self):
        self.helper = importlib.import_module("zapret_ui.update_helper")
        self.temp = tempfile.TemporaryDirectory(prefix="zapret prepare ")
        self.addCleanup(self.temp.cleanup)
        self.app = Path(self.temp.name)
        self.clock = FakeClock()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(self.helper.os, "name", "nt"))
        self.stack.enter_context(patch.object(self.helper.time, "monotonic", side_effect=self.clock.monotonic))
        self.stack.enter_context(patch.object(self.helper.time, "sleep", side_effect=self.clock.sleep))

    def test_exit_discovery_precedes_even_an_initially_clear_file_probe(self):
        sequence = []
        def discover(path):
            sequence.append("discover")
            return [19321]
        def request(port, path, timeout):
            sequence.append(("exit", port))
            return True
        def probe(path):
            sequence.append("probe")
            return []
        with patch.object(self.helper, "candidate_ports", side_effect=discover), \
                patch.object(self.helper, "request_exit", side_effect=request), \
                patch.object(self.helper, "blocked_files", side_effect=probe):
            self.helper.prepare_update(self.app, timeout=2)
        self.assertEqual(sequence, ["discover", ("exit", 19321), "probe"])
        self.assertEqual(self.clock.sleeps, [])

    def test_waits_until_locks_clear_and_does_not_repeat_successful_exit(self):
        locked = [(self.app / self.helper.APP_EXE, 32)]
        with patch.object(self.helper, "candidate_ports", return_value=[19321]) as discover, \
                patch.object(self.helper, "request_exit", return_value=True) as request, \
                patch.object(self.helper, "blocked_files", side_effect=[locked, locked, []]) as probe:
            self.helper.prepare_update(self.app, timeout=3)
        self.assertEqual(discover.call_count, 3)
        self.assertEqual(probe.call_count, 3)
        request.assert_called_once()
        self.assertEqual(self.clock.sleeps, [0.5, 0.5])

    def test_rechecks_discovery_for_an_app_that_appears_during_wait(self):
        locked = [(self.app / self.helper.APP_EXE, 32)]
        with patch.object(self.helper, "candidate_ports", side_effect=[[], [19999]]), \
                patch.object(self.helper, "request_exit", return_value=True) as request, \
                patch.object(self.helper, "blocked_files", side_effect=[locked, []]):
            self.helper.prepare_update(self.app, timeout=3)
        self.assertEqual(request.call_args.args[:2], (19999, self.app.resolve()))

    def test_http_disconnect_is_tolerated_only_when_files_are_free(self):
        with patch.object(self.helper, "candidate_ports", return_value=[19321]), \
                patch.object(self.helper, "request_exit", side_effect=ConnectionResetError("app exited")), \
                patch.object(self.helper, "blocked_files", return_value=[]):
            self.helper.prepare_update(self.app, timeout=1)
        self.assertEqual(self.clock.sleeps, [])

    def test_deadline_is_bounded_and_identifies_remaining_lock(self):
        with patch.object(self.helper, "candidate_ports", return_value=[19321]), \
                patch.object(self.helper, "request_exit", side_effect=TimeoutError("app busy")) as request, \
                patch.object(self.helper, "blocked_files", return_value=[(self.app / self.helper.APP_EXE, 32)]):
            with self.assertRaisesRegex(self.helper.UpdateBlocked, "ZapretByNerd3n.exe"):
                self.helper.prepare_update(self.app, timeout=1.1)
        self.assertAlmostEqual(self.clock.now, 1.1)
        self.assertEqual(len(self.clock.sleeps), 3)
        for call in request.call_args_list:
            self.assertGreater(call.kwargs["timeout"], 0)
            self.assertLessEqual(call.kwargs["timeout"], 1.1 / 3)

    def test_wrong_app_is_not_marked_successfully_requested_or_force_closed(self):
        locked = [(self.app / self.helper.APP_EXE, 32)]
        with patch.object(self.helper, "candidate_ports", return_value=[19321]), \
                patch.object(self.helper, "request_exit", return_value=False) as request, \
                patch.object(self.helper, "blocked_files", side_effect=[locked, []]):
            self.helper.prepare_update(self.app, timeout=1)
        self.assertEqual(request.call_count, 2)

    def test_discovery_failure_is_not_treated_as_permission_to_replace(self):
        with patch.object(self.helper, "candidate_ports", side_effect=OSError("cannot inspect owner")), \
                patch.object(self.helper, "blocked_files") as probe:
            with self.assertRaises(OSError):
                self.helper.prepare_update(self.app)
        probe.assert_not_called()

    def test_relative_path_is_rejected_before_native_or_http_calls(self):
        with patch.object(self.helper, "candidate_ports") as discover:
            with self.assertRaises(self.helper.UpdateError):
                self.helper.prepare_update(Path("relative-folder"))
        discover.assert_not_called()

    def test_helper_maps_success_busy_and_other_errors_to_exit_codes(self):
        for error, expected in ((None, 0), (self.helper.UpdateBlocked("busy"), 10),
                                (self.helper.UpdateError("invalid"), 11), (OSError("denied"), 11)):
            with self.subTest(error=error), patch.object(self.helper, "prepare_update", side_effect=error) as prepare:
                self.assertEqual(self.helper.run_update_helper(str(self.app)), expected)
            prepare.assert_called_once_with(self.app)


class UpdateCliTests(unittest.TestCase):
    def setUp(self):
        self.helper = importlib.import_module("zapret_ui.update_helper")
        self.main = importlib.import_module("main")
        self.app = str(Path(tempfile.gettempdir()).resolve() / "fixture update app")

    @unittest.skipUnless(os.name == "nt", "Windows elevation boundary")
    def test_prepare_update_returns_before_controller_or_elevation(self):
        with patch.object(sys, "argv", ["app.exe", "--prepare-update", self.app, "--elevate"]), \
                patch.object(self.helper, "run_update_helper", return_value=10) as helper, \
                patch.object(self.main, "Controller") as controller, patch.object(self.main, "LocalServer") as server, \
                patch.object(self.main, "run_desktop") as desktop, \
                patch.object(self.main.ctypes.windll.shell32, "IsUserAnAdmin") as admin, \
                patch.object(self.main.ctypes.windll.shell32, "ShellExecuteW") as elevate, \
                patch.object(self.main.ctypes.windll.user32, "MessageBoxW") as dialog:
            self.assertEqual(self.main.main(), 10)
        helper.assert_called_once_with(self.app)
        for forbidden in (controller, server, desktop, admin, elevate, dialog):
            forbidden.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows frozen entrypoint")
    def test_frozen_entrypoint_propagates_all_helper_exit_codes_without_dialog(self):
        for code in (0, 10, 11):
            with self.subTest(code=code), \
                    patch.object(sys, "argv", ["app.exe", "--prepare-update", self.app, "--elevate"]), \
                    patch.object(sys, "frozen", True, create=True), \
                    patch.object(self.helper, "run_update_helper", return_value=code), \
                    patch("zapret_ui.controller.Controller") as controller, \
                    patch("zapret_ui.server.LocalServer") as server, \
                    patch("zapret_ui.desktop.run_desktop") as desktop, \
                    patch.object(self.main.ctypes.windll.shell32, "ShellExecuteW") as elevate, \
                    patch.object(self.main.ctypes.windll.user32, "MessageBoxW") as dialog:
                with self.assertRaises(SystemExit) as caught:
                    runpy.run_path(self.main.__file__, run_name="__main__")
            self.assertEqual(caught.exception.code, code)
            for forbidden in (controller, server, desktop, elevate, dialog):
                forbidden.assert_not_called()


class DriverDigestTests(unittest.TestCase):
    def setUp(self):
        PrepareUpdateTests.setUp(self)
        self.driver = self.app / "bundle" / "bin" / "WinDivert64.sys"
        self.driver.parent.mkdir(parents=True)
        self.payload = b"fixture driver bytes: never executable, never installed"
        self.driver.write_bytes(self.payload)
        self.digest = hashlib.sha256(self.payload).hexdigest()

    def test_driver_digest_matches_bytes_and_accepts_uppercase_hex(self):
        self.assertTrue(self.helper._driver_matches(self.app, self.digest))
        self.assertTrue(self.helper._driver_matches(self.app, self.digest.upper()))
        self.assertFalse(self.helper._driver_matches(self.app, "0" * 64))
        self.driver.write_bytes(self.payload + b"changed")
        self.assertFalse(self.helper._driver_matches(self.app, self.digest))

    def test_driver_digest_missing_file_or_read_error_fails_closed(self):
        with patch.object(Path, "open", side_effect=PermissionError("fixture read denied")):
            self.assertFalse(self.helper._driver_matches(self.app, self.digest))
        self.driver.unlink()
        self.assertFalse(self.helper._driver_matches(self.app, self.digest))

    def test_identical_loaded_driver_allows_update_without_mutating_fixture(self):
        with patch.object(self.helper, "candidate_ports", return_value=[19321]), \
                patch.object(self.helper, "request_exit", return_value=True) as request, \
                patch.object(self.helper, "blocked_files", return_value=[(self.driver.resolve(), 32)]):
            self.helper.prepare_update(self.app, timeout=1, driver_sha256=self.digest)
        request.assert_called_once()
        self.assertEqual(self.clock.sleeps, [])
        self.assertEqual(self.driver.read_bytes(), self.payload)

    def test_mismatching_loaded_driver_still_blocks_update(self):
        with patch.object(self.helper, "candidate_ports", return_value=[]), \
                patch.object(self.helper, "blocked_files", return_value=[(self.driver.resolve(), 32)]):
            with self.assertRaisesRegex(self.helper.UpdateBlocked, "WinDivert64.sys"):
                self.helper.prepare_update(self.app, timeout=0.5, driver_sha256="0" * 64)
        self.assertEqual(self.clock.now, 0.5)

    def test_no_digest_preserves_previous_loaded_driver_blocking(self):
        with patch.object(self.helper, "candidate_ports", return_value=[]), \
                patch.object(self.helper, "blocked_files", return_value=[(self.driver.resolve(), 32)]):
            with self.assertRaises(self.helper.UpdateBlocked):
                self.helper.prepare_update(self.app, timeout=0.5)
        self.assertEqual(self.clock.now, 0.5)

    def test_matching_other_binaries_are_never_ignored(self):
        for relative in (self.helper.APP_EXE, "bundle/bin/winws.exe", "bundle/bin/WinDivert.dll",
                         "bundle/bin/WinDivert32.sys", "another/WinDivert64.sys"):
            with self.subTest(relative=relative):
                other = self.app / relative
                other.parent.mkdir(parents=True, exist_ok=True)
                other.write_bytes(self.payload)
                self.clock.now = 0
                with patch.object(self.helper, "candidate_ports", return_value=[]), \
                        patch.object(self.helper, "blocked_files", return_value=[(other.resolve(), 32)]):
                    with self.assertRaisesRegex(self.helper.UpdateBlocked, other.name.replace(".", r"\.")):
                        self.helper.prepare_update(self.app, timeout=0.5, driver_sha256=self.digest)
                self.assertEqual(other.read_bytes(), self.payload)

    def test_identical_driver_does_not_hide_simultaneous_executable_lock(self):
        executable = self.app / self.helper.APP_EXE
        with patch.object(self.helper, "candidate_ports", return_value=[]), \
                patch.object(self.helper, "blocked_files", return_value=[(self.driver.resolve(), 32), (executable.resolve(), 32)]):
            with self.assertRaisesRegex(self.helper.UpdateBlocked, "ZapretByNerd3n.exe"):
                self.helper.prepare_update(self.app, timeout=0.5, driver_sha256=self.digest)

    def test_driver_digest_is_rechecked_after_waiting_for_another_lock(self):
        executable = self.app / self.helper.APP_EXE
        calls = 0
        def blocked(path):
            nonlocal calls
            calls += 1
            if calls == 1:
                return [(self.driver.resolve(), 32), (executable.resolve(), 32)]
            self.driver.write_bytes(self.payload + b"changed while waiting")
            return [(self.driver.resolve(), 32)]
        with patch.object(self.helper, "candidate_ports", return_value=[]), \
                patch.object(self.helper, "blocked_files", side_effect=blocked):
            with self.assertRaisesRegex(self.helper.UpdateBlocked, "WinDivert64.sys"):
                self.helper.prepare_update(self.app, timeout=1, driver_sha256=self.digest)
        self.assertGreaterEqual(calls, 2)

    def test_unreadable_matching_driver_is_not_exempted_from_lock_check(self):
        with patch.object(self.helper, "candidate_ports", return_value=[]), \
                patch.object(self.helper, "blocked_files", return_value=[(self.driver.resolve(), 32)]), \
                patch.object(Path, "open", side_effect=PermissionError("read denied")):
            with self.assertRaises(self.helper.UpdateBlocked):
                self.helper.prepare_update(self.app, timeout=0.5, driver_sha256=self.digest)

    def test_invalid_digest_is_rejected_before_discovery_shutdown_or_file_probe(self):
        for value in ("", "a" * 63, "a" * 65, "g" * 64, "a" * 63 + "\n", 42, True, "Ｆ" * 64):
            with self.subTest(value=value), \
                    patch.object(self.helper, "candidate_ports") as discover, \
                    patch.object(self.helper, "request_exit") as request, \
                    patch.object(self.helper, "blocked_files") as probe:
                with self.assertRaises(self.helper.UpdateError):
                    self.helper.prepare_update(self.app, timeout=0.5, driver_sha256=value)
            for forbidden in (discover, request, probe):
                forbidden.assert_not_called()

    def test_helper_passes_digest_to_preparation_and_maps_invalid_digest_to11(self):
        with patch.object(self.helper, "prepare_update") as prepare:
            self.assertEqual(self.helper.run_update_helper(str(self.app), driver_sha256=self.digest), 0)
        prepare.assert_called_once_with(self.app, driver_sha256=self.digest)
        with patch.object(self.helper, "candidate_ports") as discover:
            self.assertEqual(self.helper.run_update_helper(str(self.app), driver_sha256="invalid"), 11)
        discover.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows elevation boundary")
    def test_cli_propagates_driver_digest_without_opening_app_or_elevating(self):
        main = importlib.import_module("main")
        with patch.object(sys, "argv", ["app.exe", "--prepare-update", str(self.app),
                                       "--update-driver-sha256", self.digest.upper(), "--elevate"]), \
                patch.object(self.helper, "run_update_helper", return_value=10) as helper, \
                patch.object(main, "Controller") as controller, patch.object(main, "LocalServer") as server, \
                patch.object(main, "run_desktop") as desktop, \
                patch.object(main.ctypes.windll.shell32, "IsUserAnAdmin") as admin, \
                patch.object(main.ctypes.windll.shell32, "ShellExecuteW") as elevate, \
                patch.object(main.ctypes.windll.user32, "MessageBoxW") as dialog:
            self.assertEqual(main.main(), 10)
        helper.assert_called_once_with(str(self.app), driver_sha256=self.digest.upper())
        for forbidden in (controller, server, desktop, admin, elevate, dialog):
            forbidden.assert_not_called()


if __name__ == "__main__":
    unittest.main()
