import importlib
from pathlib import Path
import runpy
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from zapret_ui import desktop


class Event:
    def __init__(self):
        self.callbacks = []
        self.flag = threading.Event()

    def __iadd__(self, callback):
        self.callbacks.append(callback)
        return self

    def emit(self, *args):
        values = [callback(*args) for callback in self.callbacks]
        self.flag.set()
        return values

    def wait(self, timeout=None):
        return self.flag.wait(timeout)


class FakeWindow:
    def __init__(self):
        self.events = Mock()
        for name in ("initialized", "before_show", "loaded", "closed", "shown"):
            setattr(self.events, name, Event())
        self.native = SimpleNamespace(webview=SimpleNamespace(NavigationStarting=Event()))
        self.destroyed = threading.Event()

    def destroy(self):
        self.events.closed.emit()
        self.destroyed.set()


class FakeServer:
    server_port = 17841

    def __init__(self):
        self.stopping = threading.Event()
        self.started = threading.Event()
        self.shutdown_calls = 0

    def serve_forever(self, poll_interval):
        self.started.set()
        self.stopping.wait(2)

    def shutdown(self):
        self.shutdown_calls += 1
        self.stopping.set()


class DesktopTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.data = Path(directory.name)
        self.server = FakeServer()
        self.window = FakeWindow()
        self.webview = Mock()
        self.webview.settings = {}
        self.webview.create_window.return_value = self.window
        self.real_loader = desktop._load_webview
        patcher = patch.object(desktop, "_load_webview", return_value=self.webview)
        patcher.start()
        self.addCleanup(patcher.stop)
        # Never change the test runner's real taskbar identity.
        identity = patch.object(desktop, "_set_windows_app_id")
        self.identity = identity.start()
        self.addCleanup(identity.stop)

    def show(self, renderer="edgechromium"):
        results = self.window.events.initialized.emit(renderer)
        if False in results:
            return False
        self.window.events.before_show.emit()
        self.window.events.shown.emit()
        self.window.events.loaded.emit()
        return True

    def test_window_close_shuts_down_http_and_preserves_http_security_boundary(self):
        def loop(**kwargs):
            self.assertTrue(self.server.started.wait(1))
            self.show()
            self.window.destroy()

        self.webview.start.side_effect = loop
        ready = Mock()
        desktop.run_desktop(self.server, self.data, on_ready=ready)
        ready.assert_called_once()
        self.assertEqual(self.server.shutdown_calls, 1)
        args, kwargs = self.webview.create_window.call_args
        self.assertEqual(args[1], "http://127.0.0.1:17841")
        self.assertNotIn("js_api", kwargs)
        self.assertTrue(self.webview.settings["ALLOW_DOWNLOADS"])
        self.assertFalse(self.webview.settings["ALLOW_FILE_URLS"])
        self.assertFalse(self.webview.settings["IGNORE_SSL_ERRORS"])
        self.webview.start.assert_called_once_with(gui="edgechromium", debug=False, private_mode=False,
                                                  storage_path=str(self.data / "webview"), http_server=False,
                                                  icon=str(Path(desktop.__file__).resolve().parents[1] / "web" / "favicon.ico"))

    def test_identity_is_set_before_creating_the_window(self):
        def create(*args, **kwargs):
            self.identity.assert_called_once_with()
            return self.window

        self.webview.create_window.side_effect = create
        self.webview.start.side_effect = lambda **kwargs: self.window.destroy()
        desktop.run_desktop(self.server, self.data)

    def test_identity_failure_stops_before_window_or_http_start(self):
        self.identity.side_effect = desktop.DesktopError("HRESULT 0x80004005")
        with self.assertRaisesRegex(desktop.DesktopError, "HRESULT"):
            desktop.run_desktop(self.server, self.data)
        self.webview.create_window.assert_not_called()
        self.webview.start.assert_not_called()
        self.assertFalse(self.server.started.is_set())

    def test_api_shutdown_closes_native_window(self):
        def loop(**kwargs):
            self.show()
            self.server.shutdown()
            self.assertTrue(self.window.destroyed.wait(1))

        self.webview.start.side_effect = loop
        desktop.run_desktop(self.server, self.data)
        self.assertTrue(self.window.destroyed.is_set())

    def test_legacy_renderer_is_rejected_without_browser_fallback(self):
        self.webview.start.side_effect = lambda **kwargs: self.show("mshtml")
        ready = Mock()
        with patch("webbrowser.open") as browser, self.assertRaisesRegex(desktop.DesktopError, "WebView2"):
            desktop.run_desktop(self.server, self.data, on_ready=ready)
        browser.assert_not_called()
        ready.assert_not_called()
        self.assertTrue(self.server.stopping.is_set())

    def test_gui_failure_still_stops_server(self):
        self.webview.start.side_effect = RuntimeError("runtime failed")
        with self.assertRaisesRegex(desktop.DesktopError, "runtime failed"):
            desktop.run_desktop(self.server, self.data)
        self.assertTrue(self.server.stopping.is_set())

    def test_auto_setup_runs_only_once_even_if_page_load_event_repeats(self):
        def loop(**kwargs):
            self.show()
            self.window.events.loaded.emit()
            self.window.destroy()

        self.webview.start.side_effect = loop
        ready = Mock()
        desktop.run_desktop(self.server, self.data, on_ready=ready)
        ready.assert_called_once()

    def test_navigation_guard_opens_external_http_in_browser_and_blocks_file_urls(self):
        with patch.object(desktop.webbrowser, "open") as browser:
            def loop(**kwargs):
                self.show()
                local = SimpleNamespace(Uri="http://127.0.0.1:17841/#settings", Cancel=False)
                external = SimpleNamespace(Uri="https://github.com/Flowseal/zapret-discord-youtube", Cancel=False)
                file_url = SimpleNamespace(Uri="file:///C:/secret.txt", Cancel=False)
                for request in (local, external, file_url):
                    self.window.native.webview.NavigationStarting.emit(None, request)
                self.assertFalse(local.Cancel)
                self.assertTrue(external.Cancel)
                self.assertTrue(file_url.Cancel)
                self.window.destroy()

            self.webview.start.side_effect = loop
            desktop.run_desktop(self.server, self.data)
            browser.assert_called_once_with("https://github.com/Flowseal/zapret-discord-youtube")

    def test_missing_dependency_has_actionable_error(self):
        with patch.dict(sys.modules, {"webview": None}):
            with self.assertRaisesRegex(desktop.DesktopError, "requirements.txt"):
                self.real_loader()


class DesktopIdentityTests(unittest.TestCase):
    def test_windows_identity_uses_installer_id_and_signed_32_bit_hresult(self):
        setter = Mock(return_value=0)
        shell = SimpleNamespace(SetCurrentProcessExplicitAppUserModelID=setter)
        with patch.object(desktop.sys, "platform", "win32"), \
                patch.object(desktop.ctypes, "WinDLL", return_value=shell, create=True) as load:
            desktop._set_windows_app_id()
        load.assert_called_once_with("shell32", use_last_error=True)
        setter.assert_called_once_with("Nerd3n.Zapret")
        self.assertEqual(setter.argtypes, [desktop.ctypes.c_wchar_p])
        self.assertIs(setter.restype, desktop.ctypes.c_int32)

    def test_failed_hresult_is_reported_as_hresult_not_last_error(self):
        for result in (-2147467259, 0x80004005):
            with self.subTest(result=result):
                setter = Mock(return_value=result)
                shell = SimpleNamespace(SetCurrentProcessExplicitAppUserModelID=setter)
                with patch.object(desktop.sys, "platform", "win32"), \
                        patch.object(desktop.ctypes, "WinDLL", return_value=shell, create=True), \
                        self.assertRaisesRegex(desktop.DesktopError, "HRESULT 0x80004005"):
                    desktop._set_windows_app_id()

    def test_non_windows_host_never_loads_or_calls_shell32(self):
        with patch.object(desktop.sys, "platform", "linux"), \
                patch.object(desktop.ctypes, "WinDLL", create=True) as load:
            desktop._set_windows_app_id()
        load.assert_not_called()

    def test_icon_resolves_from_module_root_in_source_and_frozen_layouts(self):
        with tempfile.TemporaryDirectory() as directory:
            for folder in ("checkout", "_MEI12345"):
                root = Path(directory) / folder
                (root / "web").mkdir(parents=True)
                icon = root / "web" / "favicon.ico"
                icon.write_bytes(b"fixture: no actual GUI load")
                module = root / "zapret_ui" / "desktop.py"
                with self.subTest(folder=folder), patch.object(desktop, "__file__", str(module)):
                    self.assertEqual(desktop._icon_path(), icon.resolve())

    def test_missing_icon_has_an_actionable_error(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(desktop, "__file__", str(Path(directory) / "zapret_ui" / "desktop.py")):
                with self.assertRaisesRegex(desktop.DesktopError, "favicon.ico"):
                    desktop._icon_path()


class MainModeTests(unittest.TestCase):
    def setUp(self):
        self.main = importlib.import_module("main")
        self.controller = Mock()
        self.controller.data = Path("fixture-data")
        self.server = Mock(server_port=17841)
        for patcher in (patch.object(self.main, "Controller", return_value=self.controller),
                        patch.object(self.main, "LocalServer", return_value=self.server)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def invoke(self, arguments):
        with patch.object(sys, "argv", ["main.py", *arguments]):
            self.main.main()

    def test_default_is_desktop_and_controller_is_closed_once(self):
        with patch.object(self.main, "run_desktop") as run, patch.object(self.main.webbrowser, "open") as browser:
            self.invoke([])
        run.assert_called_once_with(self.server, self.controller.data, on_ready=self.controller.schedule_auto_setup)
        browser.assert_not_called()
        self.controller.close.assert_called_once()
        self.server.server_close.assert_called_once()

    def test_desktop_failure_closes_controller_and_socket(self):
        with patch.object(self.main, "run_desktop", side_effect=desktop.DesktopError("No WebView2")):
            with self.assertRaises(desktop.DesktopError):
                self.invoke([])
        self.controller.close.assert_called_once()
        self.server.server_close.assert_called_once()
        self.controller.schedule_auto_setup.assert_not_called()

    def test_headless_mode_does_not_load_gui_or_open_browser(self):
        with patch.object(self.main, "run_desktop") as run, patch.object(self.main.webbrowser, "open") as browser:
            self.invoke(["--no-browser", "--no-auto-setup"])
        run.assert_not_called()
        browser.assert_not_called()
        self.controller.schedule_auto_setup.assert_not_called()
        self.server.serve_forever.assert_called_once()

    def test_browser_is_explicit_opt_in(self):
        with patch.object(self.main, "run_desktop") as run, patch.object(self.main.webbrowser, "open") as browser:
            self.invoke(["--browser", "--no-auto-setup"])
        run.assert_not_called()
        browser.assert_called_once_with("http://127.0.0.1:17841")
        self.server.serve_forever.assert_called_once()

    def test_port_bind_failure_closes_controller_once(self):
        with patch.object(self.main, "LocalServer", side_effect=OSError("in use")):
            with self.assertRaisesRegex(RuntimeError, "Порт"):
                self.invoke(["--no-browser"])
        self.controller.close.assert_called_once()

    def test_remove_service_never_creates_controller_or_window(self):
        with patch.object(self.main, "remove_owned_service") as remove, patch.object(self.main, "Controller") as create, patch.object(self.main, "run_desktop") as run:
            self.invoke(["--remove-service"])
        remove.assert_called_once()
        create.assert_not_called()
        run.assert_not_called()

    def test_remove_service_absent_owned_foreign_and_query_errors(self):
        manager = Mock()
        fake_module = SimpleNamespace(ServiceManager=Mock(return_value=manager))
        with patch.dict(sys.modules, {"zapret_ui.windows_service": fake_module}):
            manager.status.return_value = {"installed": False, "owned": False, "error": None}
            self.main.remove_owned_service(Path("fixture-base"))
            manager.remove.assert_not_called()
            manager.status.return_value = {"installed": True, "owned": True, "error": None}
            self.main.remove_owned_service(Path("fixture-base"))
            manager.remove.assert_called_once()
            for state in ({"installed": True, "owned": False}, {"installed": False, "error": "Access denied"}):
                manager.remove.reset_mock()
                manager.status.return_value = state
                with self.assertRaises(RuntimeError):
                    self.main.remove_owned_service(Path("fixture-base"))
                manager.remove.assert_not_called()

    def test_remove_service_failure_propagates_for_nonzero_exit(self):
        manager = Mock()
        manager.status.return_value = {"installed": True, "owned": True, "error": None}
        manager.remove.side_effect = PermissionError("Access denied")
        with patch.dict(sys.modules, {"zapret_ui.windows_service": SimpleNamespace(ServiceManager=Mock(return_value=manager))}):
            with self.assertRaises(PermissionError):
                self.main.remove_owned_service(Path("fixture-base"))

    def test_frozen_uninstaller_failure_returns_nonzero_after_error_dialog(self):
        manager = Mock()
        manager.status.return_value = {"installed": False, "owned": False, "error": "Access denied"}
        fake_module = SimpleNamespace(ServiceManager=Mock(return_value=manager))
        with patch.dict(sys.modules, {"zapret_ui.windows_service": fake_module}), \
                patch.object(sys, "argv", ["ZapretByNerd3n.exe", "--remove-service"]), \
                patch.object(sys, "frozen", True, create=True), \
                patch.object(self.main.ctypes.windll.user32, "MessageBoxW") as dialog:
            with self.assertRaises(SystemExit) as caught:
                runpy.run_path(self.main.__file__, run_name="__main__")
        self.assertEqual(caught.exception.code, 1)
        dialog.assert_called_once()
        manager.remove.assert_not_called()


if __name__ == "__main__":
    unittest.main()
