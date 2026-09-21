"""Windows desktop host for the existing loopback web UI.

Only the GUI lifetime is managed here. Engine ownership, including the distinction
between an owned session and a persistent Windows service, belongs to Controller.
No Python object is exposed to JavaScript; the existing HTTP token/origin checks
remain the sole application API boundary.
"""
from __future__ import annotations

import ctypes
from pathlib import Path
import sys
import threading
from typing import Callable
from urllib.parse import urlsplit
import webbrowser


APP_USER_MODEL_ID = "Nerd3n.Zapret"


class DesktopError(RuntimeError):
    """An actionable failure to initialize the native application window."""


def _set_windows_app_id():
    """Match the installer shortcuts before Windows sees an application window."""
    if sys.platform != "win32":
        return
    try:
        setter = ctypes.WinDLL("shell32", use_last_error=True).SetCurrentProcessExplicitAppUserModelID
        setter.argtypes = [ctypes.c_wchar_p]
        setter.restype = ctypes.c_int32  # HRESULT is signed 32-bit, including on Windows x64.
        result = ctypes.c_int32(setter(APP_USER_MODEL_ID)).value
    except (OSError, AttributeError) as exc:
        raise DesktopError(f"Не удалось задать идентификатор приложения для панели задач: {exc}") from exc
    if result < 0:
        raise DesktopError(f"Не удалось задать идентификатор приложения для панели задач: HRESULT 0x{result & 0xFFFFFFFF:08X}.")


def _icon_path() -> Path:
    """Resolve both a source checkout and PyInstaller's embedded web directory."""
    path = Path(__file__).resolve().parents[1] / "web" / "favicon.ico"
    if not path.is_file():
        raise DesktopError("Не найдена иконка приложения web/favicon.ico. Переустановите приложение.")
    return path


def _load_webview():
    try:
        import webview
    except (ImportError, OSError) as exc:
        raise DesktopError(
            "Не удалось загрузить модуль окна приложения (pywebview). "
            "Для запуска из исходников установите зависимости: python -m pip install -r requirements.txt. "
            "Для готового EXE переустановите приложение. Режим --browser доступен отдельно."
        ) from exc
    return webview


def _navigation_action(address: str, origin: str) -> str:
    """Keep local UI navigation inside the window; never allow file/custom URLs."""
    if address == "about:blank":
        return "local"
    try:
        destination, local = urlsplit(address), urlsplit(origin)
        if destination.scheme == local.scheme and destination.netloc == local.netloc:
            return "local"
        if destination.scheme in ("http", "https") and destination.hostname:
            return "external"
    except ValueError:
        pass
    return "blocked"


def run_desktop(server, data_directory: Path, *, on_ready: Callable[[], None] | None = None):
    """Run WebView2 on the calling/main thread and HTTP on a background thread.

    Closing the window stops the server; an HTTP /api/exit also closes the window.
    The caller always closes Controller and the listening socket in its finally
    block, including GUI initialization failures. No browser fallback is attempted.
    """
    if threading.current_thread() is not threading.main_thread():
        raise DesktopError("Окно приложения должно запускаться в главном потоке.")
    _set_windows_app_id()
    icon = _icon_path()
    webview = _load_webview()
    storage = Path(data_directory) / "webview"
    storage.mkdir(parents=True, exist_ok=True)
    webview.settings["ALLOW_DOWNLOADS"] = True  # Existing JSON report download links.
    webview.settings["ALLOW_FILE_URLS"] = False
    # Route new-window requests through the same navigation guard as ordinary
    # links; only HTTP(S) links are delegated to the system browser.
    webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = False
    webview.settings["REMOTE_DEBUGGING_PORT"] = None
    webview.settings["IGNORE_SSL_ERRORS"] = False
    origin = f"http://127.0.0.1:{server.server_port}"
    window = webview.create_window(
        "zapret by nerd3n", origin,
        width=1400, height=900, min_size=(1000, 700), resizable=True,
        background_color="#1B1B1E", text_select=True,
    )
    if window is None:
        raise DesktopError("Не удалось создать окно приложения.")
    closing = threading.Event()
    stopped = threading.Event()
    ready_once = threading.Event()
    ready_lock = threading.Lock()
    failures = []

    def initialized(renderer):
        if renderer != "edgechromium":
            failures.append(DesktopError(
                "Не найден Microsoft Edge WebView2 Runtime. Установите WebView2 Runtime x64 "
                "с сайта Microsoft и повторите запуск. Устаревший движок Internet Explorer не используется."
            ))
            return False
        return True

    def loaded():
        with ready_lock:
            if ready_once.is_set() or closing.is_set() or stopped.is_set():
                return
            ready_once.set()
        try:
            if on_ready is not None:
                on_ready()
        except Exception as exc:
            failures.append(exc)
            server.shutdown()

    def closed():
        closing.set()

    def navigate(_sender, args):
        address = str(args.Uri)
        action = _navigation_action(address, origin)
        if action != "local":
            args.Cancel = True
            if action == "external":
                webbrowser.open(address)

    def before_show():
        try:
            # Documented pywebview native handle; WebView2 NavigationStarting is
            # synchronous, so external content cannot load into this window.
            window.native.webview.NavigationStarting += navigate
        except Exception as exc:
            failures.append(DesktopError(f"Не удалось защитить навигацию окна: {exc}"))
            server.shutdown()

    def serve():
        try:
            server.serve_forever(poll_interval=0.1)
        except Exception as exc:
            failures.append(exc)
        finally:
            stopped.set()

    def watch_server():
        stopped.wait()
        # API shutdown may occur while WebView2 is still initializing. Wait for
        # a shown window before calling the public thread-safe destroy method.
        while not closing.is_set():
            if window.events.shown.wait(0.1):
                if not closing.is_set():
                    try:
                        window.destroy()
                    except Exception as exc:
                        if not closing.is_set():
                            failures.append(exc)
                return

    window.events.initialized += initialized
    window.events.before_show += before_show
    window.events.loaded += loaded
    window.events.closed += closed
    server_thread = threading.Thread(target=serve, name="desktop-http", daemon=True)
    watcher = threading.Thread(target=watch_server, name="desktop-exit", daemon=True)
    server_thread.start()
    watcher.start()
    try:
        try:
            webview.start(gui="edgechromium", debug=False, private_mode=False,
                          storage_path=str(storage), http_server=False, icon=str(icon))
        except Exception as exc:
            raise DesktopError(
                "Не удалось открыть окно приложения. Проверьте установку Microsoft Edge WebView2 Runtime x64 "
                f"и права на папку данных. Подробности: {exc}"
            ) from exc
        if failures:
            raise DesktopError(str(failures[0])) from failures[0]
    finally:
        closing.set()
        if server_thread.is_alive():
            server.shutdown()
        server_thread.join(timeout=5)
        watcher.join(timeout=1)
