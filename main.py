"""Desktop by default; --browser opts into a browser, --no-browser is headless."""
import argparse
import ctypes
import os
from pathlib import Path
import sys
import webbrowser
import subprocess

from zapret_ui.controller import Controller
from zapret_ui.server import LocalServer
from zapret_ui.desktop import run_desktop


def remove_owned_service(base: Path):
    """Uninstaller entry point. Never open a window or create a Controller."""
    from zapret_ui.windows_service import ServiceManager
    manager = ServiceManager(base)
    state = manager.status()
    if state.get("error"):
        raise RuntimeError("Не удалось проверить службу: " + str(state["error"]))
    if state.get("installed") is False:
        return
    if state.get("installed") is not True or state.get("owned") is not True:
        raise RuntimeError("Удаление отменено: служба ZapretByNerd3n не принадлежит этому приложению.")
    manager.remove()


def main():
    parser = argparse.ArgumentParser()
    interface = parser.add_mutually_exclusive_group()
    interface.add_argument("--no-browser", action="store_true", help="Запустить только локальный API, без окна и браузера")
    interface.add_argument("--browser", action="store_true", help="Открыть интерфейс во внешнем браузере вместо окна приложения")
    parser.add_argument("--port", type=int, default=17841)
    parser.add_argument("--auto", action="store_true", help="Первичная автоматическая настройка (включена по умолчанию)")
    parser.add_argument("--no-auto-setup", action="store_true", help="Не запускать определение сети и автоподбор")
    parser.add_argument("--elevate", action="store_true", help="Запросить повышение прав для установленного приложения")
    parser.add_argument("--remove-service", action="store_true", help="Удалить принадлежащую приложению службу без запуска интерфейса")
    parser.add_argument("--prepare-update", metavar="APP_DIR", help=argparse.SUPPRESS)
    parser.add_argument("--update-driver-sha256", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.prepare_update is not None:
        from zapret_ui.update_helper import run_update_helper
        if args.update_driver_sha256 is not None:
            return run_update_helper(args.prepare_update, driver_sha256=args.update_driver_sha256)
        return run_update_helper(args.prepare_update)
    if args.elevate and not args.remove_service and os.name == "nt" and not ctypes.windll.shell32.IsUserAnAdmin():
        child_args = [arg for arg in sys.argv[1:] if arg != "--elevate"]
        if not getattr(sys, "frozen", False):
            child_args.insert(0, str(Path(__file__).resolve()))
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                                                    subprocess.list2cmdline(child_args), str(Path(sys.executable).parent), 1)
        if result > 32:
            return
    base = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent
    if args.remove_service:
        remove_owned_service(base)
        return
    if getattr(sys, "frozen", False):
        from zapret_ui.bundled_payload import ensure_embedded_payload
        ensure_embedded_payload(base, Path(sys._MEIPASS))
    webroot = Path(getattr(sys, "_MEIPASS", base)) / "web"
    controller = Controller(base)
    server = None
    try:
        try:
            server = LocalServer(("127.0.0.1", args.port), controller, webroot)
        except OSError as exc:
            raise RuntimeError(f"Порт {args.port} недоступен. Закройте другой экземпляр приложения или укажите --port.") from exc
        url = f"http://127.0.0.1:{server.server_port}"
        if sys.stdout:
            print(f"zapret by nerd3n: {url}", flush=True)
        if args.browser or args.no_browser:
            if args.browser:
                webbrowser.open(url)
            if not args.no_auto_setup:
                controller.schedule_auto_setup()
            server.serve_forever(poll_interval=0.25)
        else:
            run_desktop(server, controller.data,
                        on_ready=None if args.no_auto_setup else controller.schedule_auto_setup)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            controller.close()
        finally:
            if server is not None:
                server.server_close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        if os.name == "nt" and getattr(sys, "frozen", False):
            ctypes.windll.user32.MessageBoxW(None, str(exc), "zapret by nerd3n", 0x10)
            raise SystemExit(1)
        else:
            raise
