"""Run from source: python main.py [--no-browser] [--port 17841]."""
import argparse
import ctypes
import os
from pathlib import Path
import sys
import threading
import webbrowser
import subprocess

from zapret_ui.controller import Controller
from zapret_ui.server import LocalServer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--port", type=int, default=17841)
    parser.add_argument("--auto", action="store_true", help="Первичная автоматическая настройка (включена по умолчанию)")
    parser.add_argument("--no-auto-setup", action="store_true", help="Не запускать определение сети и автоподбор")
    parser.add_argument("--elevate", action="store_true", help="Запросить повышение прав для установленного приложения")
    args = parser.parse_args()
    if args.elevate and os.name == "nt" and not ctypes.windll.shell32.IsUserAnAdmin():
        child_args = [arg for arg in sys.argv[1:] if arg != "--elevate"]
        if not getattr(sys, "frozen", False):
            child_args.insert(0, str(Path(__file__).resolve()))
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                                                    subprocess.list2cmdline(child_args), str(Path(sys.executable).parent), 1)
        if result > 32:
            return
    base = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent
    webroot = Path(getattr(sys, "_MEIPASS", base)) / "web"
    controller = Controller(base)
    try:
        server = LocalServer(("127.0.0.1", args.port), controller, webroot)
    except OSError:
        controller.close()
        raise RuntimeError(f"Порт {args.port} занят. Закройте другой экземпляр приложения или укажите --port.")
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        if not args.no_browser:
            threading.Timer(0.4, lambda: webbrowser.open(url)).start()
        if sys.stdout:
            print(f"zapret by nerd3n: {url}", flush=True)
        if not args.no_auto_setup:
            controller.schedule_auto_setup()
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        controller.close()
        server.server_close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        if os.name == "nt" and getattr(sys, "frozen", False):
            ctypes.windll.user32.MessageBoxW(None, str(exc), "zapret by nerd3n", 0x10)
        else:
            raise
