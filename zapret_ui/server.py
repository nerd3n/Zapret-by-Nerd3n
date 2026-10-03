"""Loopback-only server with same-origin and token checks on every mutation."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
from urllib.parse import urlsplit, parse_qs


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, controller, webroot):
        self.controller = controller
        self.webroot = Path(webroot).resolve()
        self.token = secrets.token_urlsafe(32)
        super().__init__(address, Handler)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def same_origin(self):
        expected = f"127.0.0.1:{self.server.server_port}"
        if self.headers.get("Host") != expected:
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin != "http://" + expected:
            return False
        return self.headers.get("Sec-Fetch-Site", "none") in ("none", "same-origin")

    def respond(self, status, body, content_type="application/json; charset=utf-8", download=None):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{download}"')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def do_GET(self):
        if not self.same_origin():
            return self.respond(403, {"error": "Forbidden origin"})
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        controller = self.server.controller
        try:
            if parsed.path == "/api/session":
                return self.respond(200, {"token": self.server.token})
            if parsed.path == "/api/state":
                return self.respond(200, controller.state())
            if parsed.path == "/api/strategy":
                return self.respond(200, controller.strategy(query.get("id", [""])[0]))
            if parsed.path == "/api/report":
                name = query.get("name", [""])[0]
                if not name or Path(name).name != name or not name.endswith(".json") or any(c not in "0123456789-.json" for c in name):
                    raise ValueError("Некорректное имя отчёта")
                path = controller.data / "reports" / name
                if not path.is_file():
                    return self.respond(404, {"error": "Отчёт не найден"})
                return self.respond(200, path.read_bytes(), download=name)
            allowed = {"/": "index.html", "/index.html": "index.html", "/app.js": "app.js", "/styles.css": "styles.css",
                       "/motion.js": "motion.js", "/vendor/gsap.min.js": "vendor/gsap.min.js",
                       "/assets/logo.png": "assets/logo.png", "/favicon.ico": "favicon.ico"}
            if parsed.path not in allowed:
                return self.respond(404, {"error": "Не найдено"})
            path = self.server.webroot / allowed[parsed.path]
            mime = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                    ".css": "text/css; charset=utf-8", ".png": "image/png", ".ico": "image/x-icon"}[path.suffix]
            return self.respond(200, path.read_bytes(), mime)
        except (ValueError, OSError) as exc:
            self.respond(400, {"error": str(exc)})

    def do_POST(self):
        if not self.same_origin() or not secrets.compare_digest(self.headers.get("X-Zapret-Token", ""), self.server.token):
            return self.respond(403, {"error": "Недействительный сеанс. Обновите страницу."})
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            return self.respond(415, {"error": "Ожидается JSON"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 32768:
                return self.respond(413, {"error": "Слишком большой запрос"})
            self.connection.settimeout(5)
            values = json.loads(self.rfile.read(length))
            if not isinstance(values, dict):
                raise ValueError("Ожидается объект JSON")
            controller = self.server.controller
            if self.path == "/api/settings":
                controller.save_settings(values)
            elif self.path == "/api/start":
                controller.start(values.get("strategyId"))
            elif self.path == "/api/stop":
                controller.stop()
            elif self.path == "/api/test":
                controller.begin_test(values.get("strategyIds", []), values.get("repeats", 2))
            elif self.path == "/api/baseline":
                controller.begin_test([], values.get("repeats", 2), baseline_only=True)
            elif self.path == "/api/cancel":
                controller.cancel_test()
            elif self.path == "/api/detect-network":
                controller.detect_network_async()
            elif self.path == "/api/auto-setup":
                controller.start_auto_setup()
            elif self.path in ("/api/service/install", "/api/service/start", "/api/service/stop", "/api/service/remove"):
                controller.service_action(self.path.rsplit("/", 1)[1], values.get("strategyId"))
            elif self.path == "/api/exit":
                import threading
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            else:
                return self.respond(404, {"error": "Не найдено"})
            self.respond(200, {"ok": True})
        except (ValueError, OSError) as exc:
            self.respond(400, {"error": str(exc)})
        except Exception as exc:
            self.server.controller.log("error", str(exc))
            self.respond(500, {"error": "Не удалось выполнить действие. Подробности в журнале."})
