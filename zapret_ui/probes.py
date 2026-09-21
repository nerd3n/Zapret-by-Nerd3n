"""Small, bounded HTTPS/TCP checks. These do not test playback or Discord voice.

No authentication, third-party checkers, or network configuration changes are used.
The gateway check validates REST discovery only, not a WebSocket connection.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import tempfile
import threading
import time
from typing import Callable
from urllib.parse import urlsplit


MAX_BODY_BYTES = 2 * 1024 * 1024
CONNECT_TIMEOUT = 3
REQUEST_TIMEOUT = 8


@dataclass(frozen=True)
class Target:
    name: str
    service: str
    url: str
    kind: str
    allowed_hosts: tuple[str, ...]


TARGETS = (
    Target("YouTube: главная", "YouTube", "https://www.youtube.com/", "youtube", ("www.youtube.com", "youtube.com")),
    Target("YouTube: изображение", "YouTube", "https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg", "jpeg", ("i.ytimg.com",)),
    Target("YouTube: метаданные", "YouTube", "https://www.youtube.com/oembed?url=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3DdQw4w9WgXcQ&format=json", "oembed", ("www.youtube.com", "youtube.com")),
    Target("Discord: главная", "Discord", "https://discord.com/", "discord", ("discord.com", "www.discord.com")),
    Target("Discord: Gateway API", "Discord", "https://discord.com/api/v10/gateway", "gateway", ("discord.com",)),
)


def _content_error(target: Target, status: int, content_type: str, body: bytes, effective_url: str) -> str | None:
    """Reject HTTP errors, block pages, unexpected redirects, and wrong content."""
    if not 200 <= status < 300:
        return f"HTTP {status}" if status else "Сервер не вернул HTTP-ответ"
    try:
        address = urlsplit(effective_url)
        if address.scheme != "https" or address.hostname not in target.allowed_hosts:
            return "Перенаправление на неожиданный адрес"
    except ValueError:
        return "Некорректный адрес ответа"
    if not body:
        return "Пустой ответ"
    if len(body) > MAX_BODY_BYTES:
        return "Ответ превысил лимит 2 МиБ"
    mime = content_type.partition(";")[0].strip().lower()
    if target.kind == "jpeg":
        if mime != "image/jpeg" or not body.startswith(b"\xff\xd8\xff") or not body.rstrip().endswith(b"\xff\xd9"):
            return "Ожидалось полное JPEG-изображение"
        return None
    if target.kind in {"gateway", "oembed"}:
        if mime != "application/json":
            return "Ожидался JSON-ответ"
        try:
            data = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            return "Повреждённый JSON-ответ"
        if not isinstance(data, dict):
            return "Неожиданная структура JSON"
        if target.kind == "gateway":
            gateway_url = data.get("url")
            try:
                gateway = urlsplit(gateway_url) if isinstance(gateway_url, str) else None
                if not gateway or gateway.scheme != "wss" or gateway.hostname != "gateway.discord.gg" or gateway.username or gateway.password:
                    return "Не найден ожидаемый адрес Discord Gateway"
            except ValueError:
                return "Некорректный адрес Discord Gateway"
        elif data.get("provider_name") != "YouTube" or data.get("type") != "video" or not isinstance(data.get("html"), str) or "www.youtube.com/embed/dQw4w9WgXcQ" not in data["html"]:
            return "Не найдены ожидаемые метаданные YouTube"
        return None
    if mime != "text/html":
        return "Ожидалась HTML-страница"
    text = body.decode("utf-8", errors="replace").lower()
    if "<html" not in text:
        return "Ответ не похож на HTML-страницу сервиса"
    if target.kind == "youtube":
        if "ytinitialdata" not in text or "ytcfg.set" not in text:
            return "Нет ожидаемых данных YouTube: возможна заглушка или страница согласия"
    elif target.kind == "discord":
        if "discord" not in text or not any(marker in text for marker in ("discord.com/assets/", "discord.com/", "discordapp.com/")):
            return "Нет ожидаемого содержимого Discord"
    return None


def _curl_path() -> str | None:
    if os.name == "nt":
        system_curl = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "curl.exe"
        return str(system_curl) if system_curl.is_file() else shutil.which("curl.exe")
    return shutil.which("curl")


def _result(target: Target, attempt: int) -> dict:
    return {"target": target.name, "service": target.service, "url": target.url,
            "ok": False, "httpStatus": 0, "timeMs": None, "error": None,
            "attempt": attempt, "scope": "HTTPS/TCP"}


def _probe(target: Target, attempt: int, cancel: threading.Event, curl: str | None) -> dict:
    result = _result(target, attempt)
    if cancel.is_set():
        result["error"] = "Отменено"
        return result
    if curl is None:
        result["error"] = "curl не найден: нужен штатный curl.exe Windows"
        return result
    started = time.monotonic()
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="zapret-probe-") as temporary:
            body_file = Path(temporary) / "body"
            args = [curl, "--disable", "--silent", "--show-error", "--location", "--max-redirs", "3",
                    "--proto", "=https", "--proto-redir", "=https", "--noproxy", "*", "--http1.1",
                    "--connect-timeout", str(CONNECT_TIMEOUT), "--max-time", str(REQUEST_TIMEOUT),
                    "--max-filesize", str(MAX_BODY_BYTES), "--output", str(body_file),
                    "--user-agent", "Zapret-UI-Diagnostics/1.0",
                    "--write-out", "%{http_code}\t%{content_type}\t%{time_total}\t%{url_effective}",
                    target.url]
            process = subprocess.Popen(args, shell=False, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            forced_error = None
            while True:
                if cancel.is_set():
                    forced_error = "Отменено"
                elif time.monotonic() - started > REQUEST_TIMEOUT + 1:
                    forced_error = "Истекло время ожидания"
                elif body_file.exists() and body_file.stat().st_size > MAX_BODY_BYTES:
                    # Also protects older curl builds that only check Content-Length.
                    forced_error = "Ответ превысил лимит 2 МиБ"
                if forced_error:
                    process.kill()
                    stdout, stderr = process.communicate(timeout=2)
                    break
                try:
                    stdout, stderr = process.communicate(timeout=0.1)
                    break
                except subprocess.TimeoutExpired:
                    continue
            result["timeMs"] = round((time.monotonic() - started) * 1000)
            metadata = stdout.decode("utf-8", errors="replace").strip().split("\t", 3)
            if len(metadata) == 4:
                try:
                    result["httpStatus"] = int(metadata[0])
                    elapsed = float(metadata[2])
                    if math.isfinite(elapsed) and elapsed >= 0:
                        result["timeMs"] = round(elapsed * 1000)
                except ValueError:
                    result["error"] = "Некорректный отчёт curl"
            else:
                result["error"] = "curl не вернул полный отчёт"
            if forced_error:
                result["error"] = forced_error
            elif cancel.is_set():
                result["error"] = "Отменено"
            elif process.returncode != 0:
                message = stderr.decode("utf-8", errors="replace").strip()[:400]
                result["error"] = f"curl {process.returncode}: {message or 'ошибка соединения'}"
            elif result["error"] is None:
                with body_file.open("rb") as body_stream:
                    body = body_stream.read(MAX_BODY_BYTES + 1)
                result["error"] = _content_error(target, result["httpStatus"], metadata[1], body, metadata[3])
            result["ok"] = result["error"] is None
    except (OSError, subprocess.SubprocessError) as error:
        result["error"] = str(error)[:400]
        result["timeMs"] = round((time.monotonic() - started) * 1000)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate(timeout=2)
    return result


def run_checks(repeats: int, cancel: threading.Event, on_check: Callable[[dict], None] | None = None) -> list[dict]:
    """Check five fixed URLs, at most four at once; callbacks run on the caller.

    A cancelled run may contain fewer results. Consumers must not present it as
    a completed benchmark or as evidence about an unverified provider/network.
    """
    if isinstance(repeats, bool) or not isinstance(repeats, int) or not 1 <= repeats <= 10:
        raise ValueError("Число повторов должно быть целым от 1 до 10")
    results = []
    curl = _curl_path()
    for attempt in range(1, repeats + 1):
        if cancel.is_set():
            break
        with ThreadPoolExecutor(max_workers=4, thread_name_prefix="https-check") as executor:
            futures = [executor.submit(_probe, target, attempt, cancel, curl) for target in TARGETS]
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                if on_check is not None:
                    on_check(result)
    return results


def summarize(checks: list[dict]) -> dict:
    """Score is percentage of successful checks; median uses successes only."""
    successful = [check for check in checks if check.get("ok") is True]
    timings = [check["timeMs"] for check in successful
               if isinstance(check.get("timeMs"), (float, int)) and math.isfinite(check["timeMs"]) and check["timeMs"] >= 0]
    return {"passed": len(successful), "total": len(checks),
            "medianMs": round(statistics.median(timings)) if timings else None,
            "score": round(len(successful) / len(checks) * 100, 1) if checks else 0}
