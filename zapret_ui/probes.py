"""Flowseal Standard host reachability checks; not video playback or voice tests.

The matrix mirrors Downloads 1.10.1: three HTTPS HEAD modes and ICMP per
HTTPS target, plus IP-only ICMP targets. No upstream BAT/PowerShell is run.
"""
from __future__ import annotations

from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import ipaddress
import math
import os
from pathlib import Path
import queue
import re
import shutil
import statistics
import subprocess
import tempfile
import threading
import time
from typing import Callable
from urllib.parse import urlsplit


SUITE_ID = "flowseal-standard-v1"
HTTP_MODES = ("HTTP", "TLS1.2", "TLS1.3")
MODES = (*HTTP_MODES, "PING")
STATUSES = frozenset(("OK", "ERROR", "SSL", "UNSUP", "CANCELLED"))
REQUEST_TIMEOUT = 5
PING_TIMEOUT_MS = 1000
PING_PROCESS_TIMEOUT = 8
MAX_OUTPUT_BYTES = 65536
MAX_TARGET_FILE_BYTES = 65536
MAX_TARGET_ENTRIES = 128


@dataclass(frozen=True)
class Target:
    name: str
    service: str
    url: str
    mode: str


def _host(value: str) -> str:
    if value.startswith("PING:"):
        return value[5:]
    return urlsplit(value).hostname or ""


def _service(value: str) -> str:
    if value.startswith("PING:"):
        return "DNS"
    host = _host(value).lower()
    for service, domains in (
        ("YouTube", ("youtube.com", "youtu.be", "ytimg.com", "googlevideo.com")),
        ("Discord", ("discord.com", "discord.gg", "discordapp.com")),
        ("Google", ("google.com", "gstatic.com")),
        ("Cloudflare", ("cloudflare.com",)),
    ):
        if any(host == domain or host.endswith("." + domain) for domain in domains):
            return service
    return "Other"


def _validate_url(value: str):
    if not isinstance(value, str) or not value or len(value) > 2048 or any(ch.isspace() or ord(ch) < 32 for ch in value):
        raise ValueError("Адрес цели пуст, слишком длинный или содержит пробелы")
    if value.startswith("PING:"):
        try:
            ipaddress.ip_address(value[5:])
        except ValueError as exc:
            raise ValueError("После PING: нужен IPv4 или IPv6 адрес") from exc
        return
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
        if parsed.scheme != "https" or not host or parsed.username is not None or parsed.password is not None or parsed.fragment or "#" in value or "\\" in value:
            raise ValueError
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part) for part in host.split(".")):
                raise ValueError
    except ValueError as exc:
        raise ValueError("Нужен HTTPS URL без логина, пароля и фрагмента либо PING:IP") from exc


def _expand(entries) -> tuple[Target, ...]:
    targets = []
    for name, value in entries:
        _validate_url(value)
        modes = ("PING",) if value.startswith("PING:") else MODES
        targets.extend(Target(name, _service(value), value, mode) for mode in modes)
    return tuple(targets)


TARGETS = _expand((
    ("DiscordMain", "https://discord.com"),
    ("DiscordGateway", "https://gateway.discord.gg"),
    ("DiscordCDN", "https://cdn.discordapp.com"),
    ("DiscordUpdates", "https://updates.discord.com"),
    ("YouTubeWeb", "https://www.youtube.com"),
    ("YouTubeShort", "https://youtu.be"),
    ("YouTubeImage", "https://i.ytimg.com"),
    ("YouTubeVideoRedirect", "https://redirector.googlevideo.com"),
    ("GoogleMain", "https://www.google.com"),
    ("GoogleGstatic", "https://www.gstatic.com"),
    ("CloudflareWeb", "https://www.cloudflare.com"),
    ("CloudflareCDN", "https://cdnjs.cloudflare.com"),
    ("CloudflareDNS1111", "PING:1.1.1.1"),
    ("CloudflareDNS1001", "PING:1.0.0.1"),
    ("GoogleDNS8888", "PING:8.8.8.8"),
    ("GoogleDNS8844", "PING:8.8.4.4"),
    ("Quad9DNS9999", "PING:9.9.9.9"),
))


def load_targets(path: Path) -> tuple[Target, ...]:
    """Read the actual bundled targets file; malformed/missing input is an error."""
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_TARGET_FILE_BYTES + 1)
        if len(raw) > MAX_TARGET_FILE_BYTES:
            raise ValueError("targets.txt превышает 64 КиБ")
        text = raw.decode("utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise ValueError("Не удалось прочитать targets.txt в UTF-8") from exc
    entries, names, addresses = [], set(), set()
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r'([A-Za-z0-9_]+)\s*=\s*"([^\"]+)"', line)
        if not match:
            raise ValueError(f"targets.txt, строка {number}: ожидается Имя = \"https://адрес\" или \"PING:IP\"")
        name, value = match.groups()
        if name.casefold() in names or value in addresses:
            raise ValueError(f"targets.txt, строка {number}: повтор имени или адреса")
        try:
            _validate_url(value)
        except ValueError as exc:
            raise ValueError(f"targets.txt, строка {number}: {exc}") from exc
        names.add(name.casefold())
        addresses.add(value)
        entries.append((name, value))
        if len(entries) > MAX_TARGET_ENTRIES:
            raise ValueError(f"targets.txt содержит больше {MAX_TARGET_ENTRIES} целей")
    if not entries:
        raise ValueError("targets.txt пуст: нет целей для проверки")
    return _expand(entries)


def _curl_path() -> str | None:
    if os.name == "nt":
        system_curl = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/curl.exe"
        return str(system_curl) if system_curl.is_file() else None
    return shutil.which("curl")


def _ping_path() -> str | None:
    if os.name != "nt":
        return None
    path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/ping.exe"
    return str(path) if path.is_file() else None


def _result(target: Target, attempt: int) -> dict:
    return {"target": target.name, "service": target.service, "url": target.url,
            "mode": target.mode, "attempt": attempt, "ok": False, "error": None,
            "httpStatus": 0, "timeMs": None, "status": "ERROR",
            "scope": SUITE_ID, "suiteId": SUITE_ID}


def _command(args: list[str], cancel: threading.Event, timeout: float):
    """Run only our child, with bounded files, deadline, and prompt cancellation."""
    started = time.monotonic()
    process = None
    with tempfile.TemporaryDirectory(prefix="zapret-standard-") as directory:
        stdout_path, stderr_path = Path(directory) / "out", Path(directory) / "err"
        with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
            forced = None
            try:
                if cancel.is_set():
                    return None, b"", b"", "CANCELLED"
                process = subprocess.Popen(args, shell=False, stdin=subprocess.DEVNULL,
                                           stdout=out, stderr=err,
                                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                while True:
                    if cancel.is_set():
                        forced = "CANCELLED"
                    elif stdout_path.stat().st_size > MAX_OUTPUT_BYTES or stderr_path.stat().st_size > MAX_OUTPUT_BYTES:
                        forced = "OUTPUT_LIMIT"
                    elif time.monotonic() - started > timeout:
                        forced = "TIMEOUT"
                    if forced or process.poll() is not None:
                        break
                    cancel.wait(0.05)
            finally:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
        with stdout_path.open("rb") as stream:
            stdout = stream.read(MAX_OUTPUT_BYTES + 1)
        with stderr_path.open("rb") as stream:
            stderr = stream.read(MAX_OUTPUT_BYTES + 1)
        if max(len(stdout), len(stderr)) > MAX_OUTPUT_BYTES:
            forced = forced or "OUTPUT_LIMIT"
        return process.returncode, stdout[:MAX_OUTPUT_BYTES], stderr[:MAX_OUTPUT_BYTES], forced


def _failure(result, status, error):
    result.update(ok=False, status=status, error=error)
    return result


def _forced_failure(result, forced):
    if forced == "CANCELLED":
        return _failure(result, "CANCELLED", "Отменено")
    return _failure(result, "ERROR", "Истекло время ожидания" if forced == "TIMEOUT" else "Ответ процесса превысил лимит 64 КиБ")


def _curl_status(code: int, stderr: str) -> str:
    # Unlike the upstream heuristic, a TLS handshake error (35) or the word
    # Schannel alone is not evidence that this curl lacks a capability.
    if code == 0:
        return "OK"
    if code in (6, 51, 58, 60, 77, 83, 90, 91) or re.search(
            r"could not resolve host|certificate verify failed|SSL certificate problem|self[- ]signed certificate|unable to get local issuer certificate", stderr, re.I):
        return "SSL"
    if re.search(r"not (?:found )?built[- ]in|build-time decision|built without|"
                 r"(?:option\s+--[^\r\n]*:|installed libcurl)[^\r\n]*(?:does not support|not supported)|"
                 r"TLS(?:v|\s*)1\.[23][^\r\n]*not supported (?:on Windows|by (?:your|this|the) (?:SSL|TLS) backend)|"
                 r"(?:unknown|unrecognized|unsupported) option|protocol [^\r\n]*not supported or disabled in libcurl", stderr, re.I):
        return "UNSUP"
    return "ERROR"


def _http_probe(target, attempt, cancel, curl):
    result = _result(target, attempt)
    if cancel.is_set():
        return _forced_failure(result, "CANCELLED")
    if not curl:
        return _failure(result, "UNSUP", "Не найден штатный curl.exe Windows")
    mode_args = {"HTTP": ["--http1.1"], "TLS1.2": ["--tlsv1.2", "--tls-max", "1.2"],
                 "TLS1.3": ["--tlsv1.3", "--tls-max", "1.3"]}[target.mode]
    args = [curl, "--disable", "--head", "--silent", "--show-error", "--max-time", str(REQUEST_TIMEOUT),
            "--noproxy", "*", "--proto", "=https", "--output", os.devnull,
            "--write-out", "%{http_code}\t%{time_total}\t%{remote_ip}\t%{http_version}", *mode_args, target.url]
    started = time.monotonic()
    try:
        code, stdout, stderr, forced = _command(args, cancel, REQUEST_TIMEOUT + 1)
        result["timeMs"] = round((time.monotonic() - started) * 1000)
        parts = stdout.decode("utf-8", errors="replace").strip().split("\t")
        metadata_ok = False
        if len(parts) == 4:
            try:
                status, elapsed = int(parts[0]), float(parts[1])
                if not 0 <= status <= 599 or not math.isfinite(elapsed) or elapsed < 0:
                    raise ValueError
                result.update(httpStatus=status, timeMs=round(elapsed * 1000), remoteIp=parts[2], httpVersion=parts[3])
                metadata_ok = True
            except ValueError:
                pass
        if forced:
            return _forced_failure(result, forced)
        if cancel.is_set():
            return _forced_failure(result, "CANCELLED")
        diagnostic = stderr.decode("utf-8", errors="replace").strip()[:600]
        status = _curl_status(code, diagnostic)
        if status == "OK" and (not metadata_ok or result["httpStatus"] == 0):
            return _failure(result, "ERROR", "curl не вернул корректный HTTP-отчёт")
        if status != "OK":
            return _failure(result, status, f"curl {code}: {diagnostic or 'ошибка соединения'}")
        result.update(ok=True, status="OK")
        return result
    except (OSError, subprocess.SubprocessError) as exc:
        return _failure(result, "ERROR", str(exc)[:600])


def _decode_ping(output: bytes) -> str:
    # Redirected Windows ping uses the OEM code page; errors are never classified
    # from localized words. UTF-8 is accepted for fixtures and UTF-8 system locales.
    try:
        return output.decode("utf-8")
    except UnicodeDecodeError:
        return output.decode("oem" if os.name == "nt" else "cp866", errors="replace")


def _ping_samples(text: str) -> list[float]:
    samples = []
    for line in text.splitlines():
        # Actual echo lines have one duration, statistics have three. TTL is
        # invariant for IPv4; IPv6 has no TTL. A received unreachable reply has
        # no duration and must never count as a successful echo.
        matches = re.findall(r"([=<])\s*(\d+)\s*(?:ms|мс)\b", line, re.I)
        if len(matches) == 1:
            comparator, value = matches[0]
            samples.append(0.0 if comparator == "<" and int(value) == 1 else float(value))
    return samples


def _ping_probe(target, attempt, cancel, ping):
    result = _result(target, attempt)
    result.update(pingSent=3, pingReceived=0)
    if cancel.is_set():
        return _forced_failure(result, "CANCELLED")
    if not ping:
        return _failure(result, "UNSUP", "ICMP-проверка требует штатный ping.exe Windows")
    args = [ping, "-n", "3", "-w", str(PING_TIMEOUT_MS), _host(target.url)]
    try:
        code, stdout, stderr, forced = _command(args, cancel, PING_PROCESS_TIMEOUT)
        if forced:
            return _forced_failure(result, forced)
        if cancel.is_set():
            return _forced_failure(result, "CANCELLED")
        samples = _ping_samples(_decode_ping(stdout))
        result["pingReceived"] = len(samples)
        if samples:
            result["timeMs"] = round(statistics.mean(samples))
        if code != 0 or len(samples) != 3:
            return _failure(result, "ERROR", f"ICMP: получено {len(samples)} из 3 echo-ответов; таймаут, недоступный хост или нераспознанный ответ")
        result.update(ok=True, status="OK")
        return result
    except (OSError, subprocess.SubprocessError) as exc:
        return _failure(result, "ERROR", str(exc)[:600])


def _probe_group(targets, attempt, cancel, curl, ping, completed):
    for target in targets:
        if cancel.is_set():
            break
        result = (_ping_probe(target, attempt, cancel, ping) if target.mode == "PING"
                  else _http_probe(target, attempt, cancel, curl))
        completed.put(result)


def run_checks(repeats: int, cancel: threading.Event, on_check: Callable[[dict], None] | None = None,
               *, targets=TARGETS) -> list[dict]:
    """Eight hosts in parallel; per-host modes sequential; callbacks on caller."""
    if isinstance(repeats, bool) or not isinstance(repeats, int) or not 1 <= repeats <= 10:
        raise ValueError("Число повторов должно быть целым от 1 до 10")
    targets = tuple(targets)
    if not targets:
        raise ValueError("Нет целей для проверки")
    keys, groups = set(), OrderedDict()
    for target in targets:
        if not isinstance(target, Target) or target.mode not in MODES:
            raise ValueError("Некорректная цель или режим проверки")
        _validate_url(target.url)
        if target.url.startswith("PING:") and target.mode != "PING":
            raise ValueError("Для PING:IP допустим только режим PING")
        key = (target.url, target.mode)
        if key in keys:
            raise ValueError("Повтор цели и режима проверки")
        keys.add(key)
        groups.setdefault(_host(target.url).casefold(), []).append(target)
    results = []
    curl, ping = _curl_path(), _ping_path()
    for attempt in range(1, repeats + 1):
        if cancel.is_set():
            break
        completed = queue.Queue()
        with ThreadPoolExecutor(max_workers=8, thread_name_prefix="standard-check") as executor:
            futures = [executor.submit(_probe_group, group, attempt, cancel, curl, ping, completed)
                       for group in groups.values()]
            try:
                while any(not future.done() for future in futures) or not completed.empty():
                    try:
                        result = completed.get(timeout=0.05)
                    except queue.Empty:
                        continue
                    results.append(result)
                    if on_check is not None:
                        on_check(result)
                for future in futures:
                    future.result()
            except BaseException:
                cancel.set()
                raise
    return results


def summarize(checks: list[dict], expected_checks: int | None = None) -> dict:
    """HTTP score excludes ICMP; completeness never equates unsupported to OK."""
    if expected_checks is not None and (isinstance(expected_checks, bool) or not isinstance(expected_checks, int) or expected_checks < 0):
        raise ValueError("Ожидаемое число проверок должно быть неотрицательным целым")
    http = [row for row in checks if row.get("mode") in HTTP_MODES]
    ping = [row for row in checks if row.get("mode") == "PING"]
    successful = [row for row in http if row.get("ok") is True and row.get("status") == "OK"]
    timings = [row["timeMs"] for row in successful if isinstance(row.get("timeMs"), (int, float))
               and not isinstance(row["timeMs"], bool) and math.isfinite(row["timeMs"]) and row["timeMs"] >= 0]
    keys = [(row.get("url"), row.get("mode"), row.get("attempt")) for row in checks]
    valid = all(row.get("mode") in MODES and row.get("status") in STATUSES and row.get("status") != "CANCELLED"
                and row.get("suiteId") == SUITE_ID and row.get("scope") == SUITE_ID
                and isinstance(row.get("attempt"), int) and not isinstance(row.get("attempt"), bool) and row["attempt"] > 0
                and isinstance(row.get("url"), str) and bool(row["url"])
                and row.get("ok") is (row.get("status") == "OK") for row in checks)
    unique = len(set(keys)) == len(keys) if valid else False
    return {"suiteId": SUITE_ID, "scope": SUITE_ID,
            "passed": len(successful), "total": len(http),
            "pingPassed": sum(row.get("ok") is True and row.get("status") == "OK" for row in ping),
            "pingTotal": len(ping), "unsupported": sum(row.get("status") == "UNSUP" for row in http),
            "pingUnsupported": sum(row.get("status") == "UNSUP" for row in ping),
            "checksTotal": len(checks), "complete": bool(checks) and valid and unique and (expected_checks is None or len(checks) == expected_checks),
            "medianMs": round(statistics.median(timings)) if timings else None,
            "score": round(len(successful) / len(http) * 100, 1) if http else 0}
