"""Identify the public egress network without retaining the public IP address.

Official schemas: https://ipwhois.io/documentation, https://ipapi.co/api/ and
https://2ip.me/en/api/our-api (third fallback, documented 10 requests/day).
Only ordinary unauthenticated HTTPS requests are sent. Public IP, coordinates,
and the raw response are never returned, logged, or retained after the request.
The bounded temporary response file is removed before the function returns. The external API
necessarily sees the request's public IP, as any HTTPS destination does.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import threading
import time

from .probes import _curl_path


MAX_BODY_BYTES = 16 * 1024
REQUEST_TIMEOUT = 6
SOURCES = (("ipwho.is", "https://ipwho.is/"), ("ipapi.co", "https://ipapi.co/json/"),
           ("2ip.me", "https://api.2ip.me/provider.json?ip="))
_SESSION_SALT = secrets.token_bytes(32)
WARNING = "Определён оператор внешнего IP. VPN или туннель могут скрывать домашнего провайдера; город определяется приблизительно."


class DetectionError(ValueError):
    """Contains only local, IP-free diagnostics suitable for the UI."""


class DetectionCancelled(DetectionError):
    pass


def _fetch_json(source: str, url: str, cancel: threading.Event) -> dict:
    executable = _curl_path()
    if not executable:
        raise DetectionError("Штатный curl не найден")
    if cancel.is_set():
        raise DetectionCancelled("Отменено")
    process = None
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="zapret-network-") as temporary:
            path = Path(temporary) / "response.json"
            command = [executable, "--disable", "--silent", "--show-error", "--noproxy", "*",
                       "--http1.1", "--proto", "=https", "--connect-timeout", "3",
                       "--max-time", str(REQUEST_TIMEOUT), "--max-filesize", str(MAX_BODY_BYTES),
                       "--user-agent", "Zapret-UI-Network-Detection/1.0",
                       "--header", "Accept: application/json", "--output", str(path),
                       "--write-out", "%{http_code}", url]
            process = subprocess.Popen(command, shell=False, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            while True:
                problem = None
                if cancel.is_set():
                    problem = DetectionCancelled("Отменено")
                elif time.monotonic() - started > REQUEST_TIMEOUT + 1:
                    problem = DetectionError(f"{source}: истекло время ожидания")
                elif path.exists() and path.stat().st_size > MAX_BODY_BYTES:
                    problem = DetectionError(f"{source}: слишком большой ответ")
                if problem:
                    process.kill()
                    process.communicate(timeout=2)
                    raise problem
                try:
                    stdout, _stderr = process.communicate(timeout=0.1)
                    break
                except subprocess.TimeoutExpired:
                    continue
            if cancel.is_set():
                raise DetectionCancelled("Отменено")
            if process.returncode != 0:
                # curl diagnostics can include addresses. Never copy them to UI/logs.
                raise DetectionError(f"{source}: ошибка HTTPS, код curl {process.returncode}")
            code = stdout.decode("ascii", errors="replace").strip()
            if not re.fullmatch(r"2\d\d", code):
                safe_code = code if re.fullmatch(r"\d{3}", code) else "неизвестен"
                raise DetectionError(f"{source}: HTTP {safe_code}")
            with path.open("rb") as stream:
                body = stream.read(MAX_BODY_BYTES + 1)
            if len(body) > MAX_BODY_BYTES:
                raise DetectionError(f"{source}: слишком большой ответ")
            try:
                data = json.loads(body)
            except (ValueError, UnicodeError):
                raise DetectionError(f"{source}: некорректный JSON") from None
            if not isinstance(data, dict):
                raise DetectionError(f"{source}: неизвестный формат ответа")
            return data
    except (OSError, subprocess.SubprocessError):
        raise DetectionError(f"{source}: не удалось выполнить HTTPS-запрос") from None
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate(timeout=2)


def _text(value, public_ip: str) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.split())[:160]
    cleaned = cleaned.replace(public_ip, "[IP скрыт]")
    return cleaned or None


def _parse_identity(data: dict, source: str, salt: bytes) -> dict:
    if source == "ipwho.is":
        if data.get("success") is not True:
            raise DetectionError(f"{source}: API не смог определить сеть")
        connection = data.get("connection")
        if not isinstance(connection, dict):
            raise DetectionError(f"{source}: отсутствуют сведения об операторе")
        asn, provider = connection.get("asn"), connection.get("isp") or connection.get("org")
        country = data.get("country")
    elif source == "ipapi.co":
        if data.get("error"):
            raise DetectionError(f"{source}: API не смог определить сеть")
        asn, provider = data.get("asn"), data.get("org")
        country = data.get("country_name") or data.get("country")
    elif source == "2ip.me":
        # This API provides ISP/ASN only. Do not invent or infer a city.
        asn, provider = data.get("as"), data.get("name_rus") or data.get("name_ripe")
        country = None
    else:
        raise DetectionError("Неизвестный источник данных")
    raw_ip = data.get("ip")
    try:
        if not isinstance(raw_ip, str):
            raise ValueError()
        address = ipaddress.ip_address(raw_ip)
        if not address.is_global or address.is_multicast or address.is_reserved:
            raise ValueError()
    except ValueError:
        raise DetectionError(f"{source}: API не вернул публичный IP") from None
    if isinstance(asn, bool) or not re.fullmatch(r"(?:AS)?[1-9]\d{0,9}", str(asn), re.I):
        raise DetectionError(f"{source}: неизвестный ASN")
    number = int(str(asn).upper().removeprefix("AS"))
    if not 1 <= number <= 4294967295:
        raise DetectionError(f"{source}: некорректный ASN")
    provider = _text(provider, raw_ip)
    if not provider:
        raise DetectionError(f"{source}: отсутствует название оператора")
    fingerprint = hmac.new(salt, f"{address.compressed}|AS{number}".encode("utf-8"), hashlib.sha256).hexdigest()
    return {"status": "detected", "provider": provider, "asn": f"AS{number}",
            "city": _text(data.get("city"), raw_ip), "country": _text(country, raw_ip),
            "source": source, "detectedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "fingerprint": fingerprint, "warning": WARNING, "error": None}


def detect_network(cancel: threading.Event | None = None, *, salt: bytes | str | None = None) -> dict:
    """Return egress ISP/ASN, never home-ISP verification or a raw public IP.

    The optional salt is installation-local and must never be sent to any API.
    With no salt, fingerprints stay comparable within the current app process.
    A failed/cancelled detection is returned as data and does not prevent checks.
    """
    cancel = cancel if cancel is not None else threading.Event()
    secret = _SESSION_SALT if salt is None else salt.encode("utf-8") if isinstance(salt, str) else salt
    if not isinstance(secret, bytes) or len(secret) < 16:
        raise ValueError("Локальная соль отпечатка должна содержать не менее 16 байт")
    errors = []
    for source, url in SOURCES:
        if cancel.is_set():
            break
        try:
            return _parse_identity(_fetch_json(source, url, cancel), source, secret)
        except DetectionCancelled:
            break
        except DetectionError as error:
            errors.append(str(error))
    cancelled = cancel.is_set()
    return {"status": "cancelled" if cancelled else "unavailable", "provider": None, "asn": None,
            "city": None, "country": None, "source": None,
            "detectedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"), "fingerprint": None,
            "warning": "Домашний провайдер не подтверждён. Проверки можно выполнить для текущего соединения.",
            "error": "Отменено" if cancelled else "; ".join(errors) or "Не удалось определить сеть"}
