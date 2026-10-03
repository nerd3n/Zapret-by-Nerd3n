"""Rank Flowseal Standard measurements: HTTP/TLS OK, then ping OK.

Only complete matrices can be recommended against a baseline. Every HTTP/TLS
probe must pass, except a whole TLS1.3 column explicitly unsupported in both
measurements. Unchecked TLS remains visible and never increases the score.
Reachable addresses are not evidence about video playback or Discord voice.
"""
from __future__ import annotations

from collections import Counter
import math
import statistics

from .probes import TARGETS


SCOPE = "flowseal-standard-v1"
_HTTP_MODES = frozenset(("HTTP", "TLS1.2", "TLS1.3"))
_MODES = _HTTP_MODES | {"PING"}
_STATUSES = frozenset(("OK", "ERROR", "SSL", "UNSUP", "CANCELLED"))
_ENGINE_ERRORS = frozenset(("winws завершился во время проверки", "Отменено"))


def _expected_matrix(targets, expected_checks):
    """Bind evidence to the exact endpoint/mode/attempt matrix selected to run."""
    try:
        targets = tuple(targets)
    except TypeError as exc:
        raise ValueError("Не задан список целей Standard") from exc
    if not targets:
        raise ValueError("Не задан список целей Standard")
    identities = {}
    url_modes = {}
    for target in targets:
        try:
            name, service, url, mode = target.name, target.service, target.url, target.mode
        except AttributeError as exc:
            raise ValueError("Цель не соответствует формату Standard") from exc
        if not all(isinstance(value, str) and value for value in (name, service, url, mode)) or mode not in _MODES:
            raise ValueError("Цель не соответствует формату Standard")
        key = (url, mode)
        if key in identities:
            raise ValueError("Список целей Standard содержит дубли URL и режима")
        identities[key] = (name, service)
        url_modes.setdefault(url, set()).add(mode)
    # A shortened TLS-only list must not become complete evidence accidentally.
    for url, modes in url_modes.items():
        required = {"PING"} if url.startswith("PING:") else _MODES
        if modes != required:
            raise ValueError("Для каждого URL нужны HTTP, TLS1.2, TLS1.3 и PING")
    if not any(mode in _HTTP_MODES for _, mode in identities):
        raise ValueError("Для рекомендаций нужны HTTP/TLS-цели Standard")
    if expected_checks is None:
        expected_checks = 2 * len(targets)
    if type(expected_checks) is not int or expected_checks < len(targets) or expected_checks % len(targets):
        raise ValueError("Ожидалось полное число повторов всех проверок Standard")
    repeats = expected_checks // len(targets)
    return {(url, mode, attempt): identity for (url, mode), identity in identities.items()
            for attempt in range(1, repeats + 1)}


def _metrics(result: dict, expected: dict) -> dict | None:
    if not isinstance(result, dict) or result.get("cancelled") or result.get("error"):
        return None
    if result.get("suiteId", SCOPE) != SCOPE or result.get("scope", SCOPE) != SCOPE:
        return None
    checks = result.get("checks")
    if not isinstance(checks, list) or len(checks) != len(expected):
        return None
    seen = set()
    for check in checks:
        if (not isinstance(check, dict) or type(check.get("ok")) is not bool
                or type(check.get("attempt")) is not int
                or not isinstance(check.get("url"), str) or not isinstance(check.get("mode"), str)):
            return None
        if check.get("suiteId", SCOPE) != SCOPE or check.get("scope", SCOPE) != SCOPE:
            return None
        error = check.get("error")
        if error is not None and not isinstance(error, str):
            return None
        if error in _ENGINE_ERRORS:
            return None
        status = check.get("status")
        if not isinstance(status, str) or status not in _STATUSES or status == "CANCELLED":
            return None
        key = (check["url"], check["mode"], check["attempt"])
        if key not in expected or key in seen or (check.get("target"), check.get("service")) != expected[key]:
            return None
        # Neither an unsupported TLS mode nor a transport error is a success.
        if check["ok"] != (status == "OK") or (check["ok"] and error):
            return None
        seen.add(key)
    if seen != set(expected):
        return None
    http = [check for check in checks if check["mode"] in _HTTP_MODES]
    ping = [check for check in checks if check["mode"] == "PING"]
    successful = [check for check in http if check["ok"]]
    rates = {}
    for name in sorted({check["service"] for check in http}):
        subset = [check for check in http if check["service"] == name]
        rates[name] = sum(check["ok"] for check in subset) / len(subset)
    times = [check["timeMs"] for check in successful
             if isinstance(check.get("timeMs"), (int, float)) and not isinstance(check["timeMs"], bool)
             and math.isfinite(check["timeMs"]) and check["timeMs"] >= 0]
    unsupported = sum(check["status"] == "UNSUP" for check in http)
    by_mode = {}
    for mode in sorted(_HTTP_MODES):
        subset = [check for check in http if check["mode"] == mode]
        by_mode[mode] = {"passed": sum(check["ok"] for check in subset), "total": len(subset),
                         "unsupported": sum(check["status"] == "UNSUP" for check in subset)}
    return {"strategyId": result.get("strategyId"), "name": result.get("name", ""),
            "experimental": bool(result.get("experimental")),
            "passed": len(successful), "total": len(http),
            "httpPassed": len(successful), "httpTotal": len(http),
            "httpErrors": sum(check["status"] in {"ERROR", "SSL"} for check in http),
            "unsupported": unsupported, "httpUnsupported": unsupported,
            "pingPassed": sum(check["ok"] for check in ping), "pingTotal": len(ping),
            "pingFailed": sum(not check["ok"] for check in ping),
            "modes": by_mode,
            "unsupportedModes": [mode for mode, counts in by_mode.items() if counts["unsupported"] == counts["total"]],
            "excludedUnsupportedModes": [], "supportedPassed": len(successful), "supportedTotal": len(http),
            "checksTotal": len(checks), "minimumServiceRate": min(rates.values()),
            "successRate": len(successful) / len(http), "serviceRates": rates,
            "medianMs": statistics.median(times) if times else None}


def _unsupported_tls13(metrics: dict) -> bool:
    """Only a complete TLS1.3 column may be excluded; HTTP/TLS1.2 stay mandatory."""
    tls13 = metrics["modes"]["TLS1.3"]
    return tls13["total"] > 0 and tls13["unsupported"] == tls13["total"] == metrics["unsupported"]


def _exclude_tls13(metrics: dict):
    metrics["excludedUnsupportedModes"] = ["TLS1.3"]
    metrics["supportedTotal"] -= metrics["modes"]["TLS1.3"]["total"]


def recommend(results: list[dict], baseline: dict | None = None,
              expected_checks: int | None = None, targets=TARGETS) -> dict:
    """Recommend fully passing HTTP/TLS evidence with confirmed improvement.

    Each selected endpoint, mode and attempt must be present exactly once,
    including ping results. Ordinary negative probes remain diagnostic results;
    malformed, cancelled, duplicate or failed-engine measurements do not rank.
    """
    expected = _expected_matrix(targets, expected_checks)
    if baseline is None:
        baselines = [item for item in results if isinstance(item, dict) and item.get("strategyId") == "baseline"]
        baseline = baselines[0] if len(baselines) == 1 else None
    identifiers = Counter(item["strategyId"] for item in results if isinstance(item, dict)
                          and isinstance(item.get("strategyId"), str))
    candidates = []
    for measurement in results:
        if not isinstance(measurement, dict):
            continue
        identifier = measurement.get("strategyId")
        if not isinstance(identifier, str) or not identifier or identifier == "baseline" or identifiers[identifier] != 1:
            continue
        metrics = _metrics(measurement, expected)
        if metrics is not None:
            candidates.append(metrics)
    # Flowseal Standard uses OK then PingOK. Its unordered final tie is made
    # deterministic by ID; latency and experimental status do not affect rank.
    candidates.sort(key=lambda item: (-item["httpPassed"], -item["pingPassed"], item["strategyId"]))
    baseline_metrics = _metrics(baseline, expected) if baseline is not None else None
    baseline_tls13_unsupported = baseline_metrics is not None and _unsupported_tls13(baseline_metrics)
    if baseline_tls13_unsupported:
        _exclude_tls13(baseline_metrics)
        for candidate in candidates:
            if _unsupported_tls13(candidate):
                _exclude_tls13(candidate)
    result = {"status": "no_valid_candidates", "recommendedId": None,
              "bestCandidateId": candidates[0]["strategyId"] if candidates else None,
              "baselineReachable": False, "bypassNotNeeded": False,
              "reason": "Нет завершённых проверок стратегий Standard.",
              "ranking": candidates, "scope": SCOPE, "suiteId": SCOPE,
              "excludedUnsupportedModes": ["TLS1.3"] if baseline_tls13_unsupported else []}
    if baseline_metrics is None:
        result.update(status="baseline_incomplete", reason="Базовая проверка Standard не завершена; сравнение и автозапуск недоступны.")
    elif baseline_metrics["unsupported"] and not baseline_tls13_unsupported:
        result.update(status="baseline_unsupported",
                      reason="Не все обязательные режимы HTTP/TLS доступны в базовой проверке. Автозапуск недоступен; UNSUP не считается успешной проверкой.")
    elif baseline_metrics["supportedPassed"] == baseline_metrics["supportedTotal"]:
        result.update(status="baseline_reachable", baselineReachable=True,
                      reason="Адреса Standard отвечают без zapret; работа видео и голоса не проверена. Улучшение не подтверждено.")
        if baseline_tls13_unsupported:
            result["reason"] += (f" TLS1.3 явно не поддерживается: {baseline_metrics['unsupported']} проверок не выполнены "
                                 f"(UNSUP); успешно {baseline_metrics['passed']} из {baseline_metrics['total']} HTTP/TLS-проверок.")
    elif candidates:
        best = candidates[0]
        matching_support = (best["excludedUnsupportedModes"] == ["TLS1.3"] if baseline_tls13_unsupported
                            else best["unsupported"] == 0)
        if matching_support and best["supportedPassed"] == best["supportedTotal"]:
            result.update(status="recommended", recommendedId=best["strategyId"],
                          reason="Все HTTP/TLS-проверки Standard прошли, результат лучше базового. Работа видео и голоса не проверена.")
            if baseline_tls13_unsupported:
                result["reason"] = (f"Все поддерживаемые HTTP/TLS-проверки Standard прошли, результат лучше базового. "
                                    f"Успешно {best['passed']} из {best['total']}; {best['unsupported']} проверок TLS1.3 не выполнены "
                                    "(UNSUP во всех адресах и повторах, как в базовой проверке). Работа видео и голоса не проверена.")
        else:
            reason = ("Набор неподдерживаемых режимов отличается от базовой проверки или неполон. " if not matching_support
                      else "Лучшая стратегия не прошла все поддерживаемые HTTP/TLS-проверки Standard. ")
            result.update(status="partial", reason=reason + "Автоматический запуск не выполнен.")
    return result
