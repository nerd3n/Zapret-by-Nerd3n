"""Conservative ranking of completed HTTPS/TCP measurements.

An automatic recommendation requires every endpoint to pass and improvement
over a complete baseline. Video playback, QUIC, WebSockets and voice are outside
this evidence, irrespective of a perfect HTTPS score.
"""
from __future__ import annotations

import math
import statistics

from .probes import TARGETS


SCOPE = "HTTPS/TCP only; playback, QUIC, Discord WebSocket and voice are untested"


def _metrics(result: dict, expected_checks: int) -> dict | None:
    if not isinstance(result, dict) or result.get("cancelled") or result.get("error"):
        return None
    checks = result.get("checks")
    if not isinstance(checks, list) or len(checks) != expected_checks:
        return None
    repeats = expected_checks // len(TARGETS)
    expected = {(target.url, attempt): target.service for target in TARGETS for attempt in range(1, repeats + 1)}
    seen = set()
    for check in checks:
        if not isinstance(check, dict) or type(check.get("ok")) is not bool or type(check.get("attempt")) is not int or not isinstance(check.get("url"), str):
            return None
        if check.get("error") in ("winws завершился во время проверки", "Отменено"):
            return None
        key = (check.get("url"), check["attempt"])
        if key not in expected or key in seen or check.get("service") != expected[key]:
            return None
        # A result carrying a transport/engine error cannot be a successful probe.
        if check["ok"] and check.get("error"):
            return None
        seen.add(key)
    if seen != set(expected):
        return None
    rates = {}
    for service in ("YouTube", "Discord"):
        subset = [check for check in checks if check["service"] == service]
        rates[service] = sum(check["ok"] for check in subset) / len(subset)
    successful = [check for check in checks if check["ok"]]
    times = [check["timeMs"] for check in successful
             if isinstance(check.get("timeMs"), (int, float)) and not isinstance(check["timeMs"], bool)
             and math.isfinite(check["timeMs"]) and check["timeMs"] >= 0]
    return {"strategyId": result.get("strategyId"), "name": result.get("name", ""),
            "experimental": bool(result.get("experimental")), "passed": len(successful), "total": expected_checks,
            "minimumServiceRate": min(rates.values()), "successRate": len(successful) / expected_checks,
            "serviceRates": rates, "medianMs": statistics.median(times) if times else None}


def recommend(results: list[dict], baseline: dict | None = None, expected_checks: int = 2 * len(TARGETS)) -> dict:
    """Recommend only a complete, fully passing candidate that beats baseline.

    Incomplete/cancelled runs and duplicates never become eligible. A complete
    partial candidate can appear in ranking, but is not applied automatically.
    """
    if type(expected_checks) is not int or expected_checks < len(TARGETS) or expected_checks % len(TARGETS):
        raise ValueError("Ожидалось полное число повторов всех проверок")
    if baseline is None:
        baseline = next((item for item in results if isinstance(item, dict) and item.get("strategyId") == "baseline"), None)
    candidates = []
    seen_ids = set()
    for result in results:
        if not isinstance(result, dict):
            continue
        identifier = result.get("strategyId")
        if not isinstance(identifier, str) or not identifier or identifier == "baseline" or identifier in seen_ids:
            continue
        seen_ids.add(identifier)
        metrics = _metrics(result, expected_checks)
        if metrics:
            candidates.append(metrics)
    candidates.sort(key=lambda item: (-item["minimumServiceRate"], -item["successRate"],
                                      item["medianMs"] if item["medianMs"] is not None else float("inf"),
                                      item["experimental"], item["strategyId"]))
    baseline_metrics = _metrics(baseline, expected_checks) if baseline is not None else None
    result = {"status": "no_valid_candidates", "recommendedId": None,
              "bestCandidateId": candidates[0]["strategyId"] if candidates else None,
              "bypassNotNeeded": False, "reason": "Нет завершённых проверок стратегий.",
              "ranking": candidates, "scope": SCOPE}
    if baseline_metrics is None:
        result.update(status="baseline_incomplete", reason="Базовая проверка не завершена; сравнение и автозапуск недоступны.")
    elif baseline_metrics["passed"] == expected_checks:
        result.update(status="bypass_not_needed", bypassNotNeeded=True,
                      reason="Все HTTPS/TCP-проверки проходят без zapret. Улучшение от обхода не подтверждено; видео и голос нужно проверить отдельно.")
    elif candidates:
        best = candidates[0]
        if best["passed"] == expected_checks:
            result.update(status="recommended", recommendedId=best["strategyId"],
                          reason="Все HTTPS/TCP-проверки обоих сервисов прошли, результат лучше базового. Видео и голос не проверены.")
        else:
            result.update(status="partial", reason="Ни одна стратегия не прошла все проверки обоих сервисов. Автоматический запуск не выполнен.")
    return result
