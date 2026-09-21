"""First-run ISP discovery, measured strategy selection, and confirmation."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import secrets
import threading

from .network_identity import detect_network
from .recommendation import recommend
from .probes import TARGETS, run_checks, summarize


class AutoSetupMixin:
    def initialize_auto(self):
        self.network = {"status": "unknown", "provider": None, "asn": None, "city": None,
                        "country": None, "source": None, "warning": None, "error": None}
        self.auto_setup = {"status": "pending", "reason": "При первом запуске приложение определит сеть и подберёт стратегию.",
                           "recommendation": None}
        self.auto_thread = None
        self.auto_cancel = threading.Event()
        key = self.data / "network.key"
        if not key.exists():
            key.write_text(secrets.token_hex(32), encoding="ascii")
        self.network_salt = key.read_text(encoding="ascii").strip()

    def auto_running(self):
        return self.auto_thread is not None and self.auto_thread.is_alive()

    def persist_settings(self):
        temp = self.data / "settings.tmp"
        temp.write_text(json.dumps(self.settings, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(self.data / "settings.json")

    def _auto_status(self, status, reason, recommendation=None):
        with self.lock:
            self.auto_setup.update(status=status, reason=reason)
            if recommendation is not None:
                self.auto_setup["recommendation"] = recommendation
        self.log("info" if status not in ("error", "blocked") else "warning", reason)

    def schedule_auto_setup(self):
        if not self.settings.get("autoSetupEnabled", True):
            self._auto_status("disabled", "Автоматическая настройка отключена. Её можно запустить вручную.")
        elif self.settings.get("setupCompleted") or self.settings.get("setupCancelled"):
            self.detect_network_async()
            self._auto_status("complete" if self.settings.get("setupCompleted") else "cancelled",
                              "Первичная проверка уже завершена. Для новой сети можно повторить подбор." if self.settings.get("setupCompleted")
                              else "Автоподбор был отменён. Он не возобновляется без команды пользователя.")
        else:
            self.start_auto_setup()

    def detect_network_async(self):
        with self.operation:
            if self.closing or self.job["running"] or self.auto_running():
                raise ValueError("Дождитесь завершения текущей операции.")
            self.auto_cancel.clear()
            self.network["status"] = "detecting"
            self.auto_thread = threading.Thread(target=self._detect_only, daemon=True)
            self.auto_thread.start()

    def _detect_only(self):
        try:
            network = detect_network(self.auto_cancel, salt=self.network_salt)
            with self.lock:
                self.network = network
            self.log("info", "Определение сети завершено: " + (network.get("provider") or network.get("error") or network["status"]))
        except Exception as exc:
            with self.lock:
                self.network.update(status="unavailable", error=str(exc))
            self.log("warning", "Не удалось определить сеть: " + str(exc))

    def start_auto_setup(self):
        with self.operation:
            if self.closing or self.job["running"] or self.auto_running():
                raise ValueError("Дождитесь завершения текущей операции.")
            self.auto_cancel.clear()
            self.cancel.clear()
            self.settings["setupCancelled"] = False
            with self.lock:
                self.auto_setup["recommendation"] = None
                self.network["status"] = "detecting"
            self._auto_status("detecting", "Определяем оператора текущего внешнего IP…")
            self.auto_thread = threading.Thread(target=self._auto_worker, daemon=True)
            self.auto_thread.start()

    def _auto_worker(self):
        original_id = self.active_id if self.running() else None
        original_settings = copy.deepcopy(self.settings)
        applying = False
        recommendation = None
        confirmation = None
        try:
            self._detect_only()
            if self.auto_cancel.is_set() or self.closing:
                return self._auto_status("cancelled", "Автоподбор отменён.")
            if self.network.get("status") != "detected":
                return self._auto_status("blocked", "Не удалось определить сеть. Повторите определение или используйте ручную проверку.")
            from .controller import is_admin
            if not is_admin():
                return self._auto_status("blocked", "Провайдер определён. Для автоматического подбора запустите ZapretByNerd3n.exe от имени администратора.")
            self.check_conflicts()
            self._auto_status("testing", "Сравниваем исходное подключение и все стратегии: по два запроса к каждому адресу.")
            self.begin_test([s["id"] for s in self.strategies], 2, automatic=True)
            self.worker.join()
            if self.auto_cancel.is_set() or self.cancel.is_set() or self.closing:
                return self._auto_status("cancelled", "Автоподбор отменён. Частичные результаты сохранены.")
            if self.job.get("error"):
                return self._auto_status("error", self.job["error"])
            results = copy.deepcopy(self.job["results"])
            baseline = next((r for r in results if r["strategyId"] == "baseline"), None)
            recommendation = recommend(results, baseline=baseline, expected_checks=2 * len(TARGETS))
            winner_id = recommendation.get("recommendedId")
            recommendation.update(strategyId=winner_id, applied=False,
                                  name=self.strategy(winner_id)["name"] if winner_id else None)
            with self.lock:
                self.auto_setup["recommendation"] = recommendation
                self.job["recommendation"] = recommendation
            if winner_id:
                fresh_network = detect_network(self.auto_cancel, salt=self.network_salt)
                if self.auto_cancel.is_set() or self.closing:
                    return self._auto_status("cancelled", "Автоподбор отменён до применения стратегии.")
                if fresh_network.get("status") != "detected" or fresh_network.get("fingerprint") != self.network.get("fingerprint"):
                    recommendation.update(strategyId=None, recommendedId=None, applied=False,
                                          reason="Сеть изменилась или её не удалось повторно определить. Автоматическое применение отменено.")
                    return self._auto_status("blocked", recommendation["reason"], recommendation)
                self._auto_status("confirming", "Повторно проверяем выбранную стратегию перед применением.", recommendation)
                applying = True
                self._stop()
                self._start(winner_id)
                checks = run_checks(2, self.auto_cancel)
                confirmation = {"strategyId": winner_id, "name": self.strategy(winner_id)["name"],
                                "checks": checks, **summarize(checks), "cancelled": self.auto_cancel.is_set()}
                confirmed = recommend([confirmation], baseline=baseline, expected_checks=2 * len(TARGETS))
                valid = (not self.auto_cancel.is_set() and self.running() and confirmed.get("recommendedId") == winner_id)
                if not valid:
                    self._stop()
                    if original_id and not self.closing:
                        self._start(original_id)
                    applying = False
                    recommendation.update(strategyId=None, recommendedId=None, applied=False,
                                          reason="Кандидат не прошёл повторную проверку всех адресов. Предыдущее состояние восстановлено.")
                    return self._auto_status("cancelled" if self.auto_cancel.is_set() else "error", recommendation["reason"], recommendation)
                recommendation["applied"] = True
            with self.operation:
                if self.auto_cancel.is_set() or self.closing:
                    raise ValueError("Автоподбор отменён перед сохранением результата.")
                self.settings["setupCompleted"] = True
                self.settings["setupCancelled"] = False
                self.settings["preferredStrategyId"] = winner_id
                self.persist_settings()
            applying = False
            self._auto_status("complete", recommendation.get("reason", "Автоматическая проверка завершена."), recommendation)
        except Exception as exc:
            with self.operation:
                self.settings = original_settings
            if applying:
                try:
                    self._stop()
                    if original_id and not self.closing:
                        self._start(original_id)
                except Exception as restore_error:
                    self.log("error", "Не удалось восстановить предыдущую стратегию: " + str(restore_error))
                if recommendation:
                    recommendation.update(strategyId=None, recommendedId=None, applied=False)
            self._auto_status("cancelled" if self.auto_cancel.is_set() else ("blocked" if isinstance(exc, ValueError) else "error"), str(exc))
        finally:
            if self.auto_cancel.is_set() and not self.closing:
                with self.operation:
                    self.settings["setupCancelled"] = True
                    try:
                        self.persist_settings()
                    except OSError as exc:
                        self.log("error", str(exc))
            if self.last_report and recommendation is not None:
                try:
                    path = self.data / "reports" / self.last_report
                    report = json.loads(path.read_text(encoding="utf-8"))
                    report["automaticSetup"] = {**copy.deepcopy(self.auto_setup), "confirmation": confirmation}
                    temp = path.with_suffix(".tmp")
                    temp.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
                    temp.replace(path)
                except (OSError, ValueError) as exc:
                    self.log("error", "Не удалось дополнить отчёт автоподбора: " + str(exc))
