"""Own-process lifecycle and cancellable, auditable strategy comparison."""
from __future__ import annotations

import copy
import ctypes
import json
import os
from pathlib import Path
import subprocess
import threading
import time
from datetime import datetime, timezone

from . import __version__
from .strategies import catalog, describe_provenance
from .probes import TARGETS, SUITE_ID, load_targets, run_checks, summarize
from .process_job import ProcessJob
from .process_scan import winws_process_ids
from .auto_setup import AutoSetupMixin
from .windows_service import ServiceManager, ServiceError


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def is_admin():
    return os.name == "nt" and bool(ctypes.windll.shell32.IsUserAnAdmin())


def hidden():
    return {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}


class Controller(AutoSetupMixin):
    def __init__(self, base: Path):
        self.base = base.resolve()
        self.data = self.base / "data"
        self.data.mkdir(exist_ok=True)
        (self.data / "reports").mkdir(exist_ok=True)
        self.lock = threading.RLock()
        self.operation = threading.RLock()
        self.cancel = threading.Event()
        self.closing = False
        self.proc = None
        self.active_id = None
        self.worker = None
        self.process_job = ProcessJob()
        self.service_manager = ServiceManager(self.base)
        self.service_checked = 0
        self.service_state = {}
        self.service_busy = False
        self.logs = []
        self.job = {"running": False, "cancelRequested": False, "phase": "idle", "current": 0,
                    "total": 0, "results": [], "error": None}
        self.settings = {"settingsSchema": 2, "bundlePath": str(self.base / "bundle"), "provider": "",
                         "city": "", "providerVerified": False,
                         "autoSetupEnabled": True, "setupCompleted": False, "setupCancelled": False,
                         "preferredStrategyId": None, "setupTestSuite": None}
        config = self.data / "settings.json"
        if config.exists():
            try:
                loaded = json.loads(config.read_text(encoding="utf-8"))
                if not isinstance(loaded, dict):
                    raise ValueError("Настройки должны содержать объект JSON")
                for key in self.settings:
                    if key in loaded:
                        self.settings[key] = loaded[key]
                # 0.2 shipped an unconfirmed provider label, not a user choice.
                if (loaded.get("settingsSchema", 1) == 1
                        and loaded.get("provider") == "Инфолинк"
                        and loaded.get("city") == "Щёлково"
                        and not loaded.get("providerVerified")):
                    self.settings.update(provider="", city="")
            except (ValueError, OSError):
                self.log("warning", "Не удалось прочитать настройки. Использованы значения по умолчанию.")
        # Network identity must be reconfirmed in every app session.
        self.settings["providerVerified"] = False
        self.settings["settingsSchema"] = 2
        if self.settings["setupCompleted"] and self.settings.get("setupTestSuite") != SUITE_ID:
            self.settings.update(setupCompleted=False, preferredStrategyId=None)
            self.log("warning", "Прежние пять HTTPS-проверок не подтверждают результат Standard. Нужен новый подбор.")
        # The engine is shipped with this application, including after relocation.
        self.settings["bundlePath"] = str(self.base / "bundle")
        self.strategies = []
        self.catalog_error = None
        self.last_report = None
        self.external_pids = []
        self.external_checked = 0
        self.initialize_auto()
        self.reload_catalog()
        self.test_targets = tuple(TARGETS)
        self.test_suite_error = None
        try:
            self.load_test_suite()
        except (ValueError, OSError) as exc:
            self.test_suite_error = str(exc)
        self.refresh_service(force=True)
        try:
            self.external_processes()
            if self.external_pids:
                self.log("warning", "Обнаружен другой winws. Для сравнения стратегий его нужно остановить вручную.")
        except Exception as exc:
            self.log("warning", str(exc))
        self.log("info", "Приложение готово. Сеть провайдера пока не подтверждена.")

    def log(self, level, message):
        with self.lock:
            self.logs.append({"time": timestamp(), "level": level, "message": str(message)[:1800]})
            self.logs = self.logs[-250:]

    def reload_catalog(self):
        try:
            self.strategies = catalog(Path(self.settings["bundlePath"]))
            self.catalog_error = None
        except (ValueError, OSError) as exc:
            self.strategies = []
            self.catalog_error = str(exc)
            self.log("error", self.catalog_error)

    def strategy(self, identifier):
        found = next((s for s in self.strategies if s["id"] == identifier), None)
        if found is None:
            raise ValueError("Стратегия не найдена. Обновите список.")
        return found

    def load_test_suite(self):
        """Snapshot the same target file for baseline, candidates and confirmation."""
        try:
            targets = tuple(load_targets(Path(self.settings["bundlePath"]) / "utils" / "targets.txt"))
        except (ValueError, OSError) as exc:
            self.test_suite_error = str(exc)
            raise
        self.test_targets = targets
        self.test_suite_error = None
        return targets

    def test_suite(self, targets=None):
        targets = self.test_targets if targets is None else targets
        return {"id": SUITE_ID, "name": "Flowseal Standard", "error": self.test_suite_error,
                "endpointCount": len({target.url for target in targets}),
                "httpChecksPerRepeat": sum(target.mode != "PING" for target in targets),
                "pingChecksPerRepeat": sum(target.mode == "PING" for target in targets)}

    def running(self):
        process = self.proc
        return process is not None and process.poll() is None

    def refresh_service(self, force=False):
        if self.service_busy and not force:
            return copy.deepcopy(self.service_state)
        if force or time.monotonic() - self.service_checked > 3:
            try:
                service = self.service_manager.status()
            except Exception as exc:
                service = {"supported": os.name == "nt", "installed": None, "owned": False,
                           "running": False, "status": "error", "state": "unknown", "pid": None,
                           "strategyId": None, "strategyName": None, "startType": None,
                           "path": None, "error": str(exc)}
            with self.lock:
                self.service_state = service
                self.service_checked = time.monotonic()
        return copy.deepcopy(self.service_state)

    def check_service_available(self):
        service = self.refresh_service(force=True)
        if self.service_busy:
            raise ValueError("Дождитесь завершения операции со службой.")
        if service.get("error") and service.get("supported"):
            raise ValueError("Не удалось проверить службу zapret: " + service["error"])
        if service.get("installed"):
            raise ValueError("Установлен zapret с автозапуском. Удалите автозапуск перед сеансовым запуском или новым подбором.")

    def service_action(self, action, identifier=None):
        if action not in ("install", "start", "stop", "remove"):
            raise ValueError("Неизвестное действие со службой.")
        with self.operation:
            if self.closing or self.job["running"] or self.auto_running() or self.service_busy:
                raise ValueError("Дождитесь завершения текущей операции.")
            if not is_admin():
                raise ValueError("Для управления автозапуском запустите приложение от имени администратора.")
            status = self.refresh_service(force=True)
            if action == "install":
                self.strategy(identifier)
                if status.get("installed"):
                    raise ValueError("Служба уже установлена. Удалите автозапуск перед сменой стратегии.")
            elif not status.get("installed") or not status.get("owned"):
                raise ValueError("Служба этого приложения не установлена или принадлежит другой программе.")
            if status.get("error"):
                raise ValueError(status["error"])
            if action in ("install", "start") and self.external_processes():
                raise ValueError("Работает другой winws. Остановите его в программе, где он запущен.")
            previous = self.active_id if self.running() else None
            if previous and action != "install":
                raise ValueError("Сначала остановите сеансовую стратегию.")
            self.service_busy = True
            try:
                if previous:
                    self._stop()
                if action == "install":
                    self.service_manager.install(identifier)
                else:
                    getattr(self.service_manager, action)()
                self.log("info", {"install": "zapret установлен с автозапуском Windows. Служба работает независимо от окна.",
                                  "start": "Служба zapret запущена.", "stop": "Служба zapret остановлена. Автозапуск сохранён.",
                                  "remove": "Служба zapret удалена. Автозапуск отключён."}[action])
            except (ServiceError, OSError, ValueError) as exc:
                self.log("error", str(exc))
                self.service_busy = False
                remaining = self.refresh_service(force=True)
                if previous and not self.closing and not remaining.get("installed") and not remaining.get("error"):
                    try:
                        self._start(previous)
                    except Exception as restore_error:
                        self.log("error", "Не удалось восстановить сеансовую стратегию: " + str(restore_error))
                raise ValueError(str(exc)) from exc
            finally:
                self.service_busy = False
                self.refresh_service(force=True)
                self.external_checked = 0

    def state(self):
        self.refresh_service()
        if time.monotonic() - self.external_checked > 8:
            try:
                self.external_processes()
            except Exception:
                self.external_checked = time.monotonic()
        with self.lock:
            reports = sorted((self.data / "reports").glob("*.json"), reverse=True)
            process = self.proc
            running = process is not None and process.poll() is None
            return copy.deepcopy({"version": __version__, **self.settings,
                "admin": is_admin(), "catalogError": self.catalog_error,
                "externalProcessIds": list(self.external_pids),
                "service": self.service_state, "serviceBusy": self.service_busy,
                "network": self.network, "autoSetup": self.auto_setup, "testSuite": self.test_suite(),
                "strategies": [{k: v for k, v in s.items() if k != "argv"} for s in self.strategies],
                "process": {"running": running, "strategyId": self.active_id if running else None,
                            "pid": process.pid if running else None},
                "job": self.job, "logs": self.logs,
                "reports": [{"name": p.name, "created": datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat()} for p in reports[:30]],
                "lastReport": self.last_report})

    def save_settings(self, values):
        with self.operation:
            if self.closing:
                raise ValueError("Приложение закрывается.")
            if self.job["running"] or self.running() or self.auto_running():
                raise ValueError("Остановите стратегию и проверку перед изменением настроек.")
            proposed = dict(self.settings)
            if "bundlePath" in values and values["bundlePath"] != str(self.base / "bundle"):
                raise ValueError("Путь к комплекту zapret определяется приложением автоматически.")
            for key in ("provider", "city"):
                if key in values:
                    if not isinstance(values[key], str) or len(values[key]) > 100:
                        raise ValueError("Название провайдера и город должны быть строками до 100 символов.")
                    proposed[key] = values[key].strip()
            for key in ("providerVerified", "autoSetupEnabled"):
                if key in values:
                    if not isinstance(values[key], bool):
                        raise ValueError("Некорректное значение переключателя.")
                    proposed[key] = values[key]
            if proposed["providerVerified"] and not proposed["provider"]:
                raise ValueError("Для подтверждения профиля укажите провайдера или снимите отметку.")
            new_catalog = catalog(Path(proposed["bundlePath"]))
            proposed["bundlePath"] = str(Path(proposed["bundlePath"]).resolve())
            temp = self.data / "settings.tmp"
            temp.write_text(json.dumps(proposed, ensure_ascii=False, indent=2), encoding="utf-8")
            temp.replace(self.data / "settings.json")
            with self.lock:
                self.settings, self.strategies, self.catalog_error = proposed, new_catalog, None
            self.log("info", "Настройки сохранены.")

    def external_processes(self):
        self.external_checked = time.monotonic()
        if os.name != "nt":
            return []
        pids = winws_process_ids()
        process = self.proc
        own_pid = process.pid if process is not None and process.poll() is None else None
        service = self.refresh_service()
        service_pid = service.get("pid") if service.get("owned") and service.get("running") else None
        self.external_pids = [pid for pid in pids if pid not in (own_pid, service_pid)]
        return list(self.external_pids)

    def check_conflicts(self):
        self.check_service_available()
        if self.external_processes():
            raise ValueError("Уже работает другой winws или служба zapret. Остановите его вручную, затем повторите.")

    def _start(self, identifier):
        with self.operation:
            if self.closing:
                raise ValueError("Приложение закрывается.")
            self._start_unlocked(identifier)

    def _start_unlocked(self, identifier):
        if not is_admin():
            raise ValueError("Для winws нужны права администратора. Закройте приложение и запустите его от имени администратора.")
        strategy = self.strategy(identifier)
        self.check_conflicts()
        if self.running():
            raise ValueError("Сначала остановите текущую стратегию.")
        self.proc = subprocess.Popen(strategy["argv"], cwd=str(Path(self.settings["bundlePath"]) / "bin"),
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                     **hidden())
        self.process_job.assign(self.proc)
        self.active_id = identifier
        process = self.proc
        def read_output():
            try:
                for line in iter(process.stdout.readline, b""):
                    self.log("engine", line.decode("utf-8", errors="replace").strip())
            finally:
                process.stdout.close()
        threading.Thread(target=read_output, daemon=True).start()
        time.sleep(1.2)
        if process.poll() is not None:
            self.active_id = None
            raise ValueError(f"winws завершился с кодом {process.returncode}. Подробности в журнале.")
        self.log("info", f"Запущена стратегия {strategy['name']} (PID {process.pid}).")

    def start(self, identifier):
        with self.operation:
            if self.job["running"] or self.auto_running():
                raise ValueError("Дождитесь завершения проверки.")
            self._start(identifier)

    def _stop(self):
        with self.operation:
            self._stop_unlocked()

    def _stop_unlocked(self):
        if self.running():
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
            self.log("info", "Стратегия остановлена.")
        self.proc = None
        self.active_id = None

    def stop(self):
        with self.operation:
            if self.job["running"] or self.auto_running():
                raise ValueError("Сначала отмените проверку.")
            self._stop()

    def begin_test(self, identifiers, repeats=2, baseline_only=False, automatic=False):
        with self.operation:
            if self.closing:
                raise ValueError("Приложение закрывается.")
            if self.job["running"] or (self.auto_running() and not automatic):
                raise ValueError("Проверка уже выполняется.")
            if type(repeats) is not int or not 1 <= repeats <= 3:
                raise ValueError("Количество повторов должно быть от 1 до 3.")
            if not isinstance(identifiers, list) or len(identifiers) > 64 or any(not isinstance(i, str) for i in identifiers):
                raise ValueError("Некорректный список стратегий.")
            identifiers = list(dict.fromkeys(identifiers))
            if not baseline_only and not identifiers:
                raise ValueError("Выберите хотя бы одну стратегию.")
            selected = [copy.deepcopy(self.strategy(i)) for i in identifiers]
            if selected and not is_admin():
                raise ValueError("Перебор стратегий требует запуска приложения от имени администратора.")
            if not automatic:
                self.cancel.clear()
            self.check_conflicts()
            targets = self.load_test_suite()
            previous = self.active_id if self.running() else None
            if automatic and self.auto_cancel.is_set():
                raise ValueError("Автоподбор отменён.")
            with self.lock:
                self.job = {"running": True, "cancelRequested": False, "phase": "baseline", "current": 0,
                            "total": len(selected) + 1, "results": [], "error": None,
                            "currentCheck": 0, "checksTotal": len(targets) * repeats,
                            "testSuite": self.test_suite(targets)}
            self.worker = threading.Thread(target=self._test_worker, args=(selected, repeats, previous, targets), daemon=True)
            self.worker.start()

    def cancel_test(self):
        self.auto_cancel.set()
        self.cancel.set()
        with self.lock:
            self.job["cancelRequested"] = True
        self.log("info", "Запрошена отмена проверки.")

    def _test_worker(self, selected, repeats, previous, targets=None):
        targets = tuple(self.test_targets if targets is None else targets)
        expected_checks = repeats * len(targets)
        started = timestamp()
        error = None
        self.log("info", "Начата Flowseal Standard: HTTP/1.1, TLS 1.2, TLS 1.3 и ping. Видео и голос не проверяются.")
        try:
            self._stop()
            for index, strategy in enumerate([None] + selected):
                if self.cancel.is_set():
                    break
                self.check_conflicts()
                identifier = strategy["id"] if strategy else "baseline"
                name = strategy["name"] if strategy else "Без zapret"
                with self.lock:
                    self.job.update(phase=name, current=index, currentCheck=0, checksTotal=expected_checks)
                startup_error = None
                checks = []
                def progress(check):
                    with self.lock:
                        self.job["currentCheck"] += 1
                        self.job["lastCheck"] = {key: check.get(key) for key in ("target", "mode", "status")}
                try:
                    if strategy:
                        self._start(identifier)
                        if self.cancel.wait(5):
                            break
                    checks = run_checks(repeats, self.cancel, on_check=progress, targets=targets)
                    if strategy and not self.running():
                        startup_error = "winws завершился во время проверки"
                        for check in checks:
                            check.update(ok=False, status="ERROR", error=startup_error)
                except (OSError, ValueError, subprocess.SubprocessError) as exc:
                    startup_error = str(exc)
                    self.log("error", f"{name}: {startup_error}")
                finally:
                    self._stop()
                result = {"strategyId": identifier, "name": name, "experimental": bool(strategy and strategy["experimental"]),
                          "suiteId": SUITE_ID, "repeats": repeats, "expectedChecks": expected_checks,
                          "expectedHttp": repeats * sum(target.mode != "PING" for target in targets),
                          "expectedPing": repeats * sum(target.mode == "PING" for target in targets),
                          "checks": checks, **summarize(checks, expected_checks=expected_checks), "error": startup_error,
                          "cancelled": self.cancel.is_set()}
                result["complete"] = bool(result["complete"] and not startup_error and not self.cancel.is_set())
                with self.lock:
                    self.job["results"].append(result)
                    self.job["current"] = index + 1
                self.log("info", f"{name}: HTTP/TLS {result['passed']}/{result['total']}; ping {result['pingPassed']}/{result['pingTotal']}.")
        except Exception as exc:
            error = str(exc)
            self.log("error", error)
        finally:
            try:
                self._stop()
                if previous and not self.closing:
                    self._start(previous)
                    self.log("info", "Восстановлена ранее запущенная стратегия.")
            except Exception as exc:
                error = (error + "; " if error else "") + "Не удалось восстановить стратегию: " + str(exc)
                self.log("error", error)
            cancelled = self.cancel.is_set()
            provenance = None
            try:
                provenance = describe_provenance(Path(self.settings["bundlePath"]))
            except Exception as exc:
                error = (error + "; " if error else "") + "Не удалось прочитать сведения о сборке: " + str(exc)
                self.log("error", error)
            report = {"schemaVersion": 2, "appVersion": __version__, "started": started, "finished": timestamp(),
                      "provider": self.settings["provider"], "city": self.settings["city"],
                      "providerVerifiedByUser": self.settings["providerVerified"],
                      "detectedNetwork": copy.deepcopy(self.network),
                      "suiteId": SUITE_ID, "testSuite": self.test_suite(targets),
                      "targets": [{"name": target.name, "service": target.service, "url": target.url, "mode": target.mode} for target in targets],
                      "scope": "Flowseal Standard: HTTPS HEAD HTTP/1.1, TLS1.2, TLS1.3 and ICMP; direct connection without proxy",
                      "limitations": ["Не проверяет воспроизведение видео, QUIC, Discord WebSocket и голос.",
                                      "Оператор внешнего IP определяется автоматически; домашний провайдер может отличаться из-за VPN или туннеля.",
                                      "Успешный baseline не подтверждает эффективность обхода.",
                                      "VPN и системный сетевой фильтр могут влиять на результат."],
                      "repeats": repeats, "cancelled": cancelled, "error": error,
                      "provenance": provenance,
                      "results": copy.deepcopy(self.job["results"])}
            filename = datetime.now().strftime("%Y%m%d-%H%M%S-%f") + ".json"
            saved = False
            try:
                (self.data / "reports" / filename).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
                self.last_report = filename
                saved = True
            except Exception as exc:
                error = (error + "; " if error else "") + f"Не удалось сохранить отчёт: {exc}"
                self.log("error", error)
            with self.lock:
                self.job.update(running=False, phase="cancelled" if cancelled else ("error" if error else "complete"), error=error)
            self.log("info", ("Проверка отменена." if cancelled else "Проверка завершена.") + (" Отчёт сохранён." if saved else " Отчёт не сохранён."))

    def close(self):
        with self.operation:
            self.closing = True
            self.cancel.set()
            self.auto_cancel.set()
        if self.auto_thread and self.auto_thread.is_alive():
            self.auto_thread.join(timeout=20)
        if self.worker and self.worker.is_alive():
            self.worker.join(timeout=15)
        self._stop()
        self.process_job.close()
