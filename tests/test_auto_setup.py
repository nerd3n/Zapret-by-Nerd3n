import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from zapret_ui import auto_setup, controller
from zapret_ui.probes import TARGETS, SUITE_ID


NETWORK = {"status": "detected", "provider": "Example ISP", "asn": "AS12345", "city": "Example City",
           "country": "Example", "source": "fixture", "fingerprint": "f" * 64, "warning": "External network only", "error": None}
STRATEGIES = [{"id": "candidate", "name": "Candidate", "experimental": False, "argv": ["never-run.exe"]},
              {"id": "previous", "name": "Previous", "experimental": False, "argv": ["never-run.exe"]}]
ABSENT_SERVICE = {"supported": True, "installed": False, "owned": False, "running": False,
                  "status": "not_installed", "state": "not_installed", "pid": None,
                  "strategyId": None, "strategyName": None, "startType": None,
                  "path": None, "error": None}


def measurement(identifier, success=True):
    checks = [{"target": target.name, "url": target.url, "service": target.service, "attempt": attempt,
               "mode": target.mode, "status": "OK" if success else "ERROR",
               "ok": success, "error": None, "httpStatus": 200 if success else 0, "timeMs": 100,
               "scope": SUITE_ID, "suiteId": SUITE_ID} for attempt in (1,) for target in TARGETS]
    return {"strategyId": identifier, "name": identifier, "experimental": False, "checks": checks,
            "suiteId": SUITE_ID, "error": None, "cancelled": False}


class AutoSetupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        # Scheduling must depend on this fixture, never services installed on
        # the machine running the test suite. Patch before Controller creation.
        self.service = Mock(spec=controller.ServiceManager)
        self.service.status.side_effect = lambda: copy.deepcopy(ABSENT_SERVICE)
        for operation in ("install", "start", "stop", "remove"):
            getattr(self.service, operation).side_effect = AssertionError("No service mutations in auto tests")
        for patcher in (patch.object(controller, "ServiceManager", return_value=self.service),
                        patch.object(controller, "catalog", return_value=copy.deepcopy(STRATEGIES)),
                        patch.object(controller, "load_targets", return_value=TARGETS),
                        patch.object(controller, "ProcessJob"),
                        patch.object(controller.Controller, "external_processes", return_value=[])):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.app = controller.Controller(self.base)
        self.events = []
        self.measurements = [measurement("baseline", False), measurement("candidate")]
        self.app.active_id = "previous"

        def start(identifier):
            self.events.append(("start", identifier))
            self.app.active_id = identifier

        def stop():
            self.events.append(("stop", self.app.active_id))
            self.app.active_id = None

        def begin(identifiers, repeats, automatic=False):
            self.assertEqual(repeats, 1)
            self.assertTrue(automatic)
            self.assertEqual(identifiers, [item["id"] for item in STRATEGIES])
            self.app.job.update(running=False, error=None, results=copy.deepcopy(self.measurements))
            self.app.worker = Mock()
            self.app.last_report = "fixture.json"
            (self.app.data / "reports" / "fixture.json").write_text(json.dumps({"providerVerifiedByUser": False}), encoding="utf-8")

        self.start = self.add_patch(patch.object(self.app, "_start", side_effect=start))
        self.stop = self.add_patch(patch.object(self.app, "_stop", side_effect=stop))
        self.add_patch(patch.object(self.app, "running", side_effect=lambda: self.app.active_id is not None))
        self.begin = self.add_patch(patch.object(self.app, "begin_test", side_effect=begin))
        self.conflicts = self.add_patch(patch.object(self.app, "check_conflicts"))
        self.admin = self.add_patch(patch.object(controller, "is_admin", return_value=True))
        self.detect = self.add_patch(patch.object(auto_setup, "detect_network", return_value=copy.deepcopy(NETWORK)))
        self.confirm = self.add_patch(patch.object(auto_setup, "run_checks", return_value=measurement("confirm")["checks"]))
        self.add_patch(patch.object(self.app.auto_cancel, "wait", return_value=False))
        # An accidental production engine launch must fail the test, not affect the host.
        self.add_patch(patch.object(controller.subprocess, "Popen", side_effect=AssertionError("No real process launches in auto tests")))

    def add_patch(self, patcher):
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def test_provider_detection_without_admin_stops_before_engine(self):
        self.admin.return_value = False
        self.app._auto_worker()
        self.assertEqual(self.app.network["provider"], "Example ISP")
        self.assertEqual(self.app.auto_setup["status"], "blocked")
        self.assertFalse(self.app.settings["providerVerified"])
        self.begin.assert_not_called()
        self.start.assert_not_called()

    def test_existing_external_engine_blocks_auto_comparison(self):
        self.conflicts.side_effect = ValueError("External winws is already running")
        self.app._auto_worker()
        self.assertEqual(self.app.auto_setup["status"], "blocked")
        self.begin.assert_not_called()
        self.start.assert_not_called()
        self.assertEqual(self.app.active_id, "previous")

    def test_complete_comparison_rechecks_network_confirms_and_persists(self):
        self.app._auto_worker()
        self.assertEqual(self.detect.call_count, 2)
        self.confirm.assert_called_once()
        self.assertEqual(self.confirm.call_args.args, (1, self.app.auto_cancel))
        self.assertEqual(self.confirm.call_args.kwargs["targets"], tuple(TARGETS))
        self.assertEqual(self.app.active_id, "candidate")
        self.assertEqual(self.app.auto_setup["status"], "complete")
        self.assertTrue(self.app.auto_setup["recommendation"]["applied"])
        settings = json.loads((self.app.data / "settings.json").read_text(encoding="utf-8"))
        self.assertTrue(settings["setupCompleted"])
        self.assertEqual(settings["preferredStrategyId"], "candidate")
        self.assertFalse(settings["providerVerified"])
        report = json.loads((self.app.data / "reports" / "fixture.json").read_text(encoding="utf-8"))
        self.assertEqual(report["automaticSetup"]["confirmation"]["passed"], sum(target.mode != "PING" for target in TARGETS))
        self.assertEqual(settings["setupTestSuite"], SUITE_ID)
        self.assertFalse(report["providerVerifiedByUser"])

    def test_perfect_baseline_does_not_start_recommended_engine(self):
        self.measurements[0] = measurement("baseline", True)
        self.app._auto_worker()
        self.assertEqual(self.app.auto_setup["status"], "complete")
        self.assertFalse(self.app.auto_setup["recommendation"]["bypassNotNeeded"])
        self.assertEqual(self.app.auto_setup["recommendation"]["status"], "baseline_reachable")
        self.start.assert_not_called()
        self.confirm.assert_not_called()

    def test_changed_network_cannot_apply_candidate(self):
        self.detect.side_effect = [copy.deepcopy(NETWORK), {**NETWORK, "fingerprint": "changed"}]
        self.app._auto_worker()
        self.assertEqual(self.app.auto_setup["status"], "blocked")
        self.assertIsNone(self.app.auto_setup["recommendation"]["recommendedId"])
        self.start.assert_not_called()
        self.assertEqual(self.app.active_id, "previous")

    def test_cancel_during_comparison_is_persistent_and_restores_previous(self):
        original_begin = self.begin.side_effect

        def cancel_during_comparison(*args, **kwargs):
            original_begin(*args, **kwargs)
            self.app.cancel_test()

        self.begin.side_effect = cancel_during_comparison
        self.app._auto_worker()
        self.assertEqual(self.app.auto_setup["status"], "cancelled")
        settings = json.loads((self.app.data / "settings.json").read_text(encoding="utf-8"))
        self.assertTrue(settings["setupCancelled"])
        self.start.assert_not_called()
        self.assertEqual(self.app.active_id, "previous")

    def test_cancel_during_fingerprint_recheck_is_cancelled_not_blocked(self):
        def detect(event, **kwargs):
            if self.detect.call_count == 2:
                event.set()
                return {"status": "cancelled", "fingerprint": None}
            return copy.deepcopy(NETWORK)

        self.detect.side_effect = detect
        self.app._auto_worker()
        self.assertEqual(self.app.auto_setup["status"], "cancelled")
        self.start.assert_not_called()
        self.assertTrue(self.app.settings["setupCancelled"])

    def test_failed_fresh_confirmation_restores_previous(self):
        self.confirm.return_value[0]["ok"] = False
        self.app._auto_worker()
        self.assertEqual(self.app.active_id, "previous")
        self.assertEqual([entry for entry in self.events if entry[0] == "start"], [("start", "candidate"), ("start", "previous")])
        self.assertFalse(self.app.auto_setup["recommendation"]["applied"])
        self.assertFalse(self.app.settings["setupCompleted"])

    def test_duplicate_confirmation_rows_cannot_fake_complete_success(self):
        self.confirm.return_value[0] = copy.deepcopy(self.confirm.return_value[1])
        self.app._auto_worker()
        self.assertEqual(self.app.active_id, "previous")
        self.assertFalse(self.app.auto_setup["recommendation"]["applied"])
        self.assertFalse(self.app.settings["setupCompleted"])

    def test_engine_exit_during_confirmation_is_not_a_successful_report(self):
        def engine_exits(*args, **kwargs):
            self.app.active_id = None
            return measurement("confirm")["checks"]
        self.confirm.side_effect = engine_exits
        self.app._auto_worker()
        self.assertEqual(self.app.active_id, "previous")
        self.assertFalse(self.app.auto_setup["recommendation"]["applied"])
        report = json.loads((self.app.data / "reports" / "fixture.json").read_text(encoding="utf-8"))
        confirmation = report["automaticSetup"]["confirmation"]
        self.assertFalse(confirmation["complete"])
        self.assertEqual(confirmation["passed"], 0)
        self.assertIn("winws", confirmation["error"])

    def test_failed_settings_persistence_restores_previous_and_settings(self):
        with patch.object(self.app, "persist_settings", side_effect=OSError("Disk full")):
            self.app._auto_worker()
        self.assertEqual(self.app.auto_setup["status"], "error")
        self.assertEqual(self.app.active_id, "previous")
        self.assertFalse(self.app.settings["setupCompleted"])
        self.assertIsNone(self.app.settings["preferredStrategyId"])
        self.assertFalse(self.app.auto_setup["recommendation"]["applied"])

    def test_cancelled_setup_is_not_resumed_on_restart(self):
        self.app.settings["setupCancelled"] = True
        with patch.object(self.app, "detect_network_async") as detect, patch.object(self.app, "start_auto_setup") as start:
            self.app.schedule_auto_setup()
        detect.assert_called_once()
        start.assert_not_called()
        self.assertEqual(self.app.auto_setup["status"], "cancelled")

    def test_completed_setup_refreshes_identity_without_retesting(self):
        self.app.settings["setupCompleted"] = True
        with patch.object(self.app, "detect_network_async") as detect, patch.object(self.app, "start_auto_setup") as start:
            self.app.schedule_auto_setup()
        detect.assert_called_once()
        start.assert_not_called()

    def test_busy_auto_operation_blocks_manual_mutations_and_second_auto_run(self):
        self.app.auto_thread = Mock()
        self.app.auto_thread.is_alive.return_value = True
        operations = (
            lambda: controller.Controller.start(self.app, "candidate"),
            lambda: controller.Controller.stop(self.app),
            lambda: controller.Controller.begin_test(self.app, ["candidate"]),
            lambda: controller.Controller.save_settings(self.app, {"provider": "Other"}),
            self.app.detect_network_async,
            self.app.start_auto_setup,
        )
        for operation in operations:
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                operation()
        self.start.assert_not_called()
        self.stop.assert_not_called()

    def test_cancel_while_conflict_check_is_in_progress_is_never_cleared(self):
        # Simulates the user hitting cancel while the blocking OS process scan
        # is still returning. Neither automatic nor manual setup may erase it.
        for automatic in (True, False):
            with self.subTest(automatic=automatic):
                self.app.cancel.clear()
                self.app.auto_cancel.clear()
                self.app.job["running"] = False
                self.conflicts.side_effect = self.app.cancel_test
                with patch.object(controller.threading, "Thread"):
                    try:
                        controller.Controller.begin_test(self.app, ["candidate"], automatic=automatic)
                    except ValueError:
                        pass
                self.assertTrue(self.app.cancel.is_set())
                self.assertTrue(self.app.auto_cancel.is_set())


if __name__ == "__main__":
    unittest.main()
