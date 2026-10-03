import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from zapret_ui import controller
from zapret_ui.probes import TARGETS, SUITE_ID


class StandardIntegrationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.strategy = {"id": "stock-example", "name": "Example", "experimental": False, "argv": ["never-run.exe"]}
        for patcher in (
            patch.object(controller, "catalog", return_value=[self.strategy]),
            patch.object(controller, "ProcessJob"),
            patch.object(controller.Controller, "external_processes", return_value=[]),
            patch.object(controller, "describe_provenance", return_value={}),
            patch.object(controller, "load_targets", return_value=tuple(TARGETS)),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def configured(self, values):
        (self.base / "data").mkdir(exist_ok=True)
        (self.base / "data/settings.json").write_text(json.dumps(values), encoding="utf-8")
        return controller.Controller(self.base)

    def test_old_completed_five_url_setup_requires_standard_retest(self):
        app = self.configured({"setupCompleted": True, "preferredStrategyId": "stock-example", "setupCancelled": True})
        self.assertFalse(app.settings["setupCompleted"])
        self.assertIsNone(app.settings["preferredStrategyId"])
        self.assertTrue(app.settings["setupCancelled"])

    def test_completed_standard_setup_stays_completed(self):
        app = self.configured({"setupCompleted": True, "setupTestSuite": SUITE_ID, "preferredStrategyId": "stock-example"})
        self.assertTrue(app.settings["setupCompleted"])
        self.assertEqual(app.settings["preferredStrategyId"], "stock-example")

    def test_bad_target_file_cannot_start_partial_or_fallback_test(self):
        app = controller.Controller(self.base)
        with patch.object(app, "check_conflicts"), patch.object(controller, "load_targets", side_effect=ValueError("Invalid targets")), patch.object(controller.threading, "Thread") as worker:
            with self.assertRaisesRegex(ValueError, "Invalid targets"):
                app.begin_test([], 1, baseline_only=True)
            worker.assert_not_called()
        self.assertFalse(app.job["running"])
        self.assertIn("Invalid targets", app.test_suite()["error"])

    def test_begin_pins_target_matrix_and_expected_counts(self):
        app = controller.Controller(self.base)
        with patch.object(app, "check_conflicts"), patch.object(controller.threading, "Thread") as worker:
            app.begin_test([], 2, baseline_only=True)
        self.assertEqual(worker.call_args.kwargs["args"][3], tuple(TARGETS))
        self.assertEqual(app.job["checksTotal"], 2 * len(TARGETS))
        self.assertEqual(app.job["testSuite"]["httpChecksPerRepeat"], 36)
        self.assertEqual(app.job["testSuite"]["pingChecksPerRepeat"], 17)

    def test_engine_exit_overrides_success_and_report_identifies_suite(self):
        app = controller.Controller(self.base)
        rows = [{"target": target.name, "service": target.service, "url": target.url,
                 "mode": target.mode, "attempt": 1, "status": "OK", "ok": True,
                 "error": None, "httpStatus": 200, "timeMs": 10, "suiteId": SUITE_ID, "scope": SUITE_ID} for target in TARGETS]
        with patch.object(app, "check_conflicts"), patch.object(app, "_start"), patch.object(app, "_stop"), patch.object(app, "running", return_value=False), patch.object(app.cancel, "wait", return_value=False), patch.object(controller, "run_checks", side_effect=lambda *args, **kwargs: copy.deepcopy(rows)):
            app._test_worker([self.strategy], 1, None, tuple(TARGETS))
        baseline, candidate = app.job["results"]
        self.assertEqual(baseline["passed"], 36)
        self.assertEqual(baseline["pingPassed"], 17)
        self.assertEqual(candidate["passed"], 0)
        self.assertFalse(candidate["complete"])
        self.assertIn("winws", candidate["error"])
        report = json.loads((app.data / "reports" / app.last_report).read_text(encoding="utf-8"))
        self.assertEqual(report["schemaVersion"], 2)
        self.assertEqual(report["suiteId"], SUITE_ID)
        self.assertEqual(len(report["targets"]), len(TARGETS))


if __name__ == "__main__":
    unittest.main()
