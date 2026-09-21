import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from zapret_ui import controller


STRATEGIES = [
    {"id": "one", "name": "First", "experimental": False, "argv": ["winws.exe"]},
    {"id": "two", "name": "Second", "experimental": True, "argv": ["winws.exe"]},
]


class ControllerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.catalog_patch = patch.object(controller, "catalog", return_value=STRATEGIES.copy())
        self.catalog_patch.start()
        self.addCleanup(self.catalog_patch.stop)
        self.provenance_patch = patch.object(controller, "describe_provenance", return_value={"source": "test fixture"})
        self.provenance_patch.start()
        self.addCleanup(self.provenance_patch.stop)
        self.app = controller.Controller(Path(self.temporary.name))
        self.addCleanup(self.app.process_job.close)
        self.conflicts_patch = patch.object(self.app, "check_conflicts")
        self.conflicts_patch.start()
        self.addCleanup(self.conflicts_patch.stop)
        self.app.job["running"] = True

    def report(self):
        return json.loads((self.app.data / "reports" / self.app.last_report).read_text(encoding="utf-8"))

    def test_cancel_before_checks_restores_previous_strategy(self):
        self.app.cancel.set()
        with patch.object(self.app, "_start") as start, patch.object(self.app, "_stop"), patch.object(controller, "run_checks") as checks:
            self.app._test_worker(STRATEGIES[:1], 1, "one")
        checks.assert_not_called()
        start.assert_called_once_with("one")
        self.assertFalse(self.app.job["running"])
        self.assertEqual(self.app.job["phase"], "cancelled")
        self.assertTrue(self.report()["cancelled"])
        self.assertFalse(self.report()["providerVerifiedByUser"])

    def test_cancel_during_checks_stops_further_candidates(self):
        def interrupted_checks(repeats, event):
            event.set()
            return [{"ok": False, "timeMs": None, "error": "Отменено"}]

        with patch.object(self.app, "_start") as start, patch.object(self.app, "_stop"), patch.object(controller, "run_checks", side_effect=interrupted_checks):
            self.app._test_worker(STRATEGIES, 1, "one")
        start.assert_called_once_with("one")
        self.assertEqual(len(self.report()["results"]), 1)
        self.assertTrue(self.report()["results"][0]["cancelled"])
        self.assertFalse(self.app.job["running"])

    def test_failed_restore_is_reported_and_job_finishes(self):
        with patch.object(self.app, "_start", side_effect=ValueError("driver refused")), patch.object(self.app, "_stop"), patch.object(controller, "run_checks", return_value=[]):
            self.app._test_worker([], 1, "one")
        self.assertFalse(self.app.job["running"])
        self.assertEqual(self.app.job["phase"], "error")
        self.assertIn("driver refused", self.app.job["error"])
        self.assertIn("driver refused", self.report()["error"])

    def test_shutdown_prevents_restore(self):
        self.app.closing = True
        self.app.cancel.set()
        with patch.object(self.app, "_start") as start, patch.object(self.app, "_stop"):
            self.app._test_worker([], 1, "one")
        start.assert_not_called()
        self.assertFalse(self.app.job["running"])

    def test_provenance_read_failure_cannot_leave_job_running(self):
        with patch.object(self.app, "_stop"), patch.object(controller, "run_checks", return_value=[]), patch.object(controller, "describe_provenance", side_effect=OSError("bundle removed")):
            self.app._test_worker([], 1, None)
        self.assertFalse(self.app.job["running"])
        self.assertIn("bundle removed", self.app.job["error"])

    def test_failed_report_write_finishes_job(self):
        with patch.object(self.app, "_stop"), patch.object(controller, "run_checks", return_value=[]), patch.object(Path, "write_text", side_effect=PermissionError("read only")):
            self.app._test_worker([], 1, None)
        self.assertFalse(self.app.job["running"])
        self.assertEqual(self.app.job["phase"], "error")
        self.assertIn("read only", self.app.job["error"])
        self.assertIsNone(self.app.last_report)

    def test_close_waits_for_inflight_start_before_cleanup(self):
        self.app.job["running"] = False
        entered_start = threading.Event()
        release_start = threading.Event()
        stopped = threading.Event()
        actions = []

        def start(_):
            entered_start.set()
            if not release_start.wait(2):
                raise RuntimeError("test start gate timed out")
            actions.append("started")

        def stop():
            actions.append("stopped")
            stopped.set()

        with patch.object(self.app, "_start", side_effect=start), patch.object(self.app, "_stop", side_effect=stop):
            start_thread = threading.Thread(target=self.app.start, args=("one",))
            start_thread.start()
            self.assertTrue(entered_start.wait(1))
            close_thread = threading.Thread(target=self.app.close)
            close_thread.start()
            stopped.wait(0.1)
            release_start.set()
            start_thread.join(2)
            close_thread.join(2)
        self.assertFalse(start_thread.is_alive())
        self.assertFalse(close_thread.is_alive())
        self.assertEqual(actions, ["started", "stopped"])

    def test_closing_rejects_new_start_and_test(self):
        self.app.job["running"] = False
        self.app.closing = True
        with patch.object(self.app, "_start_unlocked") as start:
            with self.assertRaises(ValueError):
                self.app.start("one")
            start.assert_not_called()
        with self.assertRaises(ValueError):
            self.app.begin_test([], baseline_only=True)


if __name__ == "__main__":
    unittest.main()
