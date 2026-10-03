import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from zapret_ui import controller, startup_diagnostics as diagnostics


class DelayedPipe:
    def __init__(self, output=b"late stderr: invalid parameter\n"):
        self.output = output
        self.entered = threading.Event()
        self.release = threading.Event()
        self.closed = threading.Event()

    def readline(self, limit):
        self.entered.set()
        if not self.release.wait(2):
            raise TimeoutError("test pipe was not released")
        result, self.output = self.output[:limit], self.output[limit:]
        return result

    def close(self):
        self.closed.set()


class StartupDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        # A minimal controller isolates every test from host SCM, process scans and
        # WinDivert. Only the explicitly permitted Python subprocess below is real.
        self.app = controller.Controller.__new__(controller.Controller)
        self.app.base = Path(temporary.name)
        self.app.data = self.app.base / "data"
        self.app.data.mkdir()
        self.app.settings = {"bundlePath": str(self.app.base / "bundle")}
        (self.app.base / "bundle/bin").mkdir(parents=True)
        self.app.strategies = [{"id": "one", "name": "Test strategy", "argv": ["never-run-winws.exe", "--test"]}]
        self.app.proc = None
        self.app.active_id = None
        self.app.logs = []
        self.app.lock = threading.RLock()
        self.app.process_job = Mock()
        self.app.check_conflicts = Mock()
        for active_patch in (patch.object(controller, "is_admin", return_value=True),
                             patch.object(controller.time, "sleep"),
                             patch.object(controller.subprocess, "Popen", side_effect=AssertionError("No real winws"))):
            active_patch.start()
            self.addCleanup(active_patch.stop)

    def process(self, output=b"bad option: --test\n", code=2):
        return SimpleNamespace(pid=12345, returncode=code, stdout=io.BytesIO(output), poll=lambda: code)

    def failure(self, process):
        with patch.object(controller.subprocess, "Popen", return_value=process) as popen:
            with self.assertRaises(ValueError) as caught:
                self.app._start_unlocked("one")
        return str(caught.exception), popen

    def report(self):
        return json.loads((self.app.data / diagnostics.FAILURE_FILENAME).read_text(encoding="utf-8"))

    def test_early_failure_contains_its_output_and_persists_after_controller_is_gone(self):
        self.app.log("engine", "OLD PROCESS: unrelated failure")
        message, popen = self.failure(self.process())
        self.assertIn("кодом 2", message)
        self.assertIn("bad option: --test", message)
        self.assertNotIn("OLD PROCESS", message)
        self.assertIsNone(self.app.active_id)
        self.assertEqual(popen.call_args.kwargs["stderr"], subprocess.STDOUT)
        report_path = self.app.data / diagnostics.FAILURE_FILENAME
        report = self.report()
        self.assertEqual(report["exitCode"], 2)
        self.assertEqual(report["strategyId"], "one")
        self.assertEqual(report["pid"], 12345)
        self.assertEqual(report["outputTail"], "bad option: --test")
        self.assertTrue(report["readerComplete"])
        self.assertNotIn("OLD PROCESS", report["outputTail"])
        del self.app
        self.assertEqual(json.loads(report_path.read_text(encoding="utf-8"))["exitCode"], 2)

    def test_reader_race_is_drained_before_failure_is_reported(self):
        stream = DelayedPipe()
        self.addCleanup(stream.release.set)
        timer = threading.Timer(0.04, stream.release.set)
        self.addCleanup(timer.cancel)
        process = self.process()
        process.stdout = stream
        def exited():
            self.assertTrue(stream.entered.wait(1))
            timer.start()
            return 2
        process.poll = exited
        message, _ = self.failure(process)
        self.assertIn("late stderr: invalid parameter", message)
        self.assertTrue(stream.closed.is_set())
        self.assertTrue(self.report()["readerComplete"])

    def test_inherited_pipe_does_not_block_startup_failure_indefinitely(self):
        stream = DelayedPipe()
        process = self.process()
        process.stdout = stream
        before = time.monotonic()
        try:
            with patch.object(diagnostics, "READER_WAIT_SECONDS", 0.03):
                message, _ = self.failure(process)
            self.assertLess(time.monotonic() - before, 1)
            self.assertFalse(self.report()["readerComplete"])
            self.assertIn("не завершилось за отведённое время", message)
            self.assertIn("кодом 2", message)
        finally:
            stream.release.set()
            self.assertTrue(stream.closed.wait(1))

    def test_large_single_line_is_bounded_and_last_error_is_retained(self):
        process = self.process(b"x" * (diagnostics.MAX_OUTPUT_BYTES * 4) + b"\nFINAL ERROR\n")
        message, _ = self.failure(process)
        report = self.report()
        self.assertLessEqual(len(report["outputTail"].encode("utf-8")), diagnostics.MAX_OUTPUT_BYTES)
        self.assertTrue(report["outputTruncated"])
        self.assertTrue(report["outputTail"].endswith("FINAL ERROR"))
        self.assertIn("FINAL ERROR", message)
        self.assertLess(len(message), diagnostics.MESSAGE_OUTPUT_CHARS + 1000)

    def test_disk_failure_keeps_main_error_and_previous_report(self):
        previous = self.app.data / diagnostics.FAILURE_FILENAME
        previous.write_text('{"previous":true}', encoding="utf-8")
        with patch.object(diagnostics.os, "replace", side_effect=PermissionError("disk denied")):
            message, _ = self.failure(self.process())
        self.assertIn("кодом 2", message)
        self.assertIn("bad option", message)
        self.assertIn("Не удалось сохранить диагностику: disk denied", message)
        self.assertEqual(json.loads(previous.read_text(encoding="utf-8")), {"previous": True})
        self.assertEqual(list(self.app.data.glob(".startup-failure-*")), [])

    def test_broken_logger_does_not_interrupt_capture_or_mask_failure(self):
        with patch.object(self.app, "log", side_effect=OSError("logger failed")):
            message, _ = self.failure(self.process(b"first line\nfinal native reason\n"))
        self.assertIn("final native reason", message)
        self.assertIn("first line", self.report()["outputTail"])
        self.assertTrue(self.report()["readerComplete"])

    def test_disk_flush_failure_never_publishes_partial_diagnostic(self):
        with patch.object(diagnostics.os, "fsync", side_effect=OSError("disk full")):
            message, _ = self.failure(self.process())
        self.assertIn("bad option", message)
        self.assertIn("disk full", message)
        self.assertFalse((self.app.data / diagnostics.FAILURE_FILENAME).exists())
        self.assertEqual(list(self.app.data.glob(".startup-failure-*")), [])

    def test_reader_io_failure_still_reports_original_exit_code(self):
        process = self.process()
        process.stdout = Mock()
        process.stdout.readline.side_effect = OSError("pipe unavailable")
        message, _ = self.failure(process)
        self.assertIn("кодом 2", message)
        self.assertIn("pipe unavailable", message)
        self.assertEqual(self.report()["readerError"], "pipe unavailable")

    def test_immediate_exit_during_job_assignment_keeps_native_output(self):
        self.app.process_job.assign.side_effect = OSError("job assignment failed")
        message, _ = self.failure(self.process(b"fatal before assignment\n"))
        self.assertIn("fatal before assignment", message)
        self.assertIn("job assignment failed", message)
        self.assertEqual(self.report()["assignmentError"], "job assignment failed")
        self.assertIsNone(self.app.active_id)

    def test_empty_output_does_not_invent_reason_for_code_two(self):
        message, _ = self.failure(self.process(b""))
        self.assertIn("кодом 2", message)
        self.assertIn("Вывод процесса не получен", message)
        self.assertNotIn("не найден", message)


class RealPipeDiagnosticsTests(unittest.TestCase):
    def test_real_python_stdout_and_stderr_are_both_captured(self):
        # No winws, driver or service: this fixture only writes to two pipes and exits.
        command = [sys.executable, "-c", "import sys; print('stdout context',flush=True); print('stderr cause',file=sys.stderr,flush=True); sys.exit(2)"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL, **controller.hidden())
        self.addCleanup(lambda: process.wait(timeout=3))
        captured = diagnostics.StartupOutput(process.stdout, Mock())
        captured.start()
        self.assertEqual(process.wait(timeout=3), 2)
        result = captured.wait()
        self.assertIn("stdout context", result["outputTail"])
        self.assertIn("stderr cause", result["outputTail"])
        self.assertTrue(result["readerComplete"])


if __name__ == "__main__":
    unittest.main()
