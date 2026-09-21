from collections import Counter
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from zapret_ui import probes


def http_target(mode="HTTP"):
    return next(target for target in probes.TARGETS if target.mode == mode)


def ping_target():
    return next(target for target in probes.TARGETS if target.mode == "PING")


def check(target, attempt=1, status="OK", elapsed=10):
    row = probes._result(target, attempt)
    row.update(status=status, ok=status == "OK", timeMs=elapsed,
               error=None if status == "OK" else "diagnostic")
    return row


ENGLISH_PING = """
Pinging example.test [192.0.2.1] with 32 bytes of data:
Reply from 192.0.2.1: bytes=32 time<1ms TTL=128
Reply from 192.0.2.1: bytes=32 time=11ms TTL=128
Reply from 192.0.2.1: bytes=32 time=19ms TTL=128
Ping statistics for 192.0.2.1:
    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 19ms, Average = 10ms
"""
RUSSIAN_PING = """
Обмен пакетами с 192.0.2.1 по с 32 байтами данных:
Ответ от 192.0.2.1: число байт=32 время<1мс TTL=128
Ответ от 192.0.2.1: число байт=32 время=11мс TTL=128
Ответ от 192.0.2.1: число байт=32 время=19мс TTL=128
Статистика Ping для 192.0.2.1:
    Пакетов: отправлено = 3, получено = 3, потеряно = 0
    Минимальное = 0мс, Максимальное = 19мс, Среднее = 10мс
"""


class TargetTests(unittest.TestCase):
    def load(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.txt"
            path.write_text(text, encoding="utf-8-sig")
            return probes.load_targets(path)

    def test_default_matrix_is_36_http_plus_17_ping(self):
        self.assertEqual(len(probes.TARGETS), 53)
        self.assertEqual(Counter(target.mode for target in probes.TARGETS),
                         {"HTTP": 12, "TLS1.2": 12, "TLS1.3": 12, "PING": 17})
        self.assertEqual(len({(target.url, target.mode) for target in probes.TARGETS}), 53)
        self.assertEqual(sum(target.service == "Discord" for target in probes.TARGETS), 16)
        self.assertEqual(sum(target.service == "YouTube" for target in probes.TARGETS), 16)
        self.assertIn(probes.Target("Quad9DNS9999", "DNS", "PING:9.9.9.9", "PING"), probes.TARGETS)
        self.assertIn("https://redirector.googlevideo.com", {target.url for target in probes.TARGETS})
        self.assertIn("https://gateway.discord.gg", {target.url for target in probes.TARGETS})

    def test_bundled_file_matches_reference_defaults(self):
        path = Path(__file__).resolve().parents[1] / "bundle/utils/targets.txt"
        self.assertEqual(probes.load_targets(path), probes.TARGETS)

    def test_additional_https_and_ipv6_ping_targets(self):
        targets = self.load('# comment\nExtra = "https://example.test/check?q=1"\nDNSv6 = "PING:2001:4860:4860::8888"\n')
        self.assertEqual(len(targets), 5)
        self.assertEqual([target.mode for target in targets], list(probes.MODES) + ["PING"])
        self.assertEqual(targets[0].service, "Other")
        self.assertEqual(targets[-1].url, "PING:2001:4860:4860::8888")

    def test_missing_empty_invalid_encoding_and_oversize_fail_clearly(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.txt"
            with self.assertRaisesRegex(ValueError, "targets.txt"):
                probes.load_targets(path)
            for body in (b"", b"# only comments", b"\xff", b"x" * (probes.MAX_TARGET_FILE_BYTES + 1)):
                path.write_bytes(body)
                with self.assertRaises(ValueError):
                    probes.load_targets(path)

    def test_malformed_targets_and_duplicates_are_rejected(self):
        bad = ['Bad format', 'X = "http://example.test"', 'X = "file:///c:/data"',
               'X = "https://user:pass@example.test"', 'X = "https://example.test/#fragment"',
               'X = "https://example.test:99999"', 'X = "https://bad host"',
               'X = "https://example.test\\evil"', 'X = "PING:example.test"', 'X = "PING:-w"',
               'X = "https://example.test"\nx = "https://other.test"',
               'X = "https://example.test"\nY = "https://example.test"']
        for text in bad:
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "строка"):
                self.load(text)

    def test_http_names_cannot_be_misclassified_by_key_name(self):
        target = self.load('DiscordMain = "https://discord.com.evil.test"')[0]
        self.assertEqual(target.service, "Other")


class HttpTests(unittest.TestCase):
    def probe(self, *, code=0, output=b"200\t0.125\t192.0.2.1\t1.1", error=b"", forced=None, mode="HTTP"):
        with patch.object(probes, "_command", return_value=(code, output, error, forced)) as command:
            result = probes._http_probe(http_target(mode), 2, threading.Event(), "curl.exe")
        return result, command

    def test_head_flags_tls_verification_and_no_proxy(self):
        result, command = self.probe()
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["timeMs"], 125)
        self.assertEqual(result["remoteIp"], "192.0.2.1")
        args, _, timeout = command.call_args.args
        self.assertEqual(args[1], "--disable")
        for flag in ("--head", "--http1.1", "--show-error"):
            self.assertIn(flag, args)
        self.assertEqual(args[args.index("--max-time") + 1], "5")
        self.assertEqual(args[args.index("--noproxy") + 1], "*")
        self.assertEqual(args[args.index("--proto") + 1], "=https")
        for flag in ("--location", "-L", "--insecure", "-k", "--fail", "-4", "-6"):
            self.assertNotIn(flag, args)
        self.assertEqual(timeout, 6)

    def test_tls_modes_pin_tls_version_without_forcing_http11(self):
        for mode, version in (("TLS1.2", "1.2"), ("TLS1.3", "1.3")):
            _, command = self.probe(mode=mode)
            args = command.call_args.args[0]
            self.assertIn("--tlsv" + version, args)
            self.assertEqual(args[args.index("--tls-max") + 1], version)
            self.assertNotIn("--http1.1", args)

    def test_response_codes_include_redirect_and_errors_as_transport_success(self):
        for status in (200, 301, 403, 404, 429, 500):
            with self.subTest(status=status):
                result, _ = self.probe(output=f"{status}\t0.2\t192.0.2.1\t2".encode())
                self.assertTrue(result["ok"])
                self.assertEqual(result["httpStatus"], status)
                self.assertEqual(result["status"], "OK")

    def test_invalid_metadata_cannot_fake_success(self):
        for metadata in (b"", b"000\t0\t\t0", b"200\tnan\t1.1.1.1\t2", b"200\t-1\t1.1.1.1\t2", b"garbage"):
            self.assertFalse(self.probe(output=metadata)[0]["ok"])

    def test_dns_and_certificate_errors_are_ssl(self):
        for code, error in ((6, b"Could not resolve host"), (60, b"certificate rejected"),
                            (35, b"SSL certificate problem: self signed certificate")):
            result, _ = self.probe(code=code, error=error)
            self.assertEqual(result["status"], "SSL")
            self.assertFalse(result["ok"])

    def test_schannel_and_handshake35_are_errors_not_unsupported(self):
        for error in (b"SSL connect error", b"schannel: failed to receive handshake", b"TLS 1.3 is not supported by server"):
            result, _ = self.probe(code=35, error=error, mode="TLS1.3")
            self.assertEqual(result["status"], "ERROR")
            self.assertFalse(result["ok"])

    def test_unsupported_requires_explicit_client_capability_evidence(self):
        errors = [b"curl: option --tlsv1.3: the installed libcurl version does not support this",
                  b"curl: (4) A requested feature was not found built-in due to a build-time decision",
                  b"curl: option --tlsv1.3: unknown option",
                  b"schannel: TLS 1.3 is not supported on Windows prior to 11"]
        for error in errors:
            result, _ = self.probe(code=4, error=error, mode="TLS1.3")
            self.assertEqual(result["status"], "UNSUP", error)
            self.assertFalse(result["ok"])

    def test_timeout_cancel_and_output_limits_never_pass(self):
        for forced, expected in (("TIMEOUT", "ERROR"), ("OUTPUT_LIMIT", "ERROR"), ("CANCELLED", "CANCELLED")):
            result, _ = self.probe(forced=forced)
            self.assertEqual(result["status"], expected)
            self.assertFalse(result["ok"])

    def test_missing_curl_and_os_error_are_visible(self):
        result = probes._http_probe(http_target(), 1, threading.Event(), None)
        self.assertEqual(result["status"], "UNSUP")
        with patch.object(probes, "_command", side_effect=OSError("cannot start")):
            result = probes._http_probe(http_target(), 1, threading.Event(), "curl")
        self.assertEqual(result["status"], "ERROR")


class PingTests(unittest.TestCase):
    def probe(self, text, code=0, forced=None):
        with patch.object(probes, "_command", return_value=(code, text, b"", forced)) as command:
            result = probes._ping_probe(ping_target(), 1, threading.Event(), "ping.exe")
        return result, command

    def test_english_russian_and_oem_replies_match(self):
        for text in (ENGLISH_PING.encode(), RUSSIAN_PING.encode(), RUSSIAN_PING.encode("cp866")):
            result, command = self.probe(text)
            self.assertTrue(result["ok"])
            self.assertEqual(result["timeMs"], 10)
            self.assertEqual(result["pingReceived"], 3)
            self.assertEqual(command.call_args.args[0], ["ping.exe", "-n", "3", "-w", "1000", "discord.com"])
            self.assertEqual(command.call_args.args[2], 8)

    def test_ipv6_and_french_echo_without_ttl(self):
        text = "\n".join(["Reply from 2001:db8::1: time=9ms", "Réponse de 2001:db8::1 : temps=12 ms", "Reply from 2001:db8::1: time<1ms"])
        result, _ = self.probe(text.encode())
        self.assertTrue(result["ok"])
        self.assertEqual(result["timeMs"], 7)

    def test_unreachable_exit_zero_is_not_success(self):
        text = "\n".join(["Reply from 192.0.2.2: Destination host unreachable."] * 3)
        result, _ = self.probe(text.encode(), code=0)
        self.assertFalse(result["ok"])
        self.assertEqual(result["pingReceived"], 0)

    def test_partial_loss_and_unrecognized_output_are_failures(self):
        for text in (b"Reply from 192.0.2.1: time=5ms TTL=128", b"unknown output", b"Request timed out."):
            self.assertFalse(self.probe(text)[0]["ok"])
        self.assertFalse(self.probe(ENGLISH_PING.encode(), code=1)[0]["ok"])

    def test_statistics_do_not_count_as_echo_replies(self):
        text = b"Minimum = 0ms, Maximum = 19ms, Average = 10ms"
        result, _ = self.probe(text)
        self.assertEqual(result["pingReceived"], 0)

    def test_cancellation_and_unavailable_platform_are_visible(self):
        result, _ = self.probe(ENGLISH_PING.encode(), forced="CANCELLED")
        self.assertEqual(result["status"], "CANCELLED")
        result = probes._ping_probe(ping_target(), 1, threading.Event(), None)
        self.assertEqual(result["status"], "UNSUP")
        self.assertIn("Windows", result["error"])


class FakeProcess:
    def __init__(self, args, *, stdin, stdout, stderr, shell, creationflags, cancel=None, body=b"ok", block=False):
        self.args = args
        self.returncode = None if block else 0
        self.killed = False
        self.waited = False
        self.stdout = stdout
        self.stderr = stderr
        stdout.write(body)
        stdout.flush()
        if cancel:
            cancel.set()
        if shell:
            raise AssertionError("shell=True is forbidden")
        if stdin is not subprocess.DEVNULL:
            raise AssertionError("stdin must be disconnected")

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout):
        self.waited = True
        return self.returncode


class ProcessTests(unittest.TestCase):
    def test_cancellation_kills_and_reaps_only_created_child(self):
        event = threading.Event()
        created = []
        def factory(*args, **kwargs):
            process = FakeProcess(*args, **kwargs, cancel=event, block=True)
            created.append(process)
            return process
        with patch.object(probes.subprocess, "Popen", side_effect=factory):
            result = probes._command(["curl.exe", "--head", "https://example.test"], event, 6)
        self.assertEqual(result[3], "CANCELLED")
        self.assertTrue(created[0].killed)
        self.assertTrue(created[0].waited)
        self.assertTrue(created[0].stdout.closed)
        self.assertFalse(Path(created[0].stdout.name).exists())

    def test_timeout_kills_and_reaps_child(self):
        created = []
        def factory(*args, **kwargs):
            process = FakeProcess(*args, **kwargs, block=True)
            created.append(process)
            return process
        with patch.object(probes.subprocess, "Popen", side_effect=factory), \
                patch.object(probes.time, "monotonic", side_effect=[0, 10]):
            result = probes._command(["ping.exe", "example.test"], threading.Event(), 8)
        self.assertEqual(result[3], "TIMEOUT")
        self.assertTrue(created[0].killed)
        self.assertTrue(created[0].waited)

    def test_output_file_limit_cannot_be_bypassed_on_process_exit(self):
        created = []
        def factory(*args, **kwargs):
            process = FakeProcess(*args, **kwargs, body=b"x" * (probes.MAX_OUTPUT_BYTES + 1))
            created.append(process)
            return process
        with patch.object(probes.subprocess, "Popen", side_effect=factory):
            result = probes._command(["curl"], threading.Event(), 6)
        self.assertEqual(result[3], "OUTPUT_LIMIT")
        self.assertEqual(len(result[1]), probes.MAX_OUTPUT_BYTES)
        self.assertTrue(created[0].stdout.closed)

    def test_pre_cancelled_command_never_spawns(self):
        event = threading.Event()
        event.set()
        with patch.object(probes.subprocess, "Popen") as popen:
            result = probes._command(["curl"], event, 6)
        popen.assert_not_called()
        self.assertEqual(result[3], "CANCELLED")

    def test_popen_failure_cleans_temporary_files(self):
        files = []
        def fail(*args, **kwargs):
            files.append(kwargs["stdout"])
            raise OSError("missing")
        with patch.object(probes.subprocess, "Popen", side_effect=fail):
            with self.assertRaises(OSError):
                probes._command(["curl"], threading.Event(), 6)
        self.assertTrue(files[0].closed)
        self.assertFalse(Path(files[0].name).exists())


class RunAndSummaryTests(unittest.TestCase):
    def test_full_matrix_repeats_and_callback_on_caller_thread(self):
        caller = threading.get_ident()
        callbacks, visits = [], {}
        lock = threading.Lock()
        def probe(target, attempt, *args):
            with lock:
                visits.setdefault((target.url, attempt), []).append(target.mode)
            return check(target, attempt)
        def callback(row):
            self.assertEqual(threading.get_ident(), caller)
            callbacks.append(row)
        with patch.object(probes, "_http_probe", side_effect=probe), patch.object(probes, "_ping_probe", side_effect=probe):
            rows = probes.run_checks(2, threading.Event(), callback)
        self.assertEqual(len(rows), 106)
        self.assertEqual(callbacks, rows)
        self.assertEqual(len({(row["url"], row["mode"], row["attempt"]) for row in rows}), 106)
        for (url, _), modes in visits.items():
            self.assertEqual(modes, ["PING"] if url.startswith("PING:") else list(probes.MODES))
        summary = probes.summarize(rows, 106)
        self.assertEqual((summary["passed"], summary["total"], summary["pingPassed"], summary["pingTotal"]), (72, 72, 34, 34))
        self.assertEqual(summary["checksTotal"], 106)
        self.assertTrue(summary["complete"])

    def test_custom_targets_and_cancellation_leave_partial_matrix(self):
        event = threading.Event()
        targets = probes.TARGETS[:4]
        def probe(target, attempt, *args):
            event.set()
            return check(target, attempt, "CANCELLED")
        with patch.object(probes, "_http_probe", side_effect=probe), patch.object(probes, "_ping_probe") as ping:
            rows = probes.run_checks(2, event, targets=targets)
        self.assertEqual(len(rows), 1)
        ping.assert_not_called()
        self.assertFalse(probes.summarize(rows, 8)["complete"])

    def test_pre_cancelled_run_spawns_no_checks(self):
        event = threading.Event()
        event.set()
        with patch.object(probes, "_http_probe") as probe:
            self.assertEqual(probes.run_checks(1, event), [])
        probe.assert_not_called()

    def test_invalid_repeats_empty_and_duplicate_targets_rejected(self):
        for repeats in (True, 0, 11, 1.5):
            with self.assertRaises(ValueError):
                probes.run_checks(repeats, threading.Event())
        for targets in ([], [http_target(), http_target()]):
            with self.assertRaises(ValueError):
                probes.run_checks(1, threading.Event(), targets=targets)

    def test_ping_never_inflates_http_score_and_unsupported_separate(self):
        rows = [check(http_target(), status="ERROR"), check(http_target("TLS1.2"), status="UNSUP"),
                check(http_target("TLS1.3")), check(ping_target())]
        summary = probes.summarize(rows, 4)
        self.assertEqual(summary["passed"], 1)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["score"], 33.3)
        self.assertEqual(summary["unsupported"], 1)
        self.assertEqual(summary["pingPassed"], 1)
        self.assertTrue(summary["complete"])

    def test_incomplete_duplicate_cancelled_legacy_and_inconsistent_results(self):
        valid = [check(target) for target in probes.TARGETS]
        self.assertTrue(probes.summarize(valid, 53)["complete"])
        variants = [valid[:-1], [valid[0]] * 53, [dict(row, status="CANCELLED", ok=False) for row in valid],
                    [dict(row, suiteId="old-five-checks") for row in valid],
                    [dict(row, ok=True, status="ERROR") for row in valid]]
        for rows in variants:
            self.assertFalse(probes.summarize(rows, 53)["complete"])
        self.assertFalse(probes.summarize([], 0)["complete"])

    def test_callback_failure_cancels_owned_workers(self):
        event = threading.Event()
        def fail(row):
            raise ValueError("UI callback failed")
        with patch.object(probes, "_http_probe", side_effect=lambda target, attempt, *args: check(target, attempt)):
            with self.assertRaisesRegex(ValueError, "UI callback"):
                probes.run_checks(1, event, fail, targets=probes.TARGETS[:3])
        self.assertTrue(event.is_set())


if __name__ == "__main__":
    unittest.main()
