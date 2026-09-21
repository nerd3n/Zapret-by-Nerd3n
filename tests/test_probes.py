import json
from pathlib import Path
import subprocess
import threading
import unittest
from unittest.mock import patch

from zapret_ui import probes


def target(kind):
    return next(item for item in probes.TARGETS if item.kind == kind)


class ContentChecks(unittest.TestCase):
    def check_body(self, kind, body, mime="application/json", status=200, url=None):
        item = target(kind)
        return probes._content_error(item, status, mime, body, url or item.url)

    def test_gateway_valid_and_wrong_host(self):
        self.assertIsNone(self.check_body("gateway", b'{"url":"wss://gateway.discord.gg"}'))
        for address in ("https://gateway.discord.gg", "wss://gateway.discord.gg.evil.test", "wss://evil.test", "wss://user@gateway.discord.gg", "wss://["):
            self.assertIsNotNone(self.check_body("gateway", json.dumps({"url": address}).encode()))

    def test_http_errors_and_html_challenge_cannot_pass(self):
        valid = b'{"url":"wss://gateway.discord.gg"}'
        for status in (0, 301, 403, 404, 429, 500):
            self.assertIsNotNone(self.check_body("gateway", valid, status=status))
        self.assertIsNotNone(self.check_body("gateway", b"<html>Verify you are human</html>", mime="text/html"))
        self.assertIsNotNone(self.check_body("gateway", b'[]'))
        self.assertIsNotNone(self.check_body("gateway", b'{"url":'))

    def test_redirect_and_empty_response_rejected(self):
        self.assertIsNotNone(self.check_body("gateway", b'{"url":"wss://gateway.discord.gg"}', url="https://login.example/"))
        self.assertIsNotNone(self.check_body("gateway", b""))

    def test_image_must_be_complete_jpeg_not_200_block_page(self):
        self.assertIsNone(self.check_body("jpeg", b"\xff\xd8\xffimage\xff\xd9", mime="image/jpeg"))
        self.assertIsNotNone(self.check_body("jpeg", b"<html>blocked</html>", mime="image/jpeg"))
        self.assertIsNotNone(self.check_body("jpeg", b"\xff\xd8\xffpartial", mime="image/jpeg"))

    def test_youtube_requires_bootstrap_not_generic_brand_mentions(self):
        self.assertIsNone(self.check_body("youtube", b"<html><script>ytcfg.set({}); var ytInitialData={};</script></html>", mime="text/html"))
        self.assertIsNotNone(self.check_body("youtube", b"<html>YouTube is blocked</html>", mime="text/html"))

    def test_youtube_metadata_and_discord_html(self):
        valid = {"provider_name": "YouTube", "type": "video", "html": '<iframe src="https://www.youtube.com/embed/dQw4w9WgXcQ"></iframe>'}
        self.assertIsNone(self.check_body("oembed", json.dumps(valid).encode()))
        valid["provider_name"] = "Another service"
        self.assertIsNotNone(self.check_body("oembed", json.dumps(valid).encode()))
        self.assertIsNone(self.check_body("discord", b'<html><a href="https://discord.com/login">Discord</a></html>', mime="text/html"))
        self.assertIsNotNone(self.check_body("discord", b'<html>Discord blocked</html>', mime="text/html"))

    def test_body_limit(self):
        self.assertIsNotNone(self.check_body("gateway", b"x" * (probes.MAX_BODY_BYTES + 1)))


class FakeCurl:
    def __init__(self, args, cancel=None, returncode=0):
        self.args = args
        self.returncode = returncode
        self.cancel = cancel
        self.killed = False
        self.calls = 0
        Path(args[args.index("--output") + 1]).write_bytes(b'{"url":"wss://gateway.discord.gg"}')

    def communicate(self, timeout):
        self.calls += 1
        if self.cancel and not self.killed:
            self.cancel.set()
            raise subprocess.TimeoutExpired(self.args, timeout)
        return b"200\tapplication/json\t0.025\thttps://discord.com/api/v10/gateway", b"test error"

    def kill(self):
        self.killed = True
        self.returncode = -9

    def poll(self):
        return self.returncode


class ProcessChecks(unittest.TestCase):
    def test_success_uses_safe_curl_flags(self):
        with patch.object(probes.subprocess, "Popen", side_effect=lambda args, **kwargs: FakeCurl(args)) as popen:
            result = probes._probe(target("gateway"), 2, threading.Event(), "curl.exe")
        self.assertTrue(result["ok"])
        self.assertEqual(result["timeMs"], 25)
        self.assertEqual(result["scope"], "HTTPS/TCP")
        self.assertEqual(result["attempt"], 2)
        args, kwargs = popen.call_args
        command = args[0]
        self.assertFalse(kwargs["shell"])
        self.assertEqual(command[1], "--disable")
        self.assertIn("--http1.1", command)
        self.assertEqual(command[command.index("--noproxy") + 1], "*")
        self.assertEqual(command[command.index("--proto-redir") + 1], "=https")
        self.assertEqual(command[command.index("--max-time") + 1], "8")
        self.assertIn("--max-filesize", command)
        self.assertNotIn("--insecure", command)
        self.assertNotIn("-k", command)

    def test_curl_failure_overrides_valid_http_body(self):
        with patch.object(probes.subprocess, "Popen", side_effect=lambda args, **kwargs: FakeCurl(args, returncode=60)):
            result = probes._probe(target("gateway"), 1, threading.Event(), "curl.exe")
        self.assertFalse(result["ok"])
        self.assertIn("curl 60", result["error"])

    def test_cancellation_kills_only_own_process(self):
        cancel = threading.Event()
        processes = []

        def start(args, **kwargs):
            process = FakeCurl(args, cancel=cancel)
            processes.append(process)
            return process

        with patch.object(probes.subprocess, "Popen", side_effect=start):
            result = probes._probe(target("gateway"), 1, cancel, "curl.exe")
        self.assertTrue(processes[0].killed)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "Отменено")

    def test_pre_cancelled_run_launches_nothing(self):
        cancel = threading.Event()
        cancel.set()
        with patch.object(probes.subprocess, "Popen") as popen:
            self.assertEqual(probes.run_checks(3, cancel), [])
            popen.assert_not_called()

    def test_repeats_callbacks_and_summary(self):
        callbacks = []

        def check(item, attempt, cancel, curl):
            result = probes._result(item, attempt)
            result.update(ok=item.service == "Discord", timeMs=20 * attempt)
            return result

        with patch.object(probes, "_probe", side_effect=check):
            results = probes.run_checks(2, threading.Event(), callbacks.append)
        self.assertEqual(len(results), 10)
        self.assertEqual(callbacks, results)
        self.assertEqual(probes.summarize(results), {"passed": 4, "total": 10, "medianMs": 30, "score": 40.0})
        self.assertEqual(probes.summarize([]), {"passed": 0, "total": 0, "medianMs": None, "score": 0})

    def test_missing_curl_is_clear_failure(self):
        result = probes._probe(target("gateway"), 1, threading.Event(), None)
        self.assertFalse(result["ok"])
        self.assertIn("curl", result["error"])

    def test_invalid_repeat_count(self):
        for value in (0, -1, 11, True, 1.5, "2"):
            with self.assertRaises(ValueError):
                probes.run_checks(value, threading.Event())


if __name__ == "__main__":
    unittest.main()
