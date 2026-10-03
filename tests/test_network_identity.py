import json
from pathlib import Path
import subprocess
import threading
import unittest
from unittest.mock import patch

from zapret_ui import network_identity as identity


PRIMARY = {"success": True, "ip": "8.8.8.8", "city": "Mountain View", "country": "United States",
           "connection": {"asn": 15169, "isp": "Google LLC", "org": "Google LLC"}, "latitude": 37.4}
FALLBACK = {"ip": "8.8.8.8", "city": "Mountain View", "country_name": "United States", "org": "Google LLC", "asn": "AS15169"}


class IdentityTests(unittest.TestCase):
    def test_primary_schema_and_privacy(self):
        with patch.object(identity, "_fetch_json", return_value=PRIMARY) as fetch:
            result = identity.detect_network(salt=b"local-test-secret" * 2)
        self.assertEqual(result["status"], "detected")
        self.assertEqual(result["provider"], "Google LLC")
        self.assertEqual(result["asn"], "AS15169")
        self.assertEqual(result["source"], "ipwho.is")
        self.assertEqual(fetch.call_count, 1)
        self.assertNotIn("8.8.8.8", json.dumps(result))
        self.assertNotIn("latitude", result)
        self.assertNotIn("providerVerified", result)
        self.assertIn("VPN", result["warning"])

    def test_fallback_after_primary_failure(self):
        with patch.object(identity, "_fetch_json", side_effect=[identity.DetectionError("HTTPS unavailable"), FALLBACK]):
            result = identity.detect_network()
        self.assertEqual(result["status"], "detected")
        self.assertEqual(result["source"], "ipapi.co")

    def test_documented_2ip_fallback_does_not_invent_city(self):
        payload = {"ip": "8.8.8.8", "as": "15169", "name_ripe": "Google LLC", "name_rus": ""}
        with patch.object(identity, "_fetch_json", side_effect=[identity.DetectionError("unavailable"), identity.DetectionError("unavailable"), payload]):
            result = identity.detect_network()
        self.assertEqual(result["status"], "detected")
        self.assertEqual(result["source"], "2ip.me")
        self.assertEqual(result["provider"], "Google LLC")
        self.assertEqual(result["asn"], "AS15169")
        self.assertIsNone(result["city"])
        self.assertIsNone(result["country"])

    def test_invalid_results_fail_without_echoing_raw_ip_or_api_error(self):
        bad_results = [
            {**PRIMARY, "success": False, "message": "sensitive 8.8.8.8"},
            {**PRIMARY, "ip": "192.168.1.2"}, {**PRIMARY, "ip": "invalid"},
            {**PRIMARY, "connection": None},
            {**PRIMARY, "connection": {"asn": True, "isp": "Example"}},
            {**PRIMARY, "connection": {"asn": 4294967296, "isp": "Example"}},
            {**PRIMARY, "connection": {"asn": 15169, "isp": ""}},
        ]
        for data in bad_results:
            with self.subTest(data=data), patch.object(identity, "_fetch_json", side_effect=[data, {"error": True, "reason": "8.8.8.8"}, {}]):
                result = identity.detect_network()
                self.assertEqual(result["status"], "unavailable")
                self.assertNotIn("8.8.8.8", json.dumps(result))

    def test_fingerprint_is_salted_stable_and_never_contains_ip(self):
        first = identity._parse_identity(PRIMARY, "ipwho.is", b"a" * 32)
        again = identity._parse_identity(FALLBACK, "ipapi.co", b"a" * 32)
        other_install = identity._parse_identity(PRIMARY, "ipwho.is", b"b" * 32)
        self.assertEqual(first["fingerprint"], again["fingerprint"])
        self.assertNotEqual(first["fingerprint"], other_install["fingerprint"])
        self.assertEqual(len(first["fingerprint"]), 64)

    def test_cancelled_detection_does_not_send_request(self):
        event = threading.Event()
        event.set()
        with patch.object(identity, "_fetch_json") as fetch:
            result = identity.detect_network(event)
        fetch.assert_not_called()
        self.assertEqual(result["status"], "cancelled")


class FakeProcess:
    def __init__(self, args, payload=PRIMARY, code=200, returncode=0, cancel=None):
        self.returncode = returncode
        self.code = code
        self.cancel = cancel
        self.killed = False
        self.args = args
        Path(args[args.index("--output") + 1]).write_bytes(json.dumps(payload).encode())

    def communicate(self, timeout):
        if self.cancel and not self.killed:
            self.cancel.set()
            raise subprocess.TimeoutExpired(self.args, timeout)
        return str(self.code).encode(), b"secret address 8.8.8.8"

    def kill(self):
        self.killed = True
        self.returncode = -9

    def poll(self):
        return self.returncode


class IdentityTransportTests(unittest.TestCase):
    def test_https_tls_no_proxy_no_curlrc_and_bounded_timeout(self):
        with patch.object(identity, "_curl_path", return_value="curl.exe"), patch.object(identity.subprocess, "Popen", side_effect=lambda args, **kwargs: FakeProcess(args)) as start:
            result = identity._fetch_json("ipwho.is", "https://ipwho.is/", threading.Event())
        self.assertEqual(result, PRIMARY)
        args, kwargs = start.call_args
        command = args[0]
        self.assertFalse(kwargs["shell"])
        self.assertEqual(command[1], "--disable")
        self.assertEqual(command[command.index("--noproxy") + 1], "*")
        self.assertEqual(command[command.index("--max-time") + 1], "6")
        self.assertEqual(command[command.index("--max-filesize") + 1], "16384")
        self.assertNotIn("--insecure", command)
        self.assertEqual(command[-1], "https://ipwho.is/")

    def test_http_and_tls_failures_do_not_echo_curl_diagnostics(self):
        for code, exitcode in ((429, 0), (200, 60), (0, 28)):
            with patch.object(identity, "_curl_path", return_value="curl.exe"), patch.object(identity.subprocess, "Popen", side_effect=lambda args, **kwargs: FakeProcess(args, code=code, returncode=exitcode)):
                with self.assertRaises(identity.DetectionError) as caught:
                    identity._fetch_json("ipwho.is", "https://ipwho.is/", threading.Event())
                self.assertNotIn("8.8.8.8", str(caught.exception))

    def test_cancellation_terminates_only_own_request(self):
        event = threading.Event()
        created = []

        def start(args, **kwargs):
            process = FakeProcess(args, cancel=event)
            created.append(process)
            return process

        with patch.object(identity, "_curl_path", return_value="curl.exe"), patch.object(identity.subprocess, "Popen", side_effect=start):
            with self.assertRaises(identity.DetectionCancelled):
                identity._fetch_json("ipwho.is", "https://ipwho.is/", event)
        self.assertTrue(created[0].killed)

    def test_large_body_is_rejected(self):
        with patch.object(identity, "_curl_path", return_value="curl.exe"), patch.object(identity.subprocess, "Popen", side_effect=lambda args, **kwargs: FakeProcess(args, payload={"padding": "x" * 20000})):
            with self.assertRaises(identity.DetectionError):
                identity._fetch_json("ipwho.is", "https://ipwho.is/", threading.Event())


if __name__ == "__main__":
    unittest.main()
