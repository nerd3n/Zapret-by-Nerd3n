import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock

from zapret_ui.server import LocalServer


class ServerBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temporary.name)
        cls.webroot = cls.base / "web"
        cls.webroot.mkdir()
        (cls.webroot / "index.html").write_text("<html>fixture</html>", encoding="utf-8")
        (cls.base / "reports").mkdir()
        cls.controller = Mock()
        cls.controller.data = cls.base
        cls.controller.state.return_value = {"job": {"running": False}}
        cls.server = LocalServer(("127.0.0.1", 0), cls.controller, cls.webroot)
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(2)
        cls.temporary.cleanup()

    def setUp(self):
        self.controller.reset_mock()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def mutation_headers(self):
        return {"Content-Type": "application/json", "X-Zapret-Token": self.server.token,
                "Origin": f"http://127.0.0.1:{self.server.server_port}", "Sec-Fetch-Site": "same-origin"}

    def test_session_available_only_with_expected_host(self):
        status, _, body = self.request("GET", "/api/session")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["token"], self.server.token)
        status, _, body = self.request("GET", "/api/session", headers={"Host": "rebinding.example"})
        self.assertEqual(status, 403)
        self.assertNotIn(self.server.token.encode(), body)

    def test_cross_origin_requests_rejected_even_with_token(self):
        headers = self.mutation_headers()
        headers["Origin"] = "https://evil.example"
        self.assertEqual(self.request("POST", "/api/start", "{}", headers)[0], 403)
        headers = self.mutation_headers()
        headers["Sec-Fetch-Site"] = "cross-site"
        self.assertEqual(self.request("POST", "/api/start", "{}", headers)[0], 403)
        self.controller.start.assert_not_called()

    def test_token_required_for_mutation(self):
        headers = self.mutation_headers()
        del headers["X-Zapret-Token"]
        self.assertEqual(self.request("POST", "/api/stop", "{}", headers)[0], 403)
        self.controller.stop.assert_not_called()

    def test_json_body_type_size_and_syntax_enforced(self):
        headers = self.mutation_headers()
        self.assertEqual(self.request("POST", "/api/stop", "[]", headers)[0], 400)
        self.assertEqual(self.request("POST", "/api/stop", "{", headers)[0], 400)
        self.assertEqual(self.request("POST", "/api/stop", " " * 32769, headers)[0], 413)
        headers["Content-Type"] = "text/plain"
        self.assertEqual(self.request("POST", "/api/stop", "{}", headers)[0], 415)
        self.controller.stop.assert_not_called()

    def test_authorized_baseline_does_not_pass_candidate_ids(self):
        self.assertEqual(self.request("POST", "/api/baseline", '{"repeats":1,"strategyIds":["ignored"]}', self.mutation_headers())[0], 200)
        self.controller.begin_test.assert_called_once_with([], 1, baseline_only=True)

    def test_file_traversal_and_unlisted_static_paths_rejected(self):
        for path in ("/../secret", "/data/settings.json", "/%2e%2e/server.py"):
            self.assertEqual(self.request("GET", path)[0], 404)
        for name in ("../settings.json", "..%2Fsettings.json", "%2e%2e%5Csettings.json", "settings.json:other"):
            self.assertEqual(self.request("GET", "/api/report?name=" + name)[0], 400)

    def test_service_actions_require_session_and_forward_only_action_and_id(self):
        for action in ("install", "start", "stop", "remove"):
            path = "/api/service/" + action
            self.assertEqual(self.request("POST", path, "{}", {"Content-Type": "application/json"})[0], 403)
            self.controller.service_action.assert_not_called()
            body = '{"strategyId":"known", "command":"ignored.exe"}'
            self.assertEqual(self.request("POST", path, body, self.mutation_headers())[0], 200)
            self.controller.service_action.assert_called_once_with(action, "known")
            self.controller.reset_mock()

    def test_static_page_has_browser_security_headers(self):
        status, headers, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"<html>fixture</html>")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])


if __name__ == "__main__":
    unittest.main()
