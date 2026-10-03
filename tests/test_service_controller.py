import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from zapret_ui import controller


ABSENT = {"supported": True, "installed": False, "owned": False, "running": False,
          "status": "absent", "state": "absent", "pid": None, "error": None}
PRESENT = {**ABSENT, "installed": True, "owned": True, "status": "stopped", "state": "stopped"}
STRATEGY = {"id": "one", "name": "One", "experimental": False, "argv": ["never-run.exe"]}


class ServiceControllerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.service = Mock()
        self.service.status.return_value = copy.deepcopy(ABSENT)
        for patcher in (patch.object(controller, "ServiceManager", return_value=self.service),
                        patch.object(controller, "catalog", return_value=[copy.deepcopy(STRATEGY)]),
                        patch.object(controller, "ProcessJob"),
                        patch.object(controller.Controller, "external_processes", return_value=[]),
                        patch.object(controller, "is_admin", return_value=True),
                        patch.object(controller.subprocess, "Popen", side_effect=AssertionError("No host engine"))):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.app = controller.Controller(self.base)

    def test_new_profile_empty_and_blank_settings_valid(self):
        self.assertEqual(self.app.settings["provider"], "")
        self.assertEqual(self.app.settings["city"], "")
        self.app.save_settings({"provider": "", "city": "", "providerVerified": False})
        self.assertEqual(json.loads((self.base / "data/settings.json").read_text())["provider"], "")
        with self.assertRaisesRegex(ValueError, "укажите провайдера"):
            self.app.save_settings({"providerVerified": True})

    def test_legacy_unconfirmed_infolink_is_cleared_but_custom_profile_preserved(self):
        config = self.base / "data/settings.json"
        for provider, city, verified, expected in (
                ("Инфолинк", "Щёлково", False, ""),
                ("Инфолинк", "Щёлково", True, "Инфолинк"),
                ("My ISP", "My city", False, "My ISP")):
            config.write_text(json.dumps({"provider": provider, "city": city,
                                          "providerVerified": verified}), encoding="utf-8")
            app = controller.Controller(self.base)
            self.assertEqual(app.settings["provider"], expected)
            self.assertFalse(app.settings["providerVerified"])
            self.assertEqual(app.settings["settingsSchema"], 2)

    def test_installed_stopped_service_blocks_session_and_baseline(self):
        self.service.status.return_value = copy.deepcopy(PRESENT)
        with self.assertRaisesRegex(ValueError, "Удалите автозапуск"):
            self.app.start("one")
        with self.assertRaisesRegex(ValueError, "Удалите автозапуск"):
            self.app.begin_test([], baseline_only=True)

    def test_startup_with_service_only_detects_network(self):
        self.service.status.return_value = copy.deepcopy(PRESENT)
        self.app.refresh_service(force=True)
        with patch.object(self.app, "detect_network_async") as detect, patch.object(self.app, "start_auto_setup") as auto:
            self.app.schedule_auto_setup()
        detect.assert_called_once()
        auto.assert_not_called()

    def test_close_never_stops_or_removes_service(self):
        self.service.status.return_value = copy.deepcopy(PRESENT)
        self.app.close()
        self.service.stop.assert_not_called()
        self.service.remove.assert_not_called()

    def test_install_stops_owned_session_then_installs_selected_strategy(self):
        self.app.active_id = "one"
        with patch.object(self.app, "running", return_value=True), patch.object(self.app, "_stop") as stop:
            self.app.service_action("install", "one")
        stop.assert_called_once()
        self.service.install.assert_called_once_with("one")
        self.assertFalse(self.app.service_busy)

    def test_failed_install_restores_session_only_if_no_service_left(self):
        self.service.install.side_effect = controller.ServiceError("fixture failed")
        self.app.active_id = "one"
        with patch.object(self.app, "running", return_value=True), patch.object(self.app, "_stop"), patch.object(self.app, "_start") as start:
            with self.assertRaisesRegex(ValueError, "fixture failed"):
                self.app.service_action("install", "one")
        start.assert_called_once_with("one")
        self.assertFalse(self.app.service_busy)

    def test_failed_install_with_remaining_service_does_not_start_second_engine(self):
        def failed(_):
            self.service.status.return_value = copy.deepcopy(PRESENT)
            raise controller.ServiceError("cleanup pending")
        self.service.install.side_effect = failed
        self.app.active_id = "one"
        with patch.object(self.app, "running", return_value=True), patch.object(self.app, "_stop"), patch.object(self.app, "_start") as start:
            with self.assertRaises(ValueError):
                self.app.service_action("install", "one")
        start.assert_not_called()

    def test_busy_admin_and_foreign_process_guards(self):
        self.app.job["running"] = True
        with self.assertRaises(ValueError):
            self.app.service_action("install", "one")
        self.app.job["running"] = False
        with patch.object(controller, "is_admin", return_value=False):
            with self.assertRaises(ValueError):
                self.app.service_action("install", "one")
        with patch.object(self.app, "external_processes", return_value=[999]):
            with self.assertRaisesRegex(ValueError, "другой winws"):
                self.app.service_action("install", "one")
        self.service.install.assert_not_called()

    def test_foreign_service_and_read_error_fail_closed(self):
        self.service.status.return_value = {**PRESENT, "owned": False}
        with self.assertRaises(ValueError):
            self.app.service_action("remove")
        self.service.remove.assert_not_called()
        self.service.status.side_effect = OSError("SCM unavailable")
        with self.assertRaisesRegex(ValueError, "SCM unavailable"):
            self.app.start("one")

    def test_owned_service_controls_route_to_manager(self):
        self.service.status.return_value = copy.deepcopy(PRESENT)
        for action in ("start", "stop", "remove"):
            self.app.service_action(action)
            getattr(self.service, action).assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
