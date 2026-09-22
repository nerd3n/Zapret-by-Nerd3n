"""Bootstrap belongs only to normal frozen launches, before Controller starts."""
import importlib
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch


class MainPayloadTests(unittest.TestCase):
    def setUp(self):
        self.main = importlib.import_module('main')
        self.controller = Mock(data=Path('fixture-data'))
        self.server = Mock(server_port=17841)

    def test_frozen_launch_extracts_before_constructing_controller(self):
        order = []
        with patch.object(sys, 'frozen', True, create=True), \
                patch.object(sys, '_MEIPASS', str(Path('fixture-resources').resolve()), create=True), \
                patch.object(sys, 'argv', ['app.exe', '--no-browser', '--no-auto-setup']), \
                patch('zapret_ui.bundled_payload.ensure_embedded_payload', side_effect=lambda *args: order.append('payload')) as ensure, \
                patch.object(self.main, 'Controller', side_effect=lambda *args: (order.append('controller'), self.controller)[1]), \
                patch.object(self.main, 'LocalServer', return_value=self.server):
            self.main.main()
            ensure.assert_called_once_with(Path(sys.executable).parent, Path(sys._MEIPASS))
        self.assertEqual(order, ['payload', 'controller'])
        self.controller.close.assert_called_once()

    def test_payload_failure_never_creates_controller_or_opens_server(self):
        with patch.object(sys, 'frozen', True, create=True), \
                patch.object(sys, '_MEIPASS', 'fixture-resources', create=True), \
                patch.object(sys, 'argv', ['app.exe']), \
                patch('zapret_ui.bundled_payload.ensure_embedded_payload', side_effect=RuntimeError('broken payload')), \
                patch.object(self.main, 'Controller') as controller, \
                patch.object(self.main, 'LocalServer') as server, \
                self.assertRaisesRegex(RuntimeError, 'broken payload'):
            self.main.main()
        controller.assert_not_called()
        server.assert_not_called()

    def test_source_launch_does_not_extract(self):
        with patch.object(sys, 'frozen', False, create=True), \
                patch.object(sys, 'argv', ['main.py', '--no-browser', '--no-auto-setup']), \
                patch('zapret_ui.bundled_payload.ensure_embedded_payload') as ensure, \
                patch.object(self.main, 'Controller', return_value=self.controller), \
                patch.object(self.main, 'LocalServer', return_value=self.server):
            self.main.main()
        ensure.assert_not_called()

    def test_maintenance_modes_never_unpack_or_start_controller(self):
        for arguments in (['--remove-service'], ['--prepare-update', 'fixture-installation']):
            with self.subTest(arguments=arguments), \
                    patch.object(sys, 'frozen', True, create=True), \
                    patch.object(sys, 'argv', ['app.exe', *arguments]), \
                    patch('zapret_ui.bundled_payload.ensure_embedded_payload') as ensure, \
                    patch('zapret_ui.update_helper.run_update_helper', return_value=0), \
                    patch.object(self.main, 'remove_owned_service'), \
                    patch.object(self.main, 'Controller') as controller:
                self.main.main()
            ensure.assert_not_called()
            controller.assert_not_called()


if __name__ == '__main__':
    unittest.main()
