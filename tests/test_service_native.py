"""Native-adapter contracts with fake Win32/registry functions only.

No WindowsAdapter constructor, real registry handle, SCM handle or service
mutation is used by these tests.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import hashlib
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from zapret_ui import windows_service as service


class ReadonlyRegistry:
    HKEY_LOCAL_MACHINE = 123
    KEY_READ = 0x20019
    KEY_WOW64_64KEY = 0x100
    REG_SZ = 1
    REG_EXPAND_SZ = 2
    REG_DWORD = 4

    def __init__(self, values):
        self.values = values
        self.opened = []
        self.read = []

    @contextmanager
    def OpenKey(self, hive, path, reserved, access):
        self.opened.append((hive, path, reserved, access))
        if access != self.KEY_READ | self.KEY_WOW64_64KEY:
            raise AssertionError("Registry fallback must use read-only access")
        yield 77

    def QueryValueEx(self, key, name):
        self.read.append(name)
        if name not in self.values:
            raise FileNotFoundError(name)
        return self.values[name]


class QueryConfigTests(unittest.TestCase):
    def setUp(self):
        self.adapter = service.WindowsAdapter.__new__(service.WindowsAdapter)
        self.query = Mock()
        self.adapter.advapi = SimpleNamespace(QueryServiceConfigW=self.query)
        self.adapter._metadata = Mock(return_value={"owner": service.OWNER, "schema": 1})
        self.fallback = {"imagePath": "old long command", "configSource": "registry"}
        self.adapter._registry_config = Mock(return_value=self.fallback)
        self.adapter._error = Mock(side_effect=lambda message: service.ServiceError(message))

    def failed_call(self, *, error, needed):
        def query(handle, buffer, size, needed_pointer):
            ctypes.cast(needed_pointer, ctypes.POINTER(ctypes.wintypes.DWORD)).contents.value = needed
            return False
        self.query.side_effect = query
        return patch.object(service.ctypes, "get_last_error", return_value=error, create=True)

    def test_native_success_uses_one_bounded_buffer_and_no_registry_fallback(self):
        # Keep the pointed-to strings alive until _query_config has read them.
        config = service._Config()
        config.serviceType = 16
        config.startType = 2
        config.binaryPath = '"C:\\Program Files\\service\\winws.exe" --filter-tcp=443'
        config.account = "LocalSystem"

        def query(handle, buffer, size, needed_pointer):
            self.assertEqual(handle, 456)
            self.assertEqual(size, 8192)
            self.assertEqual(len(buffer), 8192)
            ctypes.memmove(buffer, ctypes.byref(config), ctypes.sizeof(config))
            return True

        self.query.side_effect = query
        result = self.adapter._query_config(456)
        self.assertEqual(result["imagePath"], config.binaryPath)
        self.assertEqual(result["serviceType"], 16)
        self.assertEqual(result["startType"], "automatic")
        self.assertEqual(result["account"], "LocalSystem")
        self.query.assert_called_once()
        self.adapter._metadata.assert_called_once_with()
        self.adapter._registry_config.assert_not_called()

    def test_known_rpc_overflow_errors_use_protected_registry_fallback(self):
        for error in (1734, 1783):
            with self.subTest(error=error):
                self.query.reset_mock()
                self.adapter._registry_config.reset_mock()
                with self.failed_call(error=error, needed=0):
                    self.assertEqual(self.adapter._query_config(456), self.fallback)
                self.query.assert_called_once()
                self.assertEqual(self.query.call_args.args[2], 8192)
                self.adapter._registry_config.assert_called_once_with()

    def test_insufficient_buffer_over_8k_uses_fallback_without_larger_allocation(self):
        with self.failed_call(error=122, needed=65536):
            self.assertEqual(self.adapter._query_config(456), self.fallback)
        self.query.assert_called_once()
        self.assertEqual(len(self.query.call_args.args[1]), 8192)
        self.adapter._registry_config.assert_called_once_with()

    def test_unrelated_errors_never_fall_back_to_registry(self):
        cases = ((5, 9000), (87, 9000), (1060, 9000), (122, 0), (122, 8192), (0, 9000))
        for error, needed in cases:
            with self.subTest(error=error, needed=needed):
                self.query.reset_mock()
                self.adapter._registry_config.reset_mock()
                with self.failed_call(error=error, needed=needed):
                    with self.assertRaises(service.ServiceError):
                        self.adapter._query_config(456)
                self.query.assert_called_once()
                self.adapter._registry_config.assert_not_called()

    def test_failed_ownership_validation_is_not_hidden_by_query_fallback(self):
        self.adapter._registry_config.side_effect = service.ServiceError("unprotected registry key")
        with self.failed_call(error=1783, needed=16384):
            with self.assertRaisesRegex(service.ServiceError, "unprotected"):
                self.adapter._query_config(456)

    def test_query_always_closes_its_service_handle_after_config_failure(self):
        @contextmanager
        def scm():
            yield 321

        self.adapter._scm = scm
        self.adapter.advapi.OpenServiceW = Mock(return_value=456)
        self.adapter.advapi.QueryServiceStatusEx = Mock(return_value=True)
        self.adapter.advapi.CloseServiceHandle = Mock(return_value=True)
        self.adapter._query_config = Mock(side_effect=service.ServiceError("bad configuration"))
        with self.assertRaisesRegex(service.ServiceError, "bad configuration"):
            self.adapter.query()
        self.adapter.advapi.CloseServiceHandle.assert_called_once_with(456)
        self.adapter.advapi.OpenServiceW.assert_called_once_with(321, service.SERVICE_NAME, 0x5)


class RegistryFallbackTests(unittest.TestCase):
    def setUp(self):
        self.adapter = service.WindowsAdapter.__new__(service.WindowsAdapter)
        self.adapter.key_path = r"SYSTEM\CurrentControlSet\Services\fixture-only"
        self.command = '"C:\\Program Files\\protected snapshot\\winws.exe" ' + "--filter-tcp=443 " * 600
        self.metadata = {"owner": service.OWNER, "schema": 1,
                         "imageSha256": hashlib.sha256(self.command.encode("utf-8")).hexdigest()}
        self.values = {"ImagePath": (self.command, ReadonlyRegistry.REG_EXPAND_SZ),
                       "Type": (16, ReadonlyRegistry.REG_DWORD),
                       "Start": (2, ReadonlyRegistry.REG_DWORD),
                       "ObjectName": ("LocalSystem", ReadonlyRegistry.REG_SZ),
                       service.REGISTRY_VALUE: (json.dumps(self.metadata), ReadonlyRegistry.REG_SZ)}
        self.adapter.reg = ReadonlyRegistry(self.values)
        self.adapter._check_descriptor = Mock()

        def get_security(key, flags, buffer, size_pointer):
            ctypes.cast(size_pointer, ctypes.POINTER(ctypes.wintypes.DWORD)).contents.value = 64
            return 122 if buffer is None else 0

        self.adapter.advapi = SimpleNamespace(RegGetKeySecurity=Mock(side_effect=get_security))

    def set_metadata(self, value):
        self.values[service.REGISTRY_VALUE] = (json.dumps(value), ReadonlyRegistry.REG_SZ)

    def test_oversized_legacy_imagepath_is_read_only_and_keeps_ownership_marker(self):
        self.assertGreater(len(self.command.encode("utf-16-le")), 8192)
        result = self.adapter._registry_config()
        self.assertEqual(result["imagePath"], self.command)
        self.assertEqual(result["metadata"], self.metadata)
        self.assertEqual(result["configSource"], "registry")
        self.assertEqual(result["startType"], "automatic")
        self.adapter._check_descriptor.assert_called_once()
        self.assertTrue(self.adapter._check_descriptor.call_args.kwargs["registry"])
        self.assertEqual(len(self.adapter.reg.opened), 2)

    def test_unsafe_registry_acl_blocks_values_before_ownership_is_trusted(self):
        self.adapter._check_descriptor.side_effect = service.ServiceError("unsafe ACL")
        with self.assertRaises(service.ServiceError):
            self.adapter._registry_config()
        self.assertNotIn("ImagePath", self.adapter.reg.read)
        self.assertEqual(self.adapter.reg.read, [])

    def test_missing_foreign_or_unsupported_metadata_blocks_fallback(self):
        for metadata in (None, {}, {"owner": "other", "schema": 1},
                         {"owner": service.OWNER, "schema": 2},
                         {"owner": service.OWNER, "schema": 99}):
            with self.subTest(metadata=metadata):
                self.set_metadata(metadata)
                self.adapter.reg.read.clear()
                with self.assertRaises(service.ServiceError):
                    self.adapter._registry_config()
                self.assertNotIn("ImagePath", self.adapter.reg.read)

    def test_invalid_registry_value_types_are_rejected(self):
        for name, kind in (("ImagePath", ReadonlyRegistry.REG_DWORD),
                           ("Type", ReadonlyRegistry.REG_SZ), ("Start", ReadonlyRegistry.REG_SZ),
                           ("ObjectName", ReadonlyRegistry.REG_EXPAND_SZ)):
            with self.subTest(name=name):
                original = self.values[name]
                self.values[name] = (original[0], kind)
                with self.assertRaises(service.ServiceError):
                    self.adapter._registry_config()
                self.values[name] = original

    def test_mismatched_hash_or_unsafe_service_parameters_are_rejected(self):
        cases = (("ImagePath", self.command + " --debug"), ("ImagePath", ""),
                 ("ImagePath", "bad\0command"), ("ImagePath", "x" * 32768),
                 ("Type", 32), ("Start", 0), ("ObjectName", "OtherUser"))
        for name, value in cases:
            with self.subTest(name=name, value=str(value)[:40]):
                original = self.values[name]
                self.values[name] = (value, original[1])
                with self.assertRaises(service.ServiceError):
                    self.adapter._registry_config()
                self.values[name] = original

    def test_wrong_metadata_registry_type_is_not_accepted(self):
        self.values[service.REGISTRY_VALUE] = (json.dumps(self.metadata), ReadonlyRegistry.REG_EXPAND_SZ)
        with self.assertRaises(service.ServiceError):
            self.adapter._registry_config()
        self.assertNotIn("ImagePath", self.adapter.reg.read)

    def test_command_limit_is_65532_utf16_bytes_including_non_bmp_characters(self):
        for command, accepted in (("x" * 32766, True), ("x" * 32767, False),
                                  ("\U0001f642" * 16383, True), ("\U0001f642" * 16384, False)):
            with self.subTest(size=len(command.encode("utf-16-le"))):
                self.values["ImagePath"] = (command, ReadonlyRegistry.REG_SZ)
                metadata = {**self.metadata, "imageSha256": hashlib.sha256(command.encode("utf-8")).hexdigest()}
                self.set_metadata(metadata)
                if accepted:
                    self.assertEqual(self.adapter._registry_config()["imagePath"], command)
                else:
                    with self.assertRaises(service.ServiceError):
                        self.adapter._registry_config()

    def test_percent_expansion_is_rejected_even_with_a_matching_marker(self):
        command = '"%ProgramFiles%\\fixture\\winws.exe" --filter-tcp=443'
        self.values["ImagePath"] = (command, ReadonlyRegistry.REG_EXPAND_SZ)
        self.set_metadata({**self.metadata, "imageSha256": hashlib.sha256(command.encode("utf-8")).hexdigest()})
        with self.assertRaises(service.ServiceError):
            self.adapter._registry_config()

    def test_non_object_metadata_is_a_controlled_error(self):
        for metadata in (True, 1, "owner", [self.metadata]):
            with self.subTest(metadata=metadata):
                self.set_metadata(metadata)
                with self.assertRaises(service.ServiceError):
                    self.adapter._registry_config()


if __name__ == "__main__":
    unittest.main()
