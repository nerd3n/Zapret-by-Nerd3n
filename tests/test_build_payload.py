"""Release payload tests never execute an engine or depend on Git metadata."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from tools import build_payload as builder


SOURCE = Path(__file__).resolve().parents[1]


class BuildPayloadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="payload-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "source without git"
        self.root.mkdir()
        self.pairs = builder.load_file_list(SOURCE)
        for relative in [builder.FILE_LIST, *(source for source, _ in self.pairs)]:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE / relative, destination)
        self.output = Path(self.temporary.name) / "output" / "payload.zip"

    def build(self):
        return builder.build_payload(self.root, self.output)

    def append_mapping(self, line):
        with (self.root / builder.FILE_LIST).open("a", encoding="utf-8") as stream:
            stream.write("\n" + line + "\n")

    def test_clean_archive_matches_manifest_without_git(self):
        self.assertFalse((self.root / ".git").exists())
        result = self.build()
        expected = {destination for _, destination in self.pairs}
        with zipfile.ZipFile(self.output) as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(set(archive.namelist()), expected | {"manifest.json"})
            manifest_bytes = archive.read("manifest.json")
            self.assertNotIn(str(self.root).encode(), manifest_bytes)
            manifest = json.loads(manifest_bytes)
            self.assertEqual(set(manifest), {"schema", "files"})
            self.assertEqual(manifest["schema"], 1)
            self.assertEqual([row["path"] for row in manifest["files"]], sorted(expected))
            for row in manifest["files"]:
                self.assertEqual(set(row), {"path", "sha256", "size"})
                content = archive.read(row["path"])
                self.assertEqual(row["sha256"], hashlib.sha256(content).hexdigest())
                self.assertEqual(row["size"], len(content))
                info = archive.getinfo(row["path"])
                self.assertTrue(stat.S_ISREG(info.external_attr >> 16))
                self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0))
            for license_name in builder.LICENSE_FILES:
                self.assertEqual(archive.read(f"licenses/{license_name}"), (self.root / license_name).read_bytes())
                self.assertNotIn(license_name, archive.namelist())
        self.assertEqual(result["files"], len(expected))
        self.assertEqual(result["sha256"], hashlib.sha256(self.output.read_bytes()).hexdigest())

    def test_unlisted_user_files_and_extra_binaries_are_ignored(self):
        extras = ["bundle/lists/list-general-user.txt", "bundle/utils/logs/private.log",
                  "bundle/utils/test results/result.txt", "bundle/bin/extra.exe",
                  "profiles/private.json", "data/settings.json", ".env"]
        for relative in extras:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("DO-NOT-PACK-PRIVATE-CONTENT", encoding="utf-8")
        self.build()
        with zipfile.ZipFile(self.output) as archive:
            self.assertFalse(set(extras) & set(archive.namelist()))
        self.assertNotIn(b"DO-NOT-PACK-PRIVATE-CONTENT", self.output.read_bytes())

    def test_deterministic_despite_source_timestamps_and_list_order(self):
        self.build()
        initial = self.output.read_bytes()
        for source, _ in self.pairs:
            os.utime(self.root / source, (1_000_000_000, 1_000_000_000))
        file_list = self.root / builder.FILE_LIST
        file_list.write_text("\n".join(reversed(file_list.read_text(encoding="utf-8").splitlines())), encoding="utf-8")
        self.build()
        self.assertEqual(self.output.read_bytes(), initial)

    def test_each_native_hash_is_pinned_and_failure_preserves_previous_output(self):
        self.output.parent.mkdir()
        self.output.write_bytes(b"previous-good-output")
        for name in builder.NATIVE_HASHES:
            with self.subTest(name=name):
                path = self.root / "bundle" / "bin" / name
                original = path.read_bytes()
                path.write_bytes(original + b"tampered")
                try:
                    with self.assertRaisesRegex(builder.PayloadError, "hash mismatch"):
                        self.build()
                    self.assertEqual(self.output.read_bytes(), b"previous-good-output")
                finally:
                    path.write_bytes(original)

    def test_active_udp_seeds_must_equal_the_canonical_sources(self):
        for active in builder.ACTIVE_DEFAULTS:
            with self.subTest(active=active):
                path = self.root / active
                original = path.read_bytes()
                path.write_bytes(b"local custom UDP seed")
                try:
                    with self.assertRaisesRegex(builder.PayloadError, "canonical default"):
                        self.build()
                finally:
                    path.write_bytes(original)
        self.assertFalse(self.output.exists())

    def test_missing_input_fails_without_creating_archive(self):
        (self.root / "bundle/lists/list-google.txt").unlink()
        with self.assertRaisesRegex(builder.PayloadError, "Missing input"):
            self.build()
        self.assertFalse(self.output.exists())

    def test_missing_native_list_entry_is_rejected(self):
        path = self.root / builder.FILE_LIST
        path.write_text(path.read_text(encoding="utf-8").replace("bundle/bin/winws.exe\n", ""), encoding="utf-8")
        with self.assertRaisesRegex(builder.PayloadError, "absent from list"):
            self.build()

    def test_unsafe_paths_runtime_files_and_case_aliases_are_rejected(self):
        file_list = self.root / builder.FILE_LIST
        original = file_list.read_text(encoding="utf-8")
        invalid = ["bundle/../secret.txt", "C:/secret.txt", "bundle/CON.txt",
                   "bundle/name:stream.txt", "bundle\\secret.txt", "bundle/name./file.txt",
                   "bundle/lists/private-user.txt", "bundle/logs/secret.txt",
                   "bundle/utils/game_filter.enabled", "bundle/bin/WINWS.exe",
                   "LICENSE => bundle/renamed.txt", "licenses/unknown.txt"]
        for line in invalid:
            with self.subTest(line=line):
                file_list.write_text(original + "\n" + line + "\n", encoding="utf-8")
                with self.assertRaises(builder.PayloadError):
                    self.build()
        self.assertFalse(self.output.exists())

    def test_input_size_and_total_size_limits(self):
        with patch.object(builder, "MAX_FILE_SIZE", 1024):
            with self.assertRaisesRegex(builder.PayloadError, "size limit"):
                self.build()
        with patch.object(builder, "MAX_TOTAL_SIZE", 1024):
            with self.assertRaisesRegex(builder.PayloadError, "total size limit"):
                self.build()

    def test_output_cannot_replace_an_input(self):
        source = self.root / "bundle/general.bat"
        original = source.read_bytes()
        with self.assertRaisesRegex(builder.PayloadError, "overwrite"):
            builder.build_payload(self.root, source)
        self.assertEqual(source.read_bytes(), original)

    def test_linked_input_is_rejected(self):
        source = self.root / "bundle/README.md"
        target = self.root / "original-readme.txt"
        source.rename(target)
        try:
            source.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"Symlink creation unavailable: {exc}")
        with self.assertRaisesRegex(builder.PayloadError, "reparse points"):
            self.build()

    def test_hard_linked_input_is_rejected(self):
        source = self.root / "bundle/README.md"
        os.link(source, self.root / "alias-readme.txt")
        with self.assertRaisesRegex(builder.PayloadError, "hard links"):
            self.build()


if __name__ == "__main__":
    unittest.main()
