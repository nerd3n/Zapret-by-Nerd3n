"""Safety and real-format coverage; no test invokes winws or a batch file."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import tempfile
import unittest

from zapret_ui.strategies import StrategyError, catalog, parse_strategy, prepare_bundle


class StrategyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zapret strategy ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "with spaces & кириллица"
        (self.root / "bin").mkdir(parents=True)
        (self.root / "lists").mkdir()
        (self.root / "bin" / "winws.exe").write_bytes(b"MZfixture-only")
        (self.root / "bin" / "quic_initial_steamcommunity_com.bin").write_bytes(b"discord-fake")
        (self.root / "bin" / "quic_initial_4pda_to.bin").write_bytes(b"game-fake")
        (self.root / "lists" / "list-general.txt").write_text("youtube.com\n", encoding="utf-8")
        self.batch = self.root / "general.bat"
        self.write()

    def write(self, extra="", prefix="", suffix=""):
        self.batch.write_text(prefix + '@echo off\ncall service.bat ignored\n'
            'start "zapret: %~n0" /min "%BIN%winws.exe" '
            '--wf-tcp=80,443,%GameFilterTCP% --wf-udp=443,%GameFilterUDP% ^\n'
            '--filter-tcp=443 --hostlist="%LISTS%list-general.txt" '
            '--dpi-desync=fake,multisplit --dpi-desync-split-pos=1 '
            '--dpi-desync-repeats=6 --dpi-desync-fake-tls=^! ' + extra + '\n' + suffix,
            encoding="utf-8")

    def test_spaces_unicode_and_caret_bang_are_data(self):
        args = parse_strategy(self.batch, self.root)
        self.assertEqual(args[0], str(self.root / "bin" / "winws.exe"))
        self.assertIn("--wf-tcp=80,443,12", args)
        self.assertIn("--wf-udp=443,12", args)
        self.assertIn("--dpi-desync-fake-tls=!", args)
        self.assertIn("--hostlist=" + str(self.root / "lists" / "list-general.txt"), args)

    def test_command_and_option_injection_rejected(self):
        for payload in ["& calc.exe", "| powershell", "> out.txt", "^& calc", "--debug=@out.txt",
                        "--daemon", "--wf-tcp=%EVIL%", "--filter-tcp=443 & exit", "--wf-tcp=0",
                        "--filter-udp=65536", "--dpi-desync-repeats=999999", '"unterminated']:
            with self.subTest(payload=payload):
                self.write(payload)
                with self.assertRaises(StrategyError):
                    parse_strategy(self.batch, self.root)

    def test_file_escape_and_absolute_paths_rejected(self):
        for value in ["%LISTS%../secret.txt", "%LISTS%..\\secret.txt", "C:\\secret.txt",
                      "%LISTS%file.txt:stream", "%LISTS%%EVIL%.txt", "%LISTS%missing.txt"]:
            with self.subTest(value=value):
                self.write('--hostlist="' + value + '"')
                with self.assertRaises(StrategyError):
                    parse_strategy(self.batch, self.root)

    def test_engine_numeric_and_single_value_grammar(self):
        for token in ["--dpi-desync-repeats=٦", "--dpi-desync-split-seqovl=٦٨١",
                      "--dpi-desync-badseq-increment=١٠", "--dpi-desync-cutoff=n1٢",
                      "--dpi-desync-split-pos=1٢", "--filter-tcp=4٤٣",
                      "--ip-id=zero,seq", "--ip-id=none", "--dpi-desync-any-protocol=0,1"]:
            with self.subTest(token=token):
                self.write(token)
                with self.assertRaises(StrategyError):
                    parse_strategy(self.batch, self.root)
        self.write("--ip-id=seqgroup --dpi-desync-any-protocol=1 --filter-l3=ipv4,ipv6")
        args = parse_strategy(self.batch, self.root)
        self.assertIn("--ip-id=seqgroup", args)
        self.assertIn("--filter-l3=ipv4,ipv6", args)

    def test_symlink_file_escape_rejected(self):
        outside = Path(self.temp.name) / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        link = self.root / "lists" / "escape.txt"
        try:
            link.symlink_to(outside)
        except OSError:
            self.skipTest("Symlink privilege unavailable")
        self.write('--hostlist="%LISTS%escape.txt"')
        with self.assertRaises(StrategyError):
            parse_strategy(self.batch, self.root)

    def test_preparation_preserves_existing_defaults(self):
        created = prepare_bundle(self.root)
        self.assertEqual(len(created), 5)
        self.assertEqual((self.root / "bin" / "ACTIVE_DISCORD_UDP.bin").read_bytes(), b"discord-fake")
        self.assertEqual((self.root / "bin" / "ACTIVE_GAME_UDP.bin").read_bytes(), b"game-fake")
        self.assertEqual((self.root / "lists" / "ipset-exclude-user.txt").read_bytes(), b"203.0.113.113/32\r\n")
        user = self.root / "lists" / "list-general-user.txt"
        user.write_text("custom.example\n", encoding="utf-8")
        self.assertEqual(prepare_bundle(self.root), [])
        self.assertEqual(user.read_text(encoding="utf-8"), "custom.example\n")

    def test_multiple_start_and_incomplete_continuation_rejected(self):
        for suffix in ['start "other" /min "%BIN%winws.exe" --wf-tcp=443\n', "unused ^"]:
            self.write(suffix=suffix)
            with self.assertRaises(StrategyError):
                parse_strategy(self.batch, self.root)

    def test_missing_file_and_large_script_rejected(self):
        self.write('--dpi-desync-fake-quic="%BIN%missing.bin"')
        with self.assertRaises(StrategyError):
            parse_strategy(self.batch, self.root)
        self.batch.write_bytes(b" " * (256 * 1024 + 1))
        with self.assertRaises(StrategyError):
            parse_strategy(self.batch, self.root)

    def test_experiments_change_only_documented_parameter(self):
        for name in ["general (ALT11).bat", "general (FAKE TLS AUTO).bat"]:
            shutil.copyfile(self.batch, self.root / name)
        auto = self.root / "general (FAKE TLS AUTO).bat"
        auto.write_text(auto.read_text(encoding="utf-8").replace("--dpi-desync-repeats=6", "--dpi-desync-repeats=11"), encoding="utf-8")
        entries = catalog(self.root)
        stocks = {entry["id"]: entry for entry in entries if entry["id"].startswith("stock-")}
        variants = [entry for entry in entries if entry["id"].startswith("experiment-")]
        self.assertEqual(len(variants), 6)
        self.assertEqual(len(set(entry["id"] for entry in entries)), 9)
        for variant in variants:
            self.assertTrue(variant["experimental"])
            original = stocks[variant["base_id"]]["argv"]
            self.assertEqual(len(original), len(variant["argv"]))
            changed = [(a, b) for a, b in zip(original, variant["argv"]) if a != b]
            self.assertTrue(changed)
            prefix = variant["changes"][0]["parameter"] + "="
            self.assertTrue(all(a.startswith(prefix) and b.startswith(prefix) for a, b in changed))


class UpstreamCompatibilityTests(unittest.TestCase):
    def test_all_real_stock_strategies_parse_without_execution(self):
        bundled = Path(__file__).resolve().parents[1] / "bundle"
        fallback = bundled if (bundled / "general.bat").is_file() else Path(__file__).resolve().parents[3] / "work" / "upstream"
        root = Path(os.environ.get("ZAPRET_TEST_BUNDLE", fallback))
        if not (root / "general.bat").is_file():
            self.skipTest("Set ZAPRET_TEST_BUNDLE to run against an upstream bundle")
        with tempfile.TemporaryDirectory(prefix="zapret real bundle ") as temp:
            copied = Path(temp) / "bundle"
            shutil.copytree(root, copied, ignore=shutil.ignore_patterns(".git"))
            entries = catalog(copied)
            stocks = [entry for entry in entries if entry["id"].startswith("stock-")]
            self.assertEqual(len(stocks), len(list(copied.glob("general*.bat"))))
            self.assertEqual(len(entries) - len(stocks), 6)
            self.assertEqual(len(stocks), 22)
            tls_auto = next(entry for entry in stocks if entry["name"] == "FAKE TLS AUTO")
            self.assertIn("--dpi-desync-fake-tls=!", tls_auto["argv"])
            self.assertTrue(all(arg != "cmd.exe" for entry in entries for arg in entry["argv"]))


if __name__ == "__main__":
    unittest.main()
