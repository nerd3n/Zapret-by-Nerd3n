"""Complete Standard evidence is required; no test sends any network traffic."""
import copy
from types import SimpleNamespace
import unittest

from zapret_ui.probes import TARGETS
from zapret_ui.recommendation import SCOPE, recommend


def measurement(identifier, passing=None, latency=100, experimental=False, repeats=2, targets=TARGETS):
    checks = []
    for attempt in range(1, repeats + 1):
        for target in targets:
            ok = True if passing is None else target.service in passing
            checks.append({"url": target.url, "target": target.name, "service": target.service,
                           "mode": target.mode, "attempt": attempt, "ok": ok,
                           "status": "OK" if ok else "ERROR",
                           "error": None if ok else "Connection timeout",
                           "timeMs": latency, "httpStatus": None if target.mode == "PING" else 200 if ok else 0,
                           "scope": SCOPE, "suiteId": SCOPE})
    return {"strategyId": identifier, "name": identifier, "checks": checks, "suiteId": SCOPE,
            "experimental": experimental, "error": None, "cancelled": False}


def fail_where(result, predicate, status="ERROR", message="Connection timeout"):
    for check in result["checks"]:
        if predicate(check):
            check.update(ok=False, status=status, error=message, httpStatus=0)


class RecommendationTests(unittest.TestCase):
    def baseline(self):
        return measurement("baseline", passing=set())

    def test_default_matrix_matches_flowseal_standard_all(self):
        self.assertEqual(len(TARGETS), 53)
        self.assertEqual(sum(target.mode == "PING" for target in TARGETS), 17)
        self.assertEqual(sum(target.mode != "PING" for target in TARGETS), 36)
        self.assertTrue(any(target.url == "PING:9.9.9.9" for target in TARGETS))
        result = recommend([measurement("candidate")], baseline=self.baseline())
        best = result["ranking"][0]
        self.assertEqual((best["passed"], best["total"]), (72, 72))
        self.assertEqual((best["pingPassed"], best["pingTotal"], best["checksTotal"]), (34, 34, 106))
        self.assertEqual(result["suiteId"], SCOPE)

    def test_perfect_baseline_only_confirms_standard_addresses(self):
        result = recommend([measurement("baseline"), measurement("candidate", latency=1)])
        self.assertTrue(result["baselineReachable"])
        self.assertFalse(result["bypassNotNeeded"])
        self.assertIsNone(result["recommendedId"])
        self.assertEqual(result["status"], "baseline_reachable")
        self.assertEqual(result["reason"], "Адреса Standard отвечают без zapret; работа видео и голоса не проверена. Улучшение не подтверждено.")

    def test_ping_failures_do_not_make_a_reachable_baseline_need_bypass(self):
        baseline = measurement("baseline")
        fail_where(baseline, lambda check: check["mode"] == "PING")
        result = recommend([measurement("candidate")], baseline=baseline)
        self.assertEqual(result["status"], "baseline_reachable")
        self.assertTrue(result["baselineReachable"])
        self.assertFalse(result["bypassNotNeeded"])
        self.assertIsNone(result["recommendedId"])

    def test_complete_http_candidate_improving_baseline_is_recommended(self):
        candidate = measurement("candidate")
        fail_where(candidate, lambda check: check["mode"] == "PING")
        result = recommend([candidate], baseline=self.baseline())
        self.assertEqual(result["recommendedId"], "candidate")
        self.assertIn("голоса не проверена", result["reason"])
        self.assertFalse(result["bypassNotNeeded"])
        self.assertFalse(result["baselineReachable"])

    def test_incomplete_missing_or_duplicate_baseline_blocks_auto_recommendation(self):
        baseline = measurement("baseline")
        baseline["checks"].pop()
        for value in (baseline, None):
            with self.subTest(baseline=value is None):
                result = recommend([measurement("candidate")], baseline=value)
                self.assertEqual(result["status"], "baseline_incomplete")
                self.assertIsNone(result["recommendedId"])
        result = recommend([self.baseline(), self.baseline(), measurement("candidate")])
        self.assertEqual(result["status"], "baseline_incomplete")

    def test_five_legacy_https_results_cannot_be_eligible(self):
        legacy = {"strategyId": "legacy", "checks": [
            {"url": url, "target": "old endpoint", "service": service, "attempt": 1,
             "ok": True, "error": None, "timeMs": 1, "scope": "HTTPS/TCP"}
            for url, service in (("https://www.youtube.com/", "YouTube"),
                                 ("https://i.ytimg.com/vi/id/hqdefault.jpg", "YouTube"),
                                 ("https://www.youtube.com/oembed", "YouTube"),
                                 ("https://discord.com/", "Discord"),
                                 ("https://discord.com/api/v10/gateway", "Discord"))]}
        result = recommend([legacy], baseline=self.baseline())
        self.assertEqual(result["ranking"], [])
        self.assertIsNone(result["recommendedId"])
        # Repeating legacy rows to reach the expected count still proves nothing.
        legacy["checks"] = (legacy["checks"] * 22)[:2 * len(TARGETS)]
        result = recommend([legacy], baseline=self.baseline())
        self.assertEqual(result["ranking"], [])

    def test_incomplete_cancelled_failed_and_dead_engine_candidates_are_ineligible(self):
        results = []
        for reason in ("incomplete", "cancelled", "startup", "duplicate row", "dead engine", "cancelled row"):
            item = measurement(reason)
            if reason == "incomplete":
                item["checks"].pop()
            elif reason == "cancelled":
                item["cancelled"] = True
            elif reason == "startup":
                item["error"] = "startup failed"
            elif reason == "duplicate row":
                item["checks"][0] = copy.deepcopy(item["checks"][1])
            elif reason == "dead engine":
                fail_where(item, lambda check: True, message="winws завершился во время проверки")
            else:
                item["checks"][0].update(ok=False, status="CANCELLED", error="Отменено")
            results.append(item)
        result = recommend(results, baseline=self.baseline())
        self.assertEqual(result["ranking"], [])
        self.assertIsNone(result["recommendedId"])

    def test_mode_endpoint_service_name_and_attempt_must_match(self):
        mutations = ({"mode": "TLS9"}, {"url": "https://unmeasured.example"},
                     {"service": "unmeasured"}, {"target": "other endpoint"},
                     {"attempt": 3}, {"attempt": True}, {"mode": "PING"})
        for change in mutations:
            item = measurement("invalid")
            item["checks"][0].update(change)
            with self.subTest(change=change):
                result = recommend([item], baseline=self.baseline())
                self.assertEqual(result["ranking"], [])

    def test_duplicating_tls12_cannot_replace_tls13(self):
        item = measurement("missing-tls13")
        for check in item["checks"]:
            if check["mode"] == "TLS1.3":
                check["mode"] = "TLS1.2"
        result = recommend([item], baseline=self.baseline())
        self.assertEqual(result["ranking"], [])

    def test_googlevideo_and_gateway_failures_prevent_full_pass(self):
        for host in ("redirector.googlevideo.com", "gateway.discord.gg"):
            item = measurement(host)
            fail_where(item, lambda check: host in check["url"] and check["mode"] != "PING")
            with self.subTest(host=host):
                result = recommend([item], baseline=self.baseline())
                best = result["ranking"][0]
                self.assertEqual(result["status"], "partial")
                self.assertEqual(result["bestCandidateId"], host)
                self.assertIsNone(result["recommendedId"])
                self.assertLess(best["successRate"], 1)
                self.assertEqual(best["total"] - best["passed"], 6)

    def test_ping_success_cannot_turn_failed_http_into_a_passing_score(self):
        item = measurement("ping-only")
        fail_where(item, lambda check: check["mode"] != "PING")
        result = recommend([item], baseline=self.baseline())
        best = result["ranking"][0]
        self.assertEqual(best["passed"], 0)
        self.assertEqual(best["successRate"], 0)
        self.assertEqual(best["pingPassed"], best["pingTotal"])
        self.assertEqual(result["status"], "partial")
        self.assertIsNone(result["recommendedId"])

    def test_unsupported_tls_is_counted_separately_and_never_passes(self):
        item = measurement("unsupported")
        fail_where(item, lambda check: check["mode"] == "TLS1.3", status="UNSUP", message="TLS 1.3 is not supported")
        result = recommend([item], baseline=self.baseline())
        best = result["ranking"][0]
        self.assertEqual(best["unsupported"], 24)
        self.assertEqual(best["httpErrors"], 0)
        self.assertEqual(best["passed"], 48)
        self.assertEqual(best["total"], 72)
        self.assertAlmostEqual(best["successRate"], 2 / 3)
        self.assertIsNone(result["recommendedId"])
        item["strategyId"] = "baseline"
        next(check for check in item["checks"] if check["mode"] == "TLS1.3").update(status="ERROR", error="TLS failed")
        baseline_result = recommend([], baseline=item)
        self.assertFalse(baseline_result["baselineReachable"])

    def test_uniform_tls13_unsupported_in_both_runs_allows_supported_improvement(self):
        baseline, candidate = self.baseline(), measurement("candidate")
        for item in (baseline, candidate):
            fail_where(item, lambda check: check["mode"] == "TLS1.3", status="UNSUP", message="TLS1.3 unsupported by curl")
        result = recommend([candidate], baseline=baseline)
        best = result["ranking"][0]
        self.assertEqual(result["recommendedId"], "candidate")
        self.assertEqual(best["excludedUnsupportedModes"], ["TLS1.3"])
        self.assertEqual((best["supportedPassed"], best["supportedTotal"]), (48, 48))
        self.assertEqual((best["passed"], best["total"], best["unsupported"]), (48, 72, 24))
        self.assertAlmostEqual(best["successRate"], 2 / 3)
        self.assertIn("48 из 72", result["reason"])
        self.assertIn("UNSUP", result["reason"])

    def test_uniform_unsupported_baseline_is_reachable_only_with_explicit_caveat(self):
        baseline = measurement("baseline", repeats=1)
        fail_where(baseline, lambda check: check["mode"] == "TLS1.3", status="UNSUP", message="TLS1.3 unsupported by curl")
        result = recommend([], baseline=baseline, expected_checks=len(TARGETS))
        self.assertEqual(result["status"], "baseline_reachable")
        self.assertTrue(result["baselineReachable"])
        self.assertFalse(result["bypassNotNeeded"])
        self.assertIsNone(result["recommendedId"])
        self.assertIn("12 проверок не выполнены", result["reason"])
        self.assertIn("24 из 36", result["reason"])

    def test_unsupported_exception_requires_every_host_and_attempt_in_both_runs(self):
        for change in ("candidate partial", "baseline partial", "candidate no unsupported", "different modes"):
            baseline, candidate = self.baseline(), measurement("candidate")
            for item in (baseline, candidate):
                fail_where(item, lambda check: check["mode"] == "TLS1.3", status="UNSUP", message="TLS1.3 unsupported")
            if change == "candidate partial":
                next(check for check in candidate["checks"] if check["mode"] == "TLS1.3").update(status="ERROR", error="curl 35")
            elif change == "baseline partial":
                next(check for check in baseline["checks"] if check["mode"] == "TLS1.3").update(status="ERROR", error="curl 35")
            elif change == "candidate no unsupported":
                candidate = measurement("candidate")
            else:
                for check in candidate["checks"]:
                    if check["mode"] == "TLS1.3":
                        check.update(status="OK", ok=True, error=None)
                fail_where(candidate, lambda check: check["mode"] == "TLS1.2", status="UNSUP", message="TLS1.2 unsupported")
            with self.subTest(change=change):
                result = recommend([candidate], baseline=baseline)
                self.assertIsNone(result["recommendedId"])
                self.assertFalse(result["baselineReachable"])

    def test_http_tls12_and_generic_tls35_errors_cannot_be_excluded(self):
        for mode, status in (("HTTP", "UNSUP"), ("TLS1.2", "UNSUP"), ("TLS1.3", "ERROR"), ("TLS1.3", "SSL")):
            baseline, candidate = self.baseline(), measurement("candidate")
            for item in (baseline, candidate):
                fail_where(item, lambda check: check["mode"] == mode, status=status, message="curl 35 Schannel handshake failed")
            with self.subTest(mode=mode, status=status):
                result = recommend([candidate], baseline=baseline)
                self.assertEqual(result["excludedUnsupportedModes"], [])
                self.assertIsNone(result["recommendedId"])

    def test_uniform_unsupported_does_not_excuse_a_failed_gateway(self):
        baseline, candidate = self.baseline(), measurement("candidate")
        for item in (baseline, candidate):
            fail_where(item, lambda check: check["mode"] == "TLS1.3", status="UNSUP", message="TLS1.3 unsupported")
        fail_where(candidate, lambda check: "gateway.discord.gg" in check["url"] and check["mode"] == "TLS1.2")
        result = recommend([candidate], baseline=baseline)
        self.assertIsNone(result["recommendedId"])
        self.assertLess(result["ranking"][0]["supportedPassed"], result["ranking"][0]["supportedTotal"])

    def test_upstream_http_ok_count_ranks_before_ping_and_latency(self):
        full_http = measurement("all-http", latency=900)
        fail_where(full_http, lambda check: check["mode"] == "PING")
        less_http = measurement("all-ping", latency=1)
        fail_where(less_http, lambda check: check["mode"] == "HTTP" and check["service"] == "Google")
        result = recommend([less_http, full_http], baseline=self.baseline())
        self.assertEqual([item["strategyId"] for item in result["ranking"]], ["all-http", "all-ping"])

    def test_ping_ok_count_breaks_equal_http_scores(self):
        no_ping = measurement("a-no-ping", latency=1)
        fail_where(no_ping, lambda check: check["mode"] == "PING")
        ping = measurement("z-with-ping", latency=900)
        result = recommend([no_ping, ping], baseline=self.baseline())
        self.assertEqual(result["bestCandidateId"], "z-with-ping")

    def test_stable_id_breaks_ties_without_stock_or_latency_preference(self):
        entries = [measurement("z-stock-fast", latency=1),
                   measurement("a-experiment-slow", latency=900, experimental=True),
                   measurement("m-stock-fast", latency=1)]
        for order in (entries, list(reversed(entries))):
            result = recommend(order, baseline=self.baseline())
            self.assertEqual([entry["strategyId"] for entry in result["ranking"]],
                             ["a-experiment-slow", "m-stock-fast", "z-stock-fast"])

    def test_duplicate_strategy_ids_are_ambiguous_and_ineligible(self):
        result = recommend([measurement("same"), measurement("same", passing=set()), measurement("unique")],
                           baseline=self.baseline())
        self.assertEqual([entry["strategyId"] for entry in result["ranking"]], ["unique"])

    def test_old_or_foreign_suite_labels_are_rejected(self):
        for place, field in (("result", "suiteId"), ("result", "scope"), ("check", "suiteId"), ("check", "scope")):
            item = measurement("wrong-suite")
            (item if place == "result" else item["checks"][0])[field] = "legacy-https"
            with self.subTest(place=place, field=field):
                result = recommend([item], baseline=self.baseline())
                self.assertEqual(result["ranking"], [])

    def test_inconsistent_or_malformed_status_never_becomes_success(self):
        for change in ({"status": "UNSUP"}, {"ok": False}, {"status": "UNKNOWN"},
                       {"error": "engine failed"}, {"error": []}, {"ok": 1}, {"status": []}):
            item = measurement("invalid")
            item["checks"][0].update(change)
            with self.subTest(change=change):
                result = recommend([item], baseline=self.baseline())
                self.assertEqual(result["ranking"], [])

    def test_expected_check_count_requires_whole_repeats(self):
        for count in (0, 5, len(TARGETS) - 1, len(TARGETS) + 1, True, 1.5):
            with self.subTest(count=count), self.assertRaises(ValueError):
                recommend([], expected_checks=count)
        result = recommend([measurement("baseline", passing=set(), repeats=1), measurement("candidate", repeats=1)],
                           expected_checks=len(TARGETS))
        self.assertEqual(result["recommendedId"], "candidate")

    def test_dynamic_targets_use_the_selected_matrix_not_default_count(self):
        targets = tuple(SimpleNamespace(name="CustomGoogle", service="Google", url="https://example.org", mode=mode)
                        for mode in ("HTTP", "TLS1.2", "TLS1.3", "PING"))
        targets += (SimpleNamespace(name="CustomDNS", service="DNS", url="PING:192.0.2.1", mode="PING"),)
        baseline = measurement("baseline", passing=set(), targets=targets)
        candidate = measurement("candidate", targets=targets)
        result = recommend([candidate], baseline=baseline, targets=targets)
        self.assertEqual(result["recommendedId"], "candidate")
        self.assertEqual((result["ranking"][0]["total"], result["ranking"][0]["pingTotal"]), (6, 4))
        # The same five targets are insufficient for the default 53-target suite.
        result = recommend([candidate], baseline=baseline)
        self.assertEqual(result["status"], "baseline_incomplete")
        self.assertEqual(result["ranking"], [])

    def test_custom_target_matrix_rejects_duplicate_or_missing_modes(self):
        for targets in ((), TARGETS + TARGETS[:1], tuple(target for target in TARGETS if target.mode != "TLS1.3"),
                        tuple(target for target in TARGETS if target.url.startswith("PING:"))):
            with self.subTest(count=len(targets)), self.assertRaises(ValueError):
                recommend([], targets=targets)

    def test_latency_is_diagnostic_and_ignores_nonfinite_values(self):
        item = measurement("candidate", latency=float("nan"))
        result = recommend([item], baseline=self.baseline())
        self.assertEqual(result["recommendedId"], "candidate")
        self.assertIsNone(result["ranking"][0]["medianMs"])


if __name__ == "__main__":
    unittest.main()
