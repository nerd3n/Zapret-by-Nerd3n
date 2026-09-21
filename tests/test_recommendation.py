import copy
import unittest

from zapret_ui.probes import TARGETS
from zapret_ui.recommendation import recommend


def measurement(identifier, passing=None, latency=100, experimental=False, repeats=2):
    checks = []
    for attempt in range(1, repeats + 1):
        for target in TARGETS:
            checks.append({"url": target.url, "target": target.name, "service": target.service,
                           "attempt": attempt, "ok": True if passing is None else target.service in passing,
                           "error": None, "timeMs": latency, "scope": "HTTPS/TCP"})
    return {"strategyId": identifier, "name": identifier, "checks": checks,
            "experimental": experimental, "error": None, "cancelled": False}


class RecommendationTests(unittest.TestCase):
    def test_perfect_baseline_never_recommends_unnecessary_bypass(self):
        result = recommend([measurement("baseline"), measurement("candidate", latency=1)])
        self.assertTrue(result["bypassNotNeeded"])
        self.assertIsNone(result["recommendedId"])
        self.assertEqual(result["status"], "bypass_not_needed")

    def test_complete_candidate_improving_both_services_is_recommended(self):
        result = recommend([measurement("baseline", passing={"YouTube"}), measurement("candidate")])
        self.assertEqual(result["recommendedId"], "candidate")
        self.assertIn("голос", result["reason"])

    def test_partial_or_missing_baseline_blocks_automatic_recommendation(self):
        baseline = measurement("baseline")
        baseline["checks"].pop()
        for value in (baseline, None):
            result = recommend([measurement("candidate")], baseline=value)
            self.assertEqual(result["status"], "baseline_incomplete")
            self.assertIsNone(result["recommendedId"])

    def test_incomplete_cancelled_failed_and_dead_engine_candidates_are_ineligible(self):
        bad_results = []
        for reason in ("incomplete", "cancelled", "failed", "duplicate", "wrong service", "dead engine"):
            item = measurement(reason)
            if reason == "incomplete": item["checks"].pop()
            elif reason == "cancelled": item["cancelled"] = True
            elif reason == "failed": item["error"] = "startup failed"
            elif reason == "duplicate": item["checks"][0] = copy.deepcopy(item["checks"][1])
            elif reason == "wrong service": item["checks"][0]["service"] = "Discord"
            else:
                for check in item["checks"]:
                    check.update(ok=False, error="winws завершился во время проверки")
            bad_results.append(item)
        result = recommend(bad_results, baseline=measurement("baseline", passing=set()))
        self.assertEqual(result["ranking"], [])
        self.assertIsNone(result["recommendedId"])

    def test_partial_success_is_diagnostic_only(self):
        result = recommend([measurement("one-service", passing={"YouTube"})], baseline=measurement("baseline", passing=set()))
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["bestCandidateId"], "one-service")
        self.assertIsNone(result["recommendedId"])

    def test_minimum_service_success_ranks_before_total_or_latency(self):
        balanced = measurement("balanced", latency=900)
        balanced["checks"][0]["ok"] = False
        balanced["checks"][3]["ok"] = False
        one_service = measurement("youtube-only", passing={"YouTube"}, latency=1)
        result = recommend([one_service, balanced], baseline=measurement("baseline", passing=set()))
        self.assertEqual(result["bestCandidateId"], "balanced")

    def test_latency_then_stock_priority_break_ties(self):
        entries = [measurement("stock-slow", latency=200), measurement("experiment-fast", latency=50, experimental=True),
                   measurement("stock-fast", latency=50)]
        result = recommend(entries, baseline=measurement("baseline", passing=set()))
        self.assertEqual([entry["strategyId"] for entry in result["ranking"]], ["stock-fast", "experiment-fast", "stock-slow"])

    def test_expected_check_count_requires_whole_repeats(self):
        with self.assertRaises(ValueError):
            recommend([], expected_checks=9)
        result = recommend([measurement("baseline", passing=set(), repeats=1), measurement("candidate", repeats=1)], expected_checks=5)
        self.assertEqual(result["recommendedId"], "candidate")


if __name__ == "__main__":
    unittest.main()
