import json
import os
import tempfile
import unittest
from datetime import date

from lb_lint import analysis, model
from lb_lint.cli import main
from lb_lint.sarif import LEVEL, RULES, to_sarif

EX = os.path.join(os.path.dirname(__file__), "..", "examples")
TODAY = date(2026, 10, 1)


def findings(name="risky.json"):
    return analysis.analyze(model.load_file(os.path.join(EX, name)), TODAY)


class SarifTests(unittest.TestCase):
    def test_top_level_shape(self):
        doc = to_sarif(findings(), "examples/risky.json")
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(doc["$schema"].endswith("sarif-2.1.0.json"))
        self.assertEqual(len(doc["runs"]), 1)
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["name"], "oci-lb-config-lint")

    def test_one_result_per_finding_in_order(self):
        fs = findings()
        res = to_sarif(fs, "x.json")["runs"][0]["results"]
        self.assertEqual([r["ruleId"] for r in res], [f.rule for f in fs])
        self.assertGreater(len(res), 15)

    def test_levels_map_from_severity(self):
        self.assertEqual(LEVEL, {"high": "error", "medium": "warning", "low": "note"})
        fs = findings()
        for f, r in zip(fs, to_sarif(fs, "x.json")["runs"][0]["results"]):
            self.assertEqual(r["level"], LEVEL[f.severity])
        self.assertEqual({r["level"] for r in to_sarif(fs, "x")["runs"][0]["results"]}, {"error", "warning", "note"})

    def test_one_rule_entry_per_rule_and_index_matches(self):
        run = to_sarif(findings(), "x.json")["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        self.assertEqual([r["id"] for r in rules], sorted(RULES))
        self.assertEqual(len(rules), 19)
        for r in rules:
            self.assertTrue(r["shortDescription"]["text"])
        for r in run["results"]:
            self.assertEqual(rules[r["ruleIndex"]]["id"], r["ruleId"])

    def test_every_analysis_rule_is_described(self):
        for n in range(1, 20):
            self.assertIn(f"LB{n:03d}", RULES)
        self.assertEqual({f.rule for f in findings()}, set(RULES))

    def test_locations_message_and_evidence(self):
        res = to_sarif(findings(), "dir/inv.json")["runs"][0]["results"][0]
        loc = res["locations"][0]
        self.assertEqual(loc["physicalLocation"]["artifactLocation"]["uri"], "dir/inv.json")
        self.assertIn("/", loc["logicalLocations"][0]["name"])
        self.assertTrue(res["message"]["text"])

    def test_empty_result_case(self):
        doc = to_sarif(findings("good.json"), "examples/good.json")
        self.assertEqual(doc["runs"][0]["results"], [])
        self.assertEqual(len(doc["runs"][0]["tool"]["driver"]["rules"]), 19)

    def test_output_is_json_serialisable(self):
        json.dumps(to_sarif(findings(), "x.json"))


class CliSarifTests(unittest.TestCase):
    def test_cli_writes_sarif_and_default_is_unchanged(self):
        with tempfile.TemporaryDirectory() as t:
            s, j = os.path.join(t, "r.sarif"), os.path.join(t, "r.json")
            risky = os.path.join(EX, "risky.json")
            self.assertEqual(main([risky, "--reference-date", "2026-10-01", "--output", s, "--format", "sarif"]), 0)
            self.assertEqual(main([risky, "--reference-date", "2026-10-01", "--output", j]), 0)
            doc = json.load(open(s, encoding="utf-8"))
            rep = json.load(open(j, encoding="utf-8"))
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(len(doc["runs"][0]["results"]), len(rep["findings"]))
        self.assertEqual(set(rep), {"disclaimer", "reference_date", "findings"})

    def test_sarif_needs_output(self):
        self.assertEqual(main([os.path.join(EX, "good.json"), "--format", "sarif"]), 1)

    def test_exit_code_still_follows_fail_on(self):
        with tempfile.TemporaryDirectory() as t:
            s = os.path.join(t, "r.sarif")
            self.assertEqual(main([os.path.join(EX, "risky.json"), "--reference-date", "2026-10-01",
                                   "--output", s, "--format", "sarif", "--fail-on", "high"]), 2)

    def test_clean_input_gives_empty_sarif_and_exit_0(self):
        with tempfile.TemporaryDirectory() as t:
            s = os.path.join(t, "r.sarif")
            self.assertEqual(main([os.path.join(EX, "good.json"), "--reference-date", "2026-10-01", "--output", s, "--format", "sarif"]), 0)
            self.assertEqual(json.load(open(s, encoding="utf-8"))["runs"][0]["results"], [])


if __name__ == "__main__":
    unittest.main()
