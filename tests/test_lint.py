import copy
import json
import os
import tempfile
import unittest
from datetime import date

from lb_lint import analysis, model
from lb_lint.cli import main

HERE = os.path.dirname(__file__)
EX = os.path.join(HERE, "..", "examples")
TODAY = date(2026, 10, 1)


def load_ex(name):
    with open(os.path.join(EX, name), encoding="utf-8") as f:
        return json.load(f)


GOOD = load_ex("good.json")


def base():
    return copy.deepcopy(GOOD)


def run(d, today=TODAY, warn=30):
    return analysis.analyze(model.load(d), today, warn)


def keys(d, **kw):
    return {(f.rule, f.subject.split("/", 1)[1]) for f in run(d, **kw)}


def rules(d, **kw):
    return {f.rule for f in run(d, **kw)}


def pub(d):
    return d["load_balancers"][0]


def https(d):
    return pub(d)["listeners"][0]


def bset(d, name="web"):
    return next(s for s in pub(d)["backend_sets"] if s["name"] == name)


class CleanTests(unittest.TestCase):
    def test_good_example_has_no_findings(self):
        self.assertEqual(run(base()), [])

    def test_risky_example_covers_every_rule(self):
        got = rules(load_ex("risky.json"))
        self.assertEqual(got, {f"LB{n:03d}" for n in range(1, 20)})

    def test_finding_order_is_by_severity(self):
        sev = [analysis.SEV[f.severity] for f in run(load_ex("risky.json"))]
        self.assertEqual(sev, sorted(sev))

    def test_empty_inventory_is_fine(self):
        self.assertEqual(run({"load_balancers": []}), [])


class TlsTests(unittest.TestCase):
    def test_https_without_certificate(self):
        d = base()
        https(d)["ssl"] = {"protocols": ["TLSv1.2"]}
        self.assertIn(("LB001", "listener:https"), keys(d))

    def test_unknown_certificate(self):
        d = base()
        https(d)["ssl"]["certificate_name"] = "nope"
        self.assertIn(("LB002", "listener:https"), keys(d))
        self.assertNotIn("LB001", rules(d))

    def test_legacy_tls_versions(self):
        for v in ("TLSv1", "TLSv1.1", "TLSV1_1", "tlsv1"):
            with self.subTest(v=v):
                d = base()
                https(d)["ssl"]["protocols"] = [v, "TLSv1.2"]
                self.assertIn("LB003", rules(d))

    def test_modern_tls_only_is_clean(self):
        d = base()
        https(d)["ssl"]["protocols"] = ["TLSv1.3"]
        self.assertNotIn("LB003", rules(d))

    def test_hsts_missing(self):
        d = base()
        https(d)["rule_sets"] = []
        self.assertIn(("LB012", "listener:https"), keys(d))

    def test_hsts_header_is_case_insensitive(self):
        d = base()
        pub(d)["rule_sets"][0]["items"][0]["header"] = "strict-transport-security"
        self.assertNotIn("LB012", rules(d))

    def test_other_response_header_is_not_hsts(self):
        d = base()
        pub(d)["rule_sets"][0]["items"][0]["header"] = "X-Frame-Options"
        self.assertIn("LB012", rules(d))

    def test_plain_backend_behind_https(self):
        d = base()
        bset(d)["ssl"] = False
        self.assertIn(("LB013", "listener:https"), keys(d))

    def test_port_protocol_swap(self):
        d = base()
        https(d)["port"] = 80
        pub(d)["listeners"][1]["port"] = 443
        pub(d)["listeners"][1]["protocol"] = "HTTP"
        self.assertEqual({f.subject.split("/", 1)[1] for f in run(d) if f.rule == "LB014"}, {"listener:https", "listener:http-redirect"})


class CertTests(unittest.TestCase):
    def cert(self, when, today=TODAY, warn=30):
        d = base()
        pub(d)["certificates"][0]["not_after"] = when
        return [f for f in run(d, today, warn) if f.rule == "LB004"]

    def test_boundaries(self):
        self.assertEqual(len(self.cert("2026-10-31")), 1)       # exactly 30 days left: warns
        self.assertEqual(self.cert("2026-11-01"), [])            # 31 days left: quiet
        self.assertEqual(self.cert("2026-10-01")[0].severity, "medium")   # expires today: 0 days left
        self.assertEqual(self.cert("2026-09-30")[0].severity, "high")     # expired yesterday

    def test_warn_window_is_configurable(self):
        self.assertEqual(self.cert("2026-11-15", warn=60)[0].severity, "medium")
        self.assertEqual(self.cert("2026-11-15", warn=10), [])

    def test_reference_date_changes_result(self):
        self.assertEqual(self.cert("2027-06-30", today=date(2027, 7, 1))[0].severity, "high")


class ExposureTests(unittest.TestCase):
    def test_plain_http_public_without_redirect(self):
        d = base()
        pub(d)["listeners"][1]["rule_sets"] = []
        self.assertIn(("LB005", "listener:http-redirect"), keys(d))

    def test_http_redirect_must_target_https(self):
        d = base()
        pub(d)["rule_sets"][1]["items"][0]["protocol"] = "HTTP"
        self.assertIn("LB005", rules(d))

    def test_private_lb_may_use_plain_http(self):
        d = base()
        self.assertEqual([f for f in run(d) if f.rule == "LB005"], [])
        d["load_balancers"][1]["is_private"] = False
        self.assertIn(("LB005", "listener:api"), keys(d))

    def test_sensitive_ports_only_on_public_tcp(self):
        d = base()
        pub(d)["listeners"].append({"name": "ssh", "port": 22, "protocol": "TCP", "default_backend_set": "web"})
        self.assertIn(("LB006", "listener:ssh"), keys(d))
        pub(d)["is_private"] = True
        self.assertNotIn("LB006", rules(d))

    def test_non_sensitive_tcp_port_is_fine(self):
        d = base()
        pub(d)["listeners"].append({"name": "t", "port": 9000, "protocol": "TCP", "default_backend_set": "web"})
        self.assertNotIn("LB006", rules(d))

    def test_missing_backend_set_and_rule_set(self):
        d = base()
        https(d)["default_backend_set"] = "ghost"
        https(d)["rule_sets"] = ["security-headers", "ghost-rules"]
        subjects = [f.message for f in run(d) if f.rule == "LB007"]
        self.assertEqual(len(subjects), 2)


class BackendTests(unittest.TestCase):
    def test_missing_health_checker(self):
        d = base()
        del bset(d)["health_checker"]
        self.assertIn(("LB008", "backend-set:web"), keys(d))

    def test_timeout_boundary(self):
        d = base()
        h = bset(d)["health_checker"]
        h["interval_ms"], h["timeout_ms"] = 5000, 4999
        self.assertNotIn("LB009", rules(d))
        h["timeout_ms"] = 5000
        self.assertIn("LB009", rules(d))

    def test_retries_boundary(self):
        d = base()
        h = bset(d)["health_checker"]
        h["retries"] = 2
        self.assertNotIn("LB009", rules(d))
        h["retries"] = 1
        self.assertIn("LB009", rules(d))

    def test_http_health_check_needs_path(self):
        d = base()
        del bset(d)["health_checker"]["url_path"]
        self.assertIn("LB009", rules(d))

    def test_tcp_health_check_needs_no_path(self):
        d = base()
        self.assertEqual([f for f in run(d) if f.subject.endswith("internal-api") or "api" in f.subject], [])

    def test_single_active_backend(self):
        d = base()
        bset(d)["backends"] = [{"ip": "10.0.1.11", "port": 8443}, {"ip": "10.0.1.12", "port": 8443, "drain": True}]
        self.assertIn(("LB010", "backend-set:web"), keys(d))

    def test_backup_does_not_count_as_active(self):
        d = base()
        bset(d)["backends"] = [{"ip": "10.0.1.11", "port": 8443}, {"ip": "10.0.1.12", "port": 8443, "backup": True}]
        f = next(f for f in run(d) if f.rule == "LB010")
        self.assertEqual(f.severity, "medium")

    def test_no_active_backend_is_high(self):
        d = base()
        bset(d)["backends"] = [{"ip": "10.0.1.11", "port": 8443, "offline": True}]
        self.assertEqual(next(f for f in run(d) if f.rule == "LB010").severity, "high")
        bset(d)["backends"] = []
        self.assertEqual(next(f for f in run(d) if f.rule == "LB010").severity, "high")

    def test_duplicate_backend(self):
        d = base()
        bset(d)["backends"].append({"ip": "10.0.1.11", "port": 8443})
        self.assertIn(("LB011", "backend-set:web"), keys(d))

    def test_same_ip_different_port_is_not_duplicate(self):
        d = base()
        bset(d)["backends"].append({"ip": "10.0.1.11", "port": 9443})
        self.assertNotIn("LB011", rules(d))

    def test_unused_backend_set(self):
        d = base()
        pub(d)["backend_sets"].append({"name": "spare", "health_checker": {"protocol": "TCP"}, "backends": [{"ip": "10.0.5.1", "port": 80}, {"ip": "10.0.5.2", "port": 80}]})
        self.assertIn(("LB015", "backend-set:spare"), keys(d))


class ValidationTests(unittest.TestCase):
    def bad(self, mutate):
        d = base()
        mutate(d)
        with self.assertRaises(model.ModelError):
            model.load(d)

    def test_structural_errors(self):
        cases = [
            lambda d: d.pop("load_balancers"),
            lambda d: d["load_balancers"].append(copy.deepcopy(pub(d))),
            lambda d: pub(d)["listeners"][1].update(port=443),
            lambda d: pub(d)["listeners"][1].update(name="https"),
            lambda d: pub(d)["listeners"][0].update(protocol="UDP"),
            lambda d: pub(d)["listeners"][0].update(port=70000),
            lambda d: pub(d)["listeners"][0].update(port=True),
            lambda d: pub(d)["listeners"][0].update(port="443"),
            lambda d: pub(d)["backend_sets"].append(copy.deepcopy(bset(d))),
            lambda d: bset(d).update(policy="RANDOM"),
            lambda d: bset(d)["backends"][0].update(weight=0),
            lambda d: bset(d)["backends"][0].update(port=0),
            lambda d: bset(d)["backends"][0].update(backup="yes"),
            lambda d: bset(d)["health_checker"].update(protocol="UDP"),
            lambda d: bset(d)["health_checker"].update(timeout_ms=0),
            lambda d: pub(d)["certificates"][0].update(not_after="30/06/2027"),
            lambda d: pub(d)["certificates"][0].update(not_after="2027-02-30"),
            lambda d: pub(d).update(is_private="no"),
            lambda d: pub(d)["listeners"][0].update(rule_sets="a"),
            lambda d: https(d)["ssl"].update(protocols="TLSv1.2"),
        ]
        for i, m in enumerate(cases):
            with self.subTest(case=i):
                self.bad(m)


class CliTests(unittest.TestCase):
    def test_good_and_risky(self):
        self.assertEqual(main([os.path.join(EX, "good.json"), "--reference-date", "2026-10-01"]), 0)
        self.assertEqual(main([os.path.join(EX, "risky.json"), "--reference-date", "2026-10-01", "--fail-on", "high"]), 2)
        self.assertEqual(main([os.path.join(EX, "risky.json"), "--reference-date", "2026-10-01"]), 0)

    def test_fail_on_levels(self):
        d = base()
        https(d)["rule_sets"] = []                       # one LB012 (low) only
        with tempfile.TemporaryDirectory() as t:
            p = os.path.join(t, "i.json")
            json.dump(d, open(p, "w", encoding="utf-8"))
            args = [p, "--reference-date", "2026-10-01"]
            self.assertEqual(main(args + ["--fail-on", "medium"]), 0)
            self.assertEqual(main(args + ["--fail-on", "low"]), 2)

    def test_report_file(self):
        with tempfile.TemporaryDirectory() as t:
            out = os.path.join(t, "r.json")
            main([os.path.join(EX, "risky.json"), "--reference-date", "2026-10-01", "--output", out])
            rep = json.load(open(out, encoding="utf-8"))
        self.assertEqual(rep["reference_date"], "2026-10-01")
        self.assertIn("Not tested against a live tenancy", rep["disclaimer"])
        self.assertGreater(len(rep["findings"]), 10)

    def test_errors_exit_1(self):
        with tempfile.TemporaryDirectory() as t:
            bad = os.path.join(t, "b.json")
            open(bad, "w").write("{not json")
            self.assertEqual(main([bad]), 1)
            self.assertEqual(main([os.path.join(t, "missing.json")]), 1)
            self.assertEqual(main([os.path.join(EX, "good.json"), "--reference-date", "2026-13-01"]), 1)
            self.assertEqual(main([os.path.join(EX, "good.json"), "--reference-date", "yesterday"]), 1)
            self.assertEqual(main([os.path.join(EX, "good.json"), "--cert-warn-days", "-1"]), 1)


if __name__ == "__main__":
    unittest.main()
