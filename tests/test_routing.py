import copy
import unittest

from lb_lint import analysis, model
from test_lint import base, keys, rules, run


def route(name, backend="web", **cond):
    return {"name": name, "condition": cond, "backend_set": backend}


def with_policy(*rs, hostnames=None, listener_hosts=None):
    d = base()
    lb = d["load_balancers"][0]
    lb["hostnames"] = hostnames or []
    lb["routing_policies"] = [{"name": "p", "rules": list(rs)}]
    for l in lb["listeners"]:
        l.pop("hostnames", None)
        l.pop("routing_policy", None)
    lb["listeners"][0]["routing_policy"] = "p"
    lb["listeners"][0]["hostnames"] = listener_hosts if listener_hosts is not None else (hostnames or [])
    return d


def shadows(d):
    return {f.subject.split("/", 1)[1] for f in run(d) if f.rule == "LB016"}


class ShadowTests(unittest.TestCase):
    def test_broader_prefix_shadows_narrower(self):
        d = with_policy(route("a", path_prefix="/api"), route("b", path_prefix="/api/v1"))
        self.assertEqual(shadows(d), {"routing-policy:p/rule:b"})

    def test_narrower_first_is_fine(self):
        d = with_policy(route("a", path_prefix="/api/v1"), route("b", path_prefix="/api"))
        self.assertEqual(shadows(d), set())

    def test_prefix_shadows_exact_under_it(self):
        d = with_policy(route("a", path_prefix="/api"), route("b", path_exact="/api/x"))
        self.assertEqual(len(shadows(d)), 1)

    def test_exact_does_not_shadow_prefix_or_other_exact(self):
        self.assertEqual(shadows(with_policy(route("a", path_exact="/api"), route("b", path_prefix="/api"))), set())
        self.assertEqual(shadows(with_policy(route("a", path_exact="/api"), route("b", path_exact="/api/"))), set())

    def test_same_exact_twice_is_shadowed(self):
        self.assertEqual(len(shadows(with_policy(route("a", path_exact="/x"), route("b", path_exact="/x")))), 1)

    def test_sibling_prefixes_do_not_shadow(self):
        d = with_policy(route("a", path_prefix="/api"), route("b", path_prefix="/app"))
        self.assertEqual(shadows(d), set())

    def test_catch_all_shadows_everything_after(self):
        d = with_policy(route("a"), route("b", path_prefix="/x"), route("c", hostname="a.example.com"),
                        hostnames=["a.example.com"])
        self.assertEqual(shadows(d), {"routing-policy:p/rule:b", "routing-policy:p/rule:c"})

    def test_root_prefix_is_a_catch_all_for_paths(self):
        d = with_policy(route("a", path_prefix="/"), route("b", path_prefix="/zzz"))
        self.assertEqual(len(shadows(d)), 1)

    def test_hostname_scoped_earlier_rule_does_not_shadow_other_host(self):
        d = with_policy(route("a", hostname="a.example.com", path_prefix="/"),
                        route("b", hostname="b.example.com", path_prefix="/x"),
                        hostnames=["a.example.com", "b.example.com"])
        self.assertEqual(shadows(d), set())

    def test_hostname_scoped_earlier_rule_does_not_shadow_any_host_rule(self):
        d = with_policy(route("a", hostname="a.example.com", path_prefix="/"), route("b", path_prefix="/x"),
                        hostnames=["a.example.com"])
        self.assertEqual(shadows(d), set())

    def test_any_host_rule_shadows_host_rule(self):
        d = with_policy(route("a", path_prefix="/"), route("b", hostname="a.example.com", path_prefix="/x"),
                        hostnames=["a.example.com"])
        self.assertEqual(len(shadows(d)), 1)

    def test_reports_first_covering_rule(self):
        f = [x for x in run(with_policy(route("a", path_prefix="/a"), route("b", path_prefix="/a/b"), route("c", path_prefix="/a/b/c")))
             if x.rule == "LB016"]
        self.assertEqual({x.evidence["shadowed_by"] for x in f}, {"a"})
        self.assertEqual(len(f), 2)


class ReferenceTests(unittest.TestCase):
    def test_unused_hostname(self):
        d = with_policy(route("a"), hostnames=["a.example.com", "b.example.com"], listener_hosts=["a.example.com"])
        self.assertIn(("LB017", "hostname:b.example.com"), keys(d))
        self.assertNotIn(("LB017", "hostname:a.example.com"), keys(d))

    def test_undefined_listener_hostname(self):
        d = with_policy(route("a"), hostnames=[], listener_hosts=["x.example.com"])
        self.assertIn(("LB018", "listener:https"), keys(d))

    def test_missing_policy_and_backend_set(self):
        d = with_policy(route("a", backend="nowhere"))
        d["load_balancers"][0]["listeners"][0]["routing_policy"] = "ghost"
        f = [x for x in run(d) if x.rule == "LB018" and "listener" in x.subject]
        self.assertEqual(len(f), 1)
        d["load_balancers"][0]["listeners"][0]["routing_policy"] = "p"
        self.assertEqual({x.subject.split("/", 1)[1] for x in run(d) if x.rule == "LB018"}, {"routing-policy:p/rule:a"})

    def test_routing_policy_on_tcp_listener(self):
        d = with_policy(route("a"))
        d["load_balancers"][0]["listeners"][0]["protocol"] = "TCP"
        d["load_balancers"][0]["listeners"][0]["port"] = 8080
        self.assertTrue(any(f.rule == "LB018" and f.severity == "medium" for f in run(d)))

    def test_unused_policy(self):
        d = with_policy(route("a"))
        d["load_balancers"][0]["listeners"][0].pop("routing_policy")
        self.assertIn(("LB019", "routing-policy:p"), keys(d))

    def test_backend_set_used_only_by_a_route_is_not_unused(self):
        d = with_policy(route("a", backend="spare"))
        d["load_balancers"][0]["backend_sets"].append(copy.deepcopy(d["load_balancers"][0]["backend_sets"][0]))
        d["load_balancers"][0]["backend_sets"][-1]["name"] = "spare"
        self.assertNotIn(("LB015", "backend-set:spare"), keys(d))

    def test_no_findings_without_routing_config(self):
        d = base()
        for lb in d["load_balancers"]:
            for k in ("hostnames", "routing_policies"):
                lb.pop(k, None)
            for l in lb["listeners"]:
                l.pop("hostnames", None)
                l.pop("routing_policy", None)
        self.assertFalse(rules(d) & {"LB016", "LB017", "LB018", "LB019"})


class ValidationTests(unittest.TestCase):
    def bad(self, mutate):
        d = with_policy(route("a", hostname="a.example.com", path_prefix="/x"), hostnames=["a.example.com"])
        mutate(d["load_balancers"][0])
        with self.assertRaises(model.ModelError):
            model.load(d)

    def test_errors(self):
        pol = lambda lb: lb["routing_policies"][0]
        cases = [
            lambda lb: lb["hostnames"].append("A.Example.com"),
            lambda lb: lb["hostnames"].append("localhost"),
            lambda lb: lb["hostnames"].append("a.example.com"),
            lambda lb: lb["hostnames"].append("a*.example.com"),
            lambda lb: lb["hostnames"].append("-a.example.com"),
            lambda lb: pol(lb)["rules"][0]["condition"].update(path_prefix="x"),
            lambda lb: pol(lb)["rules"][0]["condition"].update(path_exact="/y"),
            lambda lb: pol(lb)["rules"][0]["condition"].update(hostname="Bad_Host"),
            lambda lb: pol(lb)["rules"].append(copy.deepcopy(pol(lb)["rules"][0])),
            lambda lb: lb["routing_policies"].append(copy.deepcopy(pol(lb))),
            lambda lb: pol(lb)["rules"][0].pop("backend_set"),
            lambda lb: pol(lb)["rules"][0].update(condition="x"),
            lambda lb: lb["listeners"][0].update(hostnames="a.example.com"),
            lambda lb: lb["listeners"][0].update(routing_policy=""),
        ]
        for i, m in enumerate(cases):
            with self.subTest(case=i):
                self.bad(m)

    def test_wildcard_hostname_ok(self):
        d = with_policy(route("a", hostname="*.example.com"), hostnames=["*.example.com"])
        model.load(d)


if __name__ == "__main__":
    unittest.main()
