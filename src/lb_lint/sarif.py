"""SARIF 2.1.0 output so findings can be loaded into code-scanning viewers.

The input is a JSON file without line numbers, so each result points at the input file as a
whole (artifactLocation) and names the load balancer and listener, backend set or certificate
in a logical location. This is a minimal hand-built subset of SARIF: the tests check its shape,
but it has not been validated against the official schema or loaded into a real viewer.
"""
from __future__ import annotations

from .analysis import Finding

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"high": "error", "medium": "warning", "low": "note"}
RULES = {
    "LB001": "HTTPS listener has no certificate",
    "LB002": "Listener uses a certificate that is not defined on the load balancer",
    "LB003": "TLS 1.0 or 1.1 enabled on a listener",
    "LB004": "Certificate expired or expiring soon",
    "LB005": "Public plain-HTTP listener without a redirect to HTTPS",
    "LB006": "Public load balancer forwards a sensitive TCP port",
    "LB007": "Listener points at a backend set or rule set that does not exist",
    "LB008": "Backend set has no health checker",
    "LB009": "Weak health check settings",
    "LB010": "No active backend, or a single active backend",
    "LB011": "Duplicate backend in a backend set",
    "LB012": "HTTPS listener without a Strict-Transport-Security header rule",
    "LB013": "TLS ends at the load balancer; backends are not TLS",
    "LB014": "Listener port and protocol look swapped",
    "LB015": "Backend set is not used by any listener",
}


def to_sarif(findings: list[Finding], artifact_uri: str, version: str = "0.1.0") -> dict:
    rules = [{"id": r, "shortDescription": {"text": t}} for r, t in sorted(RULES.items())]
    index = {r["id"]: i for i, r in enumerate(rules)}
    results = []
    for f in findings:
        res = {
            "ruleId": f.rule,
            "level": LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": artifact_uri}},
                "logicalLocations": [{"name": f.subject}],
            }],
        }
        if f.rule in index:
            res["ruleIndex"] = index[f.rule]
        if f.evidence:
            res["properties"] = {"evidence": f.evidence}
        results.append(res)
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "oci-lb-config-lint", "version": version, "rules": rules}},
            "results": results,
        }],
    }
