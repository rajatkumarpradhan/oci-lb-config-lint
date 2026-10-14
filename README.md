# oci-lb-config-lint

Offline lint of load balancer configuration in the shape of an OCI Load Balancer: listeners, backend sets, health checks, certificates and rule sets. It reads a JSON file, reports what looks risky or broken, and exits non-zero on demand so it can gate a CI job.

**Scope, stated plainly.** Portfolio project. It reads a simplified JSON model whose field names are this project's own, not the OCI API response format. The bundled data is synthetic. It has not been run against a real tenancy, calls no OCI API, and spends nothing. Findings are review priorities from a checklist I wrote, not a security assessment or a statement of OCI policy.

## Rules

| Rule | Severity | Meaning |
|---|---|---|
| LB001 | high | HTTPS listener has no certificate |
| LB002 | high | Listener uses a certificate that is not defined on the load balancer |
| LB003 | high | TLS 1.0 or 1.1 enabled on a listener |
| LB004 | high / medium | Certificate expired (high) or expires within `--cert-warn-days` days, default 30 (medium) |
| LB005 | medium | Public load balancer with a plain-HTTP listener and no redirect-to-HTTPS rule |
| LB006 | high | Public load balancer forwards a TCP listener on 22, 3389, 1433, 1521, 3306, 5432, 6379 or 27017 |
| LB007 | high | Listener points at a backend set or rule set that does not exist |
| LB008 | high | Backend set has no health checker |
| LB009 | medium / low | Health check timeout not smaller than the interval (medium); retries below 2, or HTTP check without a path (low) |
| LB010 | high / medium | No active backend (high); only one active backend (medium). Backup, offline and draining backends do not count as active |
| LB011 | medium | Same ip:port listed twice in a backend set |
| LB012 | low | HTTPS listener without a Strict-Transport-Security response header rule |
| LB013 | low | TLS ends at the load balancer and the backend set is not TLS |
| LB014 | medium | HTTP listener on 443 or HTTPS listener on 80 |
| LB015 | low | Backend set that no listener or routing-policy rule uses |
| LB016 | medium | Routing-policy rule that can never match because an earlier rule covers it |
| LB017 | low | Hostname defined but used by no listener |
| LB018 | high / medium | Listener or route points at a hostname, routing policy or backend set that does not exist (medium: policy on a TCP listener) |
| LB019 | low | Routing policy no listener uses |

## Usage

```
python -m pip install -e .
lb-lint examples/good.json --reference-date 2026-10-01      # 0 findings
lb-lint examples/risky.json --reference-date 2026-10-01 --output report.json
lb-lint examples/risky.json --reference-date 2026-10-01 --fail-on high   # exit 2 if any high finding
lb-lint examples/risky.json --reference-date 2026-10-01 --output report.sarif --format sarif   # SARIF 2.1.0
python -m unittest discover -s tests -v
```

`--reference-date` pins "today" for certificate checks, so results are reproducible. Without it the local date is used. Exit codes: 0 clean (or no `--fail-on` threshold hit), 1 unreadable or invalid input, 2 threshold hit.

## SARIF output

`--format sarif --output FILE` writes the findings as SARIF 2.1.0 instead of the default JSON report, with one rule entry for each of LB001 to LB019. Severity maps to level (high = error, medium = warning, low = note). Each result carries its rule id, message, the input file as `artifactLocation`, and the load balancer and listener, backend set or certificate as a logical location. The input has no line numbers, so results point at the file, not a line. `--format sarif` needs `--output`; the terminal text and exit codes are unchanged, and a clean input gives an empty results list. This is a small hand-built subset of SARIF: the tests check its shape, but it has not been validated against the official schema or loaded into a real viewer.

## Input shape

```
{"load_balancers": [{
  "name": "shop-public", "is_private": false,
  "listeners": [{"name": "https", "port": 443, "protocol": "HTTPS", "default_backend_set": "web",
                 "ssl": {"certificate_name": "shop-cert", "protocols": ["TLSv1.2", "TLSv1.3"]},
                 "rule_sets": ["security-headers"]}],
  "backend_sets": [{"name": "web", "policy": "ROUND_ROBIN", "ssl": true,
                    "health_checker": {"protocol": "HTTP", "url_path": "/healthz", "interval_ms": 10000, "timeout_ms": 3000, "retries": 3},
                    "backends": [{"ip": "10.0.1.11", "port": 8443}]}],
  "certificates": [{"name": "shop-cert", "not_after": "2027-06-30"}],
  "rule_sets": [{"name": "security-headers", "items": [{"action": "ADD_HTTP_RESPONSE_HEADER", "header": "Strict-Transport-Security"}]}]}]}
```

Validation is strict: bad ports, unknown protocols, duplicate names or listener ports, weights below 1, impossible dates and wrong types stop the run with exit 1 and a message instead of being skipped.

## Limits

- It checks a fixed list of conventions. It does not know your traffic, your WAF, your NSGs or security lists, or whether a flagged port is intended.
- Certificates are only checked by the expiry date you give. No chain, key size, SAN or revocation checks, and no certificate files are read.
- TLS checks look at the protocol list only. Cipher suites are not judged.
- Rule sets are reduced to two patterns: a REDIRECT to HTTPS and a Strict-Transport-Security header. Other actions are ignored.
- Health check ports, return codes and path correctness are not validated against the backends.
- LB006 is a port list, not an exposure analysis; a private load balancer is never flagged.
- Nothing here models routing policies, hostnames, path routes, shapes or bandwidth, or reserved IPs.
- The tool reads a file you export yourself; there is no exporter from a real tenancy.

## Tests

50 unit tests: every rule with its boundaries (certificate expiry at 30/31 days, today and yesterday, timeout equal to the interval, retries 1 and 2), cases that must stay quiet (private load balancers, backup backends, same IP on another port, modern TLS only), 20 structural validation cases, finding order, the CLI exit codes, the JSON report, and the SARIF output (shape, level mapping, rule index, empty case, CLI). A healthy example must produce zero findings and the risky example must trigger every rule. CI runs on Python 3.10, 3.11 and 3.12.

## License

MIT

## Routing policies and hostnames

The input can define `hostnames` and `routing_policies` on a load balancer. A listener lists the hostnames it serves and names one `routing_policy`. Each policy has ordered `rules` with a `condition` (`hostname`, and either `path_prefix` or `path_exact`) and a `backend_set`. A rule with no condition matches everything.

Shadowing (LB016) assumes first-match-wins in rule order, which is how I modelled it. A prefix is a plain string prefix, so `/api` also covers `/apix`. An exact path only covers the same exact path. A rule with no hostname covers every host; a rule with a hostname only covers that same host. Not modelled: wildcard hostname matching against concrete hostnames, regex or header conditions, and OCI's real rule-ordering and limits. This follows my own simplified schema, not the OCI API, and has not been checked against a real load balancer.
