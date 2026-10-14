"""Lint rules. Findings are review priorities from a simplified model, not a security assessment."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import date

from .model import Inventory, LoadBalancer

SEV = {"high": 0, "medium": 1, "low": 2}
DEFAULT_CERT_WARN_DAYS = 30
LEGACY_TLS = {"TLSV1", "TLSV1.0", "TLSV1_0", "TLSV1.1", "TLSV1_1"}
SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 1433: "SQL Server", 1521: "Oracle DB", 3306: "MySQL",
                   5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"}


@dataclass
class Finding:
    rule: str
    severity: str
    subject: str
    message: str
    evidence: dict

    def to_dict(self):
        return asdict(self)


def _redirects_to_https(lb: LoadBalancer, names: list[str]) -> bool:
    return any(r.action == "REDIRECT" and r.redirect_protocol == "HTTPS"
               for n in names for r in lb.rule_sets.get(n, []))


def _has_hsts(lb: LoadBalancer, names: list[str]) -> bool:
    return any(r.action == "ADD_HTTP_RESPONSE_HEADER" and (r.header or "").lower() == "strict-transport-security"
               for n in names for r in lb.rule_sets.get(n, []))


def _host_covers(earlier, later) -> bool:
    """An earlier route with no hostname matches every host; otherwise the hostnames must be equal."""
    return earlier is None or earlier == later


def _path_covers(e, l) -> bool:
    """True when every request path matched by route l is already matched by route e (prefix = plain string prefix)."""
    if e.path_prefix is None and e.path_exact is None:
        return True
    if e.path_exact is not None:
        return l.path_exact == e.path_exact
    lp = l.path_prefix if l.path_prefix is not None else l.path_exact
    return lp is not None and lp.startswith(e.path_prefix)


def shadowed_by(routes) -> dict:
    """Map index of a shadowed route to the index of the first earlier route that covers it."""
    out = {}
    for i, r in enumerate(routes):
        for j in range(i):
            e = routes[j]
            if _host_covers(e.hostname, r.hostname) and _path_covers(e, r):
                out[i] = j
                break
    return out


def analyze(inv: Inventory, today: date, cert_warn_days: int = DEFAULT_CERT_WARN_DAYS) -> list[Finding]:
    out: list[Finding] = []
    for lb in inv.load_balancers:
        sets = {s.name: s for s in lb.backend_sets}
        used = {x.default_backend_set for x in lb.listeners}
        used_pols = {x.routing_policy for x in lb.listeners if x.routing_policy}
        used |= {r.backend_set for n in used_pols for r in lb.routing_policies.get(n, [])}
        used_hosts = {h for x in lb.listeners for h in x.hostnames}
        for x in lb.listeners:
            sub = f"{lb.name}/listener:{x.name}"
            if x.protocol == "HTTPS":
                if not x.certificate:
                    out.append(Finding("LB001", "high", sub, "HTTPS listener has no certificate configured.", {"port": x.port}))
                elif x.certificate not in lb.certificates:
                    out.append(Finding("LB002", "high", sub, f"Certificate {x.certificate!r} is not defined on this load balancer.",
                                       {"certificate": x.certificate}))
                if not _has_hsts(lb, x.rule_sets):
                    out.append(Finding("LB012", "low", sub, "No Strict-Transport-Security response header rule on this HTTPS listener.",
                                       {"rule_sets": x.rule_sets}))
                bs = sets.get(x.default_backend_set)
                if bs is not None and not bs.ssl:
                    out.append(Finding("LB013", "low", sub, f"TLS ends at the load balancer; backend set {bs.name!r} is plain TCP/HTTP to the backends.",
                                       {"backend_set": bs.name}))
            legacy = sorted(set(x.tls_protocols) & LEGACY_TLS)
            if legacy:
                out.append(Finding("LB003", "high", sub, f"Legacy TLS version(s) enabled: {', '.join(legacy)}.", {"protocols": x.tls_protocols}))
            if x.protocol == "HTTP" and x.port == 443 or x.protocol == "HTTPS" and x.port == 80:
                out.append(Finding("LB014", "medium", sub, f"{x.protocol} listener on port {x.port}: port and protocol look swapped.",
                                   {"port": x.port, "protocol": x.protocol}))
            if not lb.is_private:
                if x.protocol == "HTTP" and not _redirects_to_https(lb, x.rule_sets):
                    out.append(Finding("LB005", "medium", sub, "Public plain-HTTP listener with no redirect-to-HTTPS rule.", {"port": x.port}))
                if x.port in SENSITIVE_PORTS and x.protocol == "TCP":
                    out.append(Finding("LB006", "high", sub, f"Public load balancer forwards port {x.port} ({SENSITIVE_PORTS[x.port]}) from the internet.",
                                       {"port": x.port}))
            if x.default_backend_set not in sets:
                out.append(Finding("LB007", "high", sub, f"Default backend set {x.default_backend_set!r} does not exist.",
                                   {"backend_set": x.default_backend_set}))
            for h in x.hostnames:
                if h not in lb.hostnames:
                    out.append(Finding("LB018", "high", sub, f"Hostname {h!r} is not defined on this load balancer.", {"hostname": h}))
            if x.routing_policy and x.routing_policy not in lb.routing_policies:
                out.append(Finding("LB018", "high", sub, f"Routing policy {x.routing_policy!r} does not exist.", {"routing_policy": x.routing_policy}))
            if x.routing_policy and x.protocol == "TCP":
                out.append(Finding("LB018", "medium", sub, "A routing policy is set on a TCP listener; path and host routing only apply to HTTP and HTTPS.",
                                   {"routing_policy": x.routing_policy}))
            for rn in x.rule_sets:
                if rn not in lb.rule_sets:
                    out.append(Finding("LB007", "high", sub, f"Rule set {rn!r} does not exist.", {"rule_set": rn}))
        for h in lb.hostnames:
            if h not in used_hosts:
                out.append(Finding("LB017", "low", f"{lb.name}/hostname:{h}", "Hostname is defined but no listener uses it.", {"hostname": h}))
        for pn, routes in lb.routing_policies.items():
            sub = f"{lb.name}/routing-policy:{pn}"
            if pn not in used_pols:
                out.append(Finding("LB019", "low", sub, "Routing policy is not used by any listener.", {}))
            for i, j in shadowed_by(routes).items():
                out.append(Finding("LB016", "medium", f"{sub}/rule:{routes[i].name}",
                                   f"Can never match: rule {routes[j].name!r} earlier in the policy already matches every request this rule would.",
                                   {"shadowed_by": routes[j].name}))
            for r in routes:
                if r.backend_set not in sets:
                    out.append(Finding("LB018", "high", f"{sub}/rule:{r.name}", f"Backend set {r.backend_set!r} does not exist.", {"backend_set": r.backend_set}))
        for name, d in sorted(lb.certificates.items()):
            left = (d - today).days
            sub = f"{lb.name}/certificate:{name}"
            if left < 0:
                out.append(Finding("LB004", "high", sub, f"Certificate expired {-left} day(s) ago ({d.isoformat()}).", {"not_after": d.isoformat(), "days_left": left}))
            elif left <= cert_warn_days:
                out.append(Finding("LB004", "medium", sub, f"Certificate expires in {left} day(s) ({d.isoformat()}).", {"not_after": d.isoformat(), "days_left": left}))
        for s in lb.backend_sets:
            sub = f"{lb.name}/backend-set:{s.name}"
            if s.name not in used:
                out.append(Finding("LB015", "low", sub, "Backend set is not the default of any listener.", {}))
            h = s.health_checker
            if h is None:
                out.append(Finding("LB008", "high", sub, "No health checker: failed backends keep receiving traffic.", {}))
            else:
                if h.timeout_ms >= h.interval_ms:
                    out.append(Finding("LB009", "medium", sub, f"Health check timeout {h.timeout_ms}ms is not smaller than the interval {h.interval_ms}ms.",
                                       {"timeout_ms": h.timeout_ms, "interval_ms": h.interval_ms}))
                if h.retries < 2:
                    out.append(Finding("LB009", "low", sub, f"Health check retries is {h.retries}: one slow response can mark a backend unhealthy.", {"retries": h.retries}))
                if h.protocol == "HTTP" and not h.url_path:
                    out.append(Finding("LB009", "low", sub, "HTTP health check has no url_path.", {}))
            live = [b for b in s.backends if not (b.backup or b.offline or b.drain)]
            if not live:
                out.append(Finding("LB010", "high", sub, "No active backend: all are backup, offline, draining, or none are defined.",
                                   {"backends": len(s.backends)}))
            elif len(live) == 1:
                out.append(Finding("LB010", "medium", sub, f"Only one active backend ({live[0].ip}:{live[0].port}): single point of failure.",
                                   {"backend": f"{live[0].ip}:{live[0].port}"}))
            seen, dup = set(), set()
            for b in s.backends:
                k = (b.ip, b.port)
                (dup if k in seen else seen).add(k)
            for ip, port in sorted(dup):
                out.append(Finding("LB011", "medium", sub, f"Backend {ip}:{port} is listed more than once.", {"backend": f"{ip}:{port}"}))
    out.sort(key=lambda f: (SEV[f.severity], f.rule, f.subject, f.message))
    return out
