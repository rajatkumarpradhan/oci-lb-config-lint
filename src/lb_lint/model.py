"""Load and validate the simplified load balancer export.

The field names are this project's own simplified schema, not the OCI API response format.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date


class ModelError(ValueError):
    pass


PROTOCOLS = {"HTTP", "HTTPS", "TCP"}
POLICIES = {"ROUND_ROBIN", "LEAST_CONNECTIONS", "IP_HASH"}
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def parse_date(v, what) -> date:
    if not isinstance(v, str) or not _DATE.match(v):
        raise ModelError(f"{what} must be a YYYY-MM-DD date, got {v!r}")
    try:
        return date.fromisoformat(v)
    except ValueError:
        raise ModelError(f"{what} is not a real date: {v!r}") from None


@dataclass
class Backend:
    ip: str
    port: int
    weight: int = 1
    backup: bool = False
    drain: bool = False
    offline: bool = False


@dataclass
class HealthChecker:
    protocol: str
    port: int = 0                  # 0 means "same as the backend port"
    url_path: str | None = None
    return_code: int | None = None
    interval_ms: int = 10000
    timeout_ms: int = 3000
    retries: int = 3


@dataclass
class BackendSet:
    name: str
    policy: str
    health_checker: HealthChecker | None
    ssl: bool
    persistence: str | None
    backends: list[Backend]


@dataclass
class Listener:
    name: str
    port: int
    protocol: str
    default_backend_set: str
    certificate: str | None
    tls_protocols: list[str]
    rule_sets: list[str]


@dataclass
class Rule:
    action: str
    header: str | None = None
    redirect_protocol: str | None = None


@dataclass
class LoadBalancer:
    name: str
    is_private: bool
    listeners: list[Listener]
    backend_sets: list[BackendSet]
    certificates: dict[str, date]
    rule_sets: dict[str, list[Rule]]


@dataclass
class Inventory:
    load_balancers: list[LoadBalancer] = field(default_factory=list)


def _int(v, what, lo=0, hi=65535):
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise ModelError(f"{what} must be an integer in [{lo}, {hi}], got {v!r}")
    return v


def _str(v, what):
    if not isinstance(v, str) or not v.strip():
        raise ModelError(f"{what} must be a non-empty string")
    return v


def _bool(v, what):
    if not isinstance(v, bool):
        raise ModelError(f"{what} must be true or false")
    return v


def _backend(b, where) -> Backend:
    return Backend(_str(b["ip"], f"{where}.ip"), _int(b["port"], f"{where}.port", 1),
                   _int(b.get("weight", 1), f"{where}.weight", 1, 100),
                   _bool(b.get("backup", False), f"{where}.backup"),
                   _bool(b.get("drain", False), f"{where}.drain"),
                   _bool(b.get("offline", False), f"{where}.offline"))


def _health(h, where) -> HealthChecker:
    proto = _str(h["protocol"], f"{where}.protocol").upper()
    if proto not in {"HTTP", "TCP"}:
        raise ModelError(f"{where}.protocol must be HTTP or TCP")
    return HealthChecker(proto, _int(h.get("port", 0), f"{where}.port"), h.get("url_path"),
                         h.get("return_code"), _int(h.get("interval_ms", 10000), f"{where}.interval_ms", 1, 10**7),
                         _int(h.get("timeout_ms", 3000), f"{where}.timeout_ms", 1, 10**7),
                         _int(h.get("retries", 3), f"{where}.retries", 0, 100))


def _backend_set(s, where) -> BackendSet:
    name = _str(s["name"], f"{where}.name")
    pol = _str(s.get("policy", "ROUND_ROBIN"), f"{where}.policy").upper()
    if pol not in POLICIES:
        raise ModelError(f"{where}.policy must be one of {sorted(POLICIES)}")
    h = s.get("health_checker")
    backends = [_backend(b, f"{where}.backends[{i}]") for i, b in enumerate(s.get("backends", []))]
    return BackendSet(name, pol, _health(h, f"{where}.health_checker") if h else None,
                      _bool(s.get("ssl", False), f"{where}.ssl"), s.get("session_persistence"), backends)


def _listener(x, where) -> Listener:
    proto = _str(x["protocol"], f"{where}.protocol").upper()
    if proto not in PROTOCOLS:
        raise ModelError(f"{where}.protocol must be one of {sorted(PROTOCOLS)}")
    ssl = x.get("ssl") or {}
    protos = ssl.get("protocols", [])
    if not isinstance(protos, list) or any(not isinstance(p, str) for p in protos):
        raise ModelError(f"{where}.ssl.protocols must be a list of strings")
    rs = x.get("rule_sets", [])
    if not isinstance(rs, list) or any(not isinstance(p, str) for p in rs):
        raise ModelError(f"{where}.rule_sets must be a list of names")
    return Listener(_str(x["name"], f"{where}.name"), _int(x["port"], f"{where}.port", 1), proto,
                    _str(x["default_backend_set"], f"{where}.default_backend_set"),
                    ssl.get("certificate_name"), [p.upper() for p in protos], rs)


def _rule(r, where) -> Rule:
    return Rule(_str(r["action"], f"{where}.action").upper(), r.get("header"),
                (r.get("protocol") or "").upper() or None)


def load(data: dict) -> Inventory:
    try:
        lbs = []
        names = set()
        for i, lb in enumerate(data["load_balancers"]):
            where = f"load_balancers[{i}]"
            name = _str(lb["name"], f"{where}.name")
            if name in names:
                raise ModelError(f"duplicate load balancer {name!r}")
            names.add(name)
            listeners = [_listener(x, f"{where}.listeners[{j}]") for j, x in enumerate(lb.get("listeners", []))]
            ports = [x.port for x in listeners]
            if len(ports) != len(set(ports)):
                raise ModelError(f"{name}: two listeners share a port")
            lnames = [x.name for x in listeners]
            if len(lnames) != len(set(lnames)):
                raise ModelError(f"{name}: duplicate listener name")
            sets = [_backend_set(s, f"{where}.backend_sets[{j}]") for j, s in enumerate(lb.get("backend_sets", []))]
            snames = [s.name for s in sets]
            if len(snames) != len(set(snames)):
                raise ModelError(f"{name}: duplicate backend set name")
            certs = {_str(c["name"], f"{where}.certificates.name"): parse_date(c["not_after"], f"{where}.certificates.not_after")
                     for c in lb.get("certificates", [])}
            rsets = {_str(r["name"], f"{where}.rule_sets.name"): [_rule(x, f"{where}.rule_sets") for x in r.get("items", [])]
                     for r in lb.get("rule_sets", [])}
            lbs.append(LoadBalancer(name, _bool(lb.get("is_private", False), f"{where}.is_private"),
                                    listeners, sets, certs, rsets))
    except (KeyError, TypeError, AttributeError) as e:
        raise ModelError(f"invalid model: {e!r}") from e
    return Inventory(lbs)


def load_file(path: str) -> Inventory:
    with open(path, encoding="utf-8") as f:
        return load(json.load(f))
