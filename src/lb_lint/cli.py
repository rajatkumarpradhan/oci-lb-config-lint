from __future__ import annotations

import argparse
import json
import sys
from datetime import date

from . import analysis, model

DISCLAIMER = ("Review priorities from a simplified model of load balancer configuration. "
              "Not tested against a live tenancy; calls no OCI API.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="lb-lint", description="Offline lint of load balancer configuration (synthetic/exported data).")
    ap.add_argument("inventory")
    ap.add_argument("--reference-date", help="YYYY-MM-DD used for certificate expiry (default: today)")
    ap.add_argument("--cert-warn-days", type=int, default=analysis.DEFAULT_CERT_WARN_DAYS)
    ap.add_argument("--output")
    ap.add_argument("--fail-on", choices=["high", "medium", "low"])
    a = ap.parse_args(argv)
    try:
        if a.cert_warn_days < 0:
            raise ValueError("--cert-warn-days must be 0 or more")
        today = model.parse_date(a.reference_date, "--reference-date") if a.reference_date else date.today()
        inv = model.load_file(a.inventory)
    except (OSError, json.JSONDecodeError, model.ModelError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    fs = analysis.analyze(inv, today, a.cert_warn_days)
    for f in fs:
        print(f"[{f.severity.upper():6}] {f.rule} {f.subject}: {f.message}")
    print(f"{len(fs)} finding(s) across {len(inv.load_balancers)} load balancer(s).")
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            json.dump({"disclaimer": DISCLAIMER, "reference_date": today.isoformat(),
                       "findings": [f.to_dict() for f in fs]}, fh, indent=1)
    if a.fail_on and any(analysis.SEV[f.severity] <= analysis.SEV[a.fail_on] for f in fs):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
