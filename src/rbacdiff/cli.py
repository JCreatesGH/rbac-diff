"""Command-line access review: diff two RBAC snapshots and flag risk."""
from __future__ import annotations
import argparse
import json
import sys
from typing import List, Optional

from .model import load_snapshot
from .diff import diff_snapshots
from .policy import sod_violations, over_privileged, risky_grants, SodRule


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rbacdiff", description="Diff two RBAC snapshots and flag SoD / over-privilege risk.")
    parser.add_argument("before", help="JSON snapshot ({user:[roles]} or {name,assignments})")
    parser.add_argument("after", help="JSON snapshot to compare against")
    parser.add_argument("--sensitive", help="comma-separated sensitive role names")
    parser.add_argument("--sod", help="JSON file: [{name, role_a, role_b}, ...]")
    parser.add_argument("--max-roles", type=int, help="flag users holding more than N roles")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    try:
        with open(args.before, encoding="utf-8") as f:
            before = load_snapshot(json.load(f), "before")
        with open(args.after, encoding="utf-8") as f:
            after = load_snapshot(json.load(f), "after")
        sod_rules = []
        if args.sod:
            with open(args.sod, encoding="utf-8") as f:
                sod_rules = [SodRule(**r) for r in json.load(f)]
    except (OSError, json.JSONDecodeError, TypeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    sensitive = {s.strip() for s in args.sensitive.split(",")} if args.sensitive else set()
    changes = diff_snapshots(before, after)
    risky = risky_grants(changes, sensitive)
    viol = sod_violations(after, sod_rules)
    if sensitive or args.max_roles is not None:
        viol += over_privileged(after, sensitive, args.max_roles)

    if args.json:
        print(json.dumps({
            "changes": [{"user": c.user, "granted": sorted(c.granted), "revoked": sorted(c.revoked)}
                        for c in changes],
            "risky_grants": [{"user": v.user, "detail": v.detail} for v in risky],
            "violations": [{"user": v.user, "kind": v.kind, "detail": v.detail} for v in viol],
        }, indent=2))
    else:
        print(f"Changes ({before.name} → {after.name}): {len(changes)}")
        for c in changes:
            bits = []
            if c.granted: bits.append(f"+{sorted(c.granted)}")
            if c.revoked: bits.append(f"-{sorted(c.revoked)}")
            print(f"  {c.user}: {' '.join(bits)}")
        if risky:
            print("\n⚠ Risky grants (newly granted sensitive roles):")
            for v in risky:
                print(f"  • {v.user}: {v.detail}")
        if viol:
            print("\n⚠ Policy violations in the after snapshot:")
            for v in viol:
                print(f"  • {v.user} [{v.kind}]: {v.detail}")
        if not risky and not viol:
            print("\n✓ No risky grants or policy violations.")

    return 1 if (risky or viol) else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
