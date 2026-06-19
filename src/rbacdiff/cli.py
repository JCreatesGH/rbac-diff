"""Command-line access review: diff two RBAC snapshots and flag risk."""
from __future__ import annotations
import argparse
import json
import sys
from typing import List, Optional

from .model import load_snapshot, load_catalog
from .diff import diff_snapshots, permission_changes
from .policy import (sod_violations, over_privileged, risky_grants, risky_permission_grants,
                     who_can, broad_permissions, SodRule)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rbacdiff", description="Diff two RBAC snapshots and flag SoD / over-privilege risk.")
    parser.add_argument("before", help="JSON snapshot ({user:[roles]} or {name,assignments})")
    parser.add_argument("after", help="JSON snapshot to compare against")
    parser.add_argument("--sensitive", help="comma-separated sensitive role names")
    parser.add_argument("--sod", help="JSON file: [{name, role_a, role_b}, ...]")
    parser.add_argument("--max-roles", type=int, help="flag users holding more than N roles")
    parser.add_argument("--catalog-before", help="JSON role→permissions catalog for the BEFORE snapshot")
    parser.add_argument("--catalog-after",
                        help="JSON role→permissions catalog for the AFTER snapshot (defaults to --catalog-before)")
    parser.add_argument("--sensitive-perms",
                        help="comma-separated sensitive permission globs, e.g. 'prod:*,*:delete'")
    parser.add_argument("--who-can", metavar="PERM",
                        help="list users in the AFTER snapshot whose effective permissions allow PERM (needs a catalog)")
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
        # role→permission catalogs (optional). One catalog applies to both sides;
        # supplying both compares effective permissions across catalog drift too.
        cat_before = cat_after = None
        cb, ca = args.catalog_before or args.catalog_after, args.catalog_after or args.catalog_before
        if cb:
            with open(cb, encoding="utf-8") as f:
                cat_before = load_catalog(json.load(f), "catalog-before")
            with open(ca, encoding="utf-8") as f:
                cat_after = load_catalog(json.load(f), "catalog-after")
    except (OSError, json.JSONDecodeError, TypeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    # Focused query: who can do PERM (against the after snapshot + catalog)?
    if args.who_can:
        if cat_after is None:
            print("error: --who-can needs a catalog (--catalog-before/--catalog-after)", file=sys.stderr)
            return 2
        users = who_can(after, cat_after, args.who_can)
        if args.json:
            print(json.dumps({"permission": args.who_can, "users": users}, indent=2))
        else:
            print(f"Users who can '{args.who_can}' (in {after.name}): {len(users)}")
            for u in users:
                print(f"  • {u}")
        return 0

    sensitive = {s.strip() for s in args.sensitive.split(",")} if args.sensitive else set()
    changes = diff_snapshots(before, after)
    risky = risky_grants(changes, sensitive)
    viol = sod_violations(after, sod_rules)
    if sensitive or args.max_roles is not None:
        viol += over_privileged(after, sensitive, args.max_roles)

    perm_changes = []
    risky_perms = []
    broad = {}
    if cat_before is not None:
        perm_changes = permission_changes(before, after, cat_before, cat_after)
        sens_perms = ({s.strip() for s in args.sensitive_perms.split(",")}
                      if args.sensitive_perms else set())
        risky_perms = risky_permission_grants(perm_changes, sens_perms)
        broad = broad_permissions(cat_after)        # informational least-privilege finding

    if args.json:
        print(json.dumps({
            "changes": [{"user": c.user, "granted": sorted(c.granted), "revoked": sorted(c.revoked)}
                        for c in changes],
            "risky_grants": [{"user": v.user, "detail": v.detail} for v in risky],
            "violations": [{"user": v.user, "kind": v.kind, "detail": v.detail} for v in viol],
            "permission_changes": [{"user": c.user, "gained": sorted(c.gained), "lost": sorted(c.lost)}
                                   for c in perm_changes],
            "risky_permission_grants": [{"user": v.user, "detail": v.detail} for v in risky_perms],
            "broad_permissions": broad,
        }, indent=2))
    else:
        print(f"Changes ({before.name} → {after.name}): {len(changes)}")
        for c in changes:
            bits = []
            if c.granted: bits.append(f"+{sorted(c.granted)}")
            if c.revoked: bits.append(f"-{sorted(c.revoked)}")
            print(f"  {c.user}: {' '.join(bits)}")
        if perm_changes:
            print(f"\nEffective permission changes: {len(perm_changes)}")
            for c in perm_changes:
                bits = []
                if c.gained: bits.append(f"+{sorted(c.gained)}")
                if c.lost: bits.append(f"-{sorted(c.lost)}")
                print(f"  {c.user}: {' '.join(bits)}")
        if risky:
            print("\n⚠ Risky grants (newly granted sensitive roles):")
            for v in risky:
                print(f"  • {v.user}: {v.detail}")
        if risky_perms:
            print("\n⚠ Risky permission grants (newly gained sensitive permissions):")
            for v in risky_perms:
                print(f"  • {v.user}: {v.detail}")
        if viol:
            print("\n⚠ Policy violations in the after snapshot:")
            for v in viol:
                print(f"  • {v.user} [{v.kind}]: {v.detail}")
        if broad:
            print("\nℹ Broad (wildcard) permissions in the after catalog:")
            for role, perms in sorted(broad.items()):
                print(f"  • {role}: {perms}")
        if not risky and not viol and not risky_perms:
            print("\n✓ No risky grants or policy violations.")

    return 1 if (risky or viol or risky_perms) else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
