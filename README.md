# rbac-diff

[![CI](https://github.com/JCreatesGH/rbac-diff/actions/workflows/ci.yml/badge.svg)](https://github.com/JCreatesGH/rbac-diff/actions)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Run an access review with evidence. `rbacdiff` compares two RBAC snapshots — across systems or across time — at both the **role** and the **effective-permission** level, and flags **over-privilege**, **separation-of-duties**, and **risky grants**. It catches the incident role-level diffing misses: *nobody's role assignment changed, but a role's definition quietly gained `prod:deploy`.* Perfect for quarterly access certifications and SOX/ISO audits.

![screenshot](assets/screenshot.png)

## Install

```bash
pip install rbacdiff
```

## Use it

```python
from rbacdiff import load_snapshot, diff_snapshots, sod_violations, over_privileged, SodRule

before = load_snapshot(last_quarter)     # {user: [roles]}
after = load_snapshot(current)

for c in diff_snapshots(before, after):
    print(c.user, "granted", c.granted, "revoked", c.revoked)

rules = [SodRule("AP segregation", "ap_invoice_create", "ap_invoice_approve")]
sod_violations(after, rules)             # users who can create AND approve

over_privileged(after, sensitive_roles={"admin", "security_admin"}, max_roles=10)

from rbacdiff import risky_grants
risky_grants(diff_snapshots(before, after), {"admin"})   # who was *newly* granted admin
```

### Effective permissions (what users can actually *do*)

Give it a role→permission **catalog** and it compares effective access, not just role labels — so it catches capability creep even when no role assignment changed:

```python
from rbacdiff import load_catalog, permission_changes, risky_permission_grants

before_cat = load_catalog({"dev": ["code:write"]})
after_cat  = load_catalog({"dev": ["code:write", "prod:deploy"]})   # the role's definition drifted

changes = permission_changes(before, after, before_cat, after_cat)
risky_permission_grants(changes, {"prod:*", "*:delete"})   # glob-matched sensitive perms
```

Catalogs support role **inheritance** (`{"admin": {"permissions": [...], "inherits": ["dev"]}}`) and are cycle-safe.

## CLI

Installing the package adds an `rbacdiff` command for access reviews in CI (exits 1 on any risk):

```bash
$ rbacdiff before.json after.json --sensitive admin,security_admin
$ rbacdiff before.json after.json --sod sod-rules.json --json
$ rbacdiff before.json after.json --max-roles 10
# effective-permission review (one catalog, or --catalog-before/--catalog-after for drift):
$ rbacdiff before.json after.json --catalog-before cat-b.json --catalog-after cat-a.json \
    --sensitive-perms 'prod:*,secrets:*'
```

## What it finds

- **Grant/revoke diff** — exactly which roles each user gained or lost between snapshots (including new and removed users).
- **SoD violations** — users holding both halves of a conflicting role pair (e.g. create + approve), via configurable `SodRule` packs.
- **Over-privilege** — users holding sensitive roles, or more than a threshold number of roles.
- **Risky grants** — from the diff, the users who were *newly* granted a sensitive role (the headline access-review signal).
- **Effective-permission diff** — with a role catalog, the permissions each user gained/lost (across role *and* catalog drift), plus **risky permission grants** matched by glob (`prod:*`, `*:delete`).

Snapshots are just `{user: [roles]}` and catalogs `{role: [permissions]}`, so it works with ServiceNow, Active Directory, cloud IAM exports, or anything you can dump to JSON.

## Development

```bash
pip install -e .[dev] && python -m pytest -q   # 18 tests
```

## License

MIT
