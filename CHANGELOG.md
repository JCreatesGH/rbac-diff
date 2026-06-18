# Changelog

All notable changes are documented here, following
[Keep a Changelog](https://keepachangelog.com/) and [SemVer](https://semver.org/).

## [0.2.0]

### Added
- **Effective-permission analysis** — a `RoleCatalog` (role → permissions, with
  cycle-safe role **inheritance**) and `effective_permissions(snapshot, catalog)`
  to compute what each user can actually do.
- `permission_changes(before, after, before_catalog, after_catalog)` — per-user
  gained/lost *effective* permissions. Catches the incident role-level diffing
  misses: a role's definition drifted (granting new access) with no assignment
  change.
- `risky_permission_grants(changes, patterns)` — newly gained sensitive
  permissions matched by glob (`prod:*`, `*:delete`).
- CLI: `--catalog-before` / `--catalog-after` and `--sensitive-perms` add an
  effective-permission review (exits 1 on a risky permission grant).

## [0.1.0]

### Added
- Diff two RBAC snapshots (role grants/revokes per user), `sod_violations`,
  `over_privileged`, `risky_grants`, and an `rbacdiff` CLI (`--sensitive`,
  `--sod`, `--max-roles`, `--json`).
