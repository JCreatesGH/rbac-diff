"""Separation-of-duties and over-privilege checks."""
from __future__ import annotations
import fnmatch
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, TYPE_CHECKING
from .model import Snapshot, RoleCatalog
from .diff import effective_permissions   # safe: diff.py does not import policy.py

if TYPE_CHECKING:
    from .diff import AssignmentChange, PermissionChange


@dataclass(frozen=True)
class SodRule:
    name: str
    role_a: str
    role_b: str        # holding both a and b is a conflict


@dataclass
class Violation:
    user: str
    kind: str          # "sod" | "over-privilege"
    detail: str


def sod_violations(snapshot: Snapshot, rules: List[SodRule]) -> List[Violation]:
    out: List[Violation] = []
    for user, roles in snapshot.assignments.items():
        for rule in rules:
            if rule.role_a in roles and rule.role_b in roles:
                out.append(Violation(user, "sod",
                    f"{rule.name}: holds both '{rule.role_a}' and '{rule.role_b}'"))
    return sorted(out, key=lambda v: (v.user, v.detail))


def over_privileged(snapshot: Snapshot, sensitive_roles: Set[str],
                    max_roles: Optional[int] = None) -> List[Violation]:
    out: List[Violation] = []
    for user, roles in snapshot.assignments.items():
        held = roles & sensitive_roles
        if held:
            out.append(Violation(user, "over-privilege",
                f"holds sensitive role(s): {sorted(held)}"))
        if max_roles is not None and len(roles) > max_roles:
            out.append(Violation(user, "over-privilege",
                f"holds {len(roles)} roles (> {max_roles})"))
    return sorted(out, key=lambda v: (v.user, v.detail))


def risky_grants(changes: List["AssignmentChange"], sensitive_roles: Set[str]) -> List[Violation]:
    """From a diff, flag users who were *newly granted* a sensitive role — the most
    actionable access-review signal ('who just got admin?')."""
    out: List[Violation] = []
    for c in changes:
        gained = c.granted & sensitive_roles
        if gained:
            out.append(Violation(c.user, "risky-grant",
                f"newly granted sensitive role(s): {sorted(gained)}"))
    return sorted(out, key=lambda v: (v.user, v.detail))


def who_can(snapshot: Snapshot, catalog: RoleCatalog, permission: str) -> List[str]:
    """The auditor's reverse lookup: every user whose effective permissions allow
    `permission`. Glob-aware in the *grant's* favor — a user holding `prod:*` (or
    `*:*`) can do `prod:deploy`. Returns a sorted user list."""
    eff = effective_permissions(snapshot, catalog)
    return sorted(u for u, perms in eff.items()
                  if any(fnmatch.fnmatchcase(permission, p) for p in perms))


def broad_permissions(catalog: RoleCatalog) -> Dict[str, List[str]]:
    """Roles whose effective permissions include a wildcard grant (`*:*`, `prod:*`,
    `*:delete`, …) — a standard least-privilege audit finding. Inheritance is
    followed, so a role that inherits a wildcard is flagged too."""
    out: Dict[str, List[str]] = {}
    for role in set(catalog.grants) | set(catalog.inherits):
        wild = sorted(p for p in catalog.permissions_of(role) if "*" in p or "?" in p)
        if wild:
            out[role] = wild
    return out


def risky_permission_grants(changes: List["PermissionChange"],
                            sensitive_patterns: Set[str]) -> List[Violation]:
    """From an effective-permission diff, flag users who *newly gained* a sensitive
    permission. Patterns are globs, so `prod:*` matches `prod:deploy` and `*:delete`
    matches `db:delete` — catches capability creep even with no role change."""
    out: List[Violation] = []
    for c in changes:
        hits = sorted(p for p in c.gained
                      if any(fnmatch.fnmatchcase(p, pat) for pat in sensitive_patterns))
        if hits:
            out.append(Violation(c.user, "risky-grant",
                f"newly gained sensitive permission(s): {hits}"))
    return sorted(out, key=lambda v: (v.user, v.detail))
