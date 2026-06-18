"""Diff two RBAC snapshots — at the role and the effective-permission level."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set
from .model import Snapshot, RoleCatalog


@dataclass
class AssignmentChange:
    user: str
    granted: Set[str] = field(default_factory=set)
    revoked: Set[str] = field(default_factory=set)


def diff_snapshots(a: Snapshot, b: Snapshot) -> List[AssignmentChange]:
    """Changes going from snapshot `a` to `b`."""
    changes: List[AssignmentChange] = []
    for user in sorted(a.users() | b.users()):
        ra, rb = a.roles_of(user), b.roles_of(user)
        granted, revoked = rb - ra, ra - rb
        if granted or revoked:
            changes.append(AssignmentChange(user, granted, revoked))
    return changes


def effective_permissions(snapshot: Snapshot, catalog: RoleCatalog) -> Dict[str, Set[str]]:
    """The set of permissions each user actually holds, resolved through their
    roles (and role inheritance)."""
    out: Dict[str, Set[str]] = {}
    for user, roles in snapshot.assignments.items():
        perms: Set[str] = set()
        for role in roles:
            perms |= catalog.permissions_of(role)
        out[user] = perms
    return out


@dataclass
class PermissionChange:
    user: str
    gained: Set[str] = field(default_factory=set)
    lost: Set[str] = field(default_factory=set)


def permission_changes(before: Snapshot, after: Snapshot,
                       before_catalog: RoleCatalog, after_catalog: RoleCatalog) -> List[PermissionChange]:
    """Per-user change in *effective* permissions from before→after. Catches the
    case role-level diffing misses: a role's definition changed (granting new
    permissions) even though no role assignment did."""
    eff_a = effective_permissions(before, before_catalog)
    eff_b = effective_permissions(after, after_catalog)
    changes: List[PermissionChange] = []
    for user in sorted(set(eff_a) | set(eff_b)):
        pa, pb = eff_a.get(user, set()), eff_b.get(user, set())
        gained, lost = pb - pa, pa - pb
        if gained or lost:
            changes.append(PermissionChange(user, gained, lost))
    return changes
