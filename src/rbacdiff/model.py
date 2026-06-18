"""RBAC snapshot: who has which roles, and what those roles can do."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, Set


@dataclass
class Snapshot:
    name: str
    assignments: Dict[str, Set[str]] = field(default_factory=dict)   # user -> roles

    def users(self) -> Set[str]:
        return set(self.assignments)

    def roles_of(self, user: str) -> Set[str]:
        return self.assignments.get(user, set())


def load_snapshot(data: Dict[str, Any], name: str = "snapshot") -> Snapshot:
    """Accepts {user: [roles]} or {"name":..., "assignments": {user:[roles]}}."""
    if "assignments" in data:
        name = data.get("name", name)
        raw = data["assignments"]
    else:
        raw = data
    return Snapshot(name=name, assignments={u: set(r) for u, r in raw.items()})


@dataclass
class RoleCatalog:
    """What each role grants: direct permissions plus optional role inheritance."""
    name: str
    grants: Dict[str, Set[str]] = field(default_factory=dict)     # role -> direct permissions
    inherits: Dict[str, Set[str]] = field(default_factory=dict)   # role -> parent roles

    def permissions_of(self, role: str) -> Set[str]:
        """All permissions a role confers, following inheritance (cycle-safe)."""
        out: Set[str] = set()
        seen: Set[str] = set()
        stack = [role]
        while stack:
            r = stack.pop()
            if r in seen:
                continue
            seen.add(r)
            out |= self.grants.get(r, set())
            stack.extend(self.inherits.get(r, set()))
        return out


def load_catalog(data: Dict[str, Any], name: str = "catalog") -> RoleCatalog:
    """Accepts {role: [perms]}, {role: {permissions:[...], inherits:[...]}}, or
    {"name":..., "roles": {...}}."""
    if "roles" in data:
        name = data.get("name", name)
        raw = data["roles"]
    else:
        raw = data
    grants: Dict[str, Set[str]] = {}
    inherits: Dict[str, Set[str]] = {}
    for role, spec in raw.items():
        if isinstance(spec, dict):
            grants[role] = set(spec.get("permissions", []))
            inherits[role] = set(spec.get("inherits", []))
        else:
            grants[role] = set(spec)
            inherits[role] = set()
    return RoleCatalog(name=name, grants=grants, inherits=inherits)
