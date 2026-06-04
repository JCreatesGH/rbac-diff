"""RBAC snapshot: who has which roles."""
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
