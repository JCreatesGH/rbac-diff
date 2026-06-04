"""Diff two RBAC snapshots."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set
from .model import Snapshot


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
