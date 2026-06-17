"""Separation-of-duties and over-privilege checks."""
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional, Set, TYPE_CHECKING
from .model import Snapshot

if TYPE_CHECKING:
    from .diff import AssignmentChange


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
