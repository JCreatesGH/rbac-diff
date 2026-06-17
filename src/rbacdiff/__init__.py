"""rbacdiff: diff RBAC snapshots and flag over-privilege and SoD violations."""
from .model import Snapshot, load_snapshot
from .diff import diff_snapshots, AssignmentChange
from .policy import sod_violations, over_privileged, risky_grants, SodRule, Violation
__all__ = ["Snapshot", "load_snapshot", "diff_snapshots", "AssignmentChange",
           "sod_violations", "over_privileged", "risky_grants", "SodRule", "Violation"]
__version__ = "0.1.0"
