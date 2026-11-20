"""Installation detection and safe repair planning for ``doctor --fix``."""

from .detect import SystemSnapshot, detect_system
from .fix import run_fix
from .plan import APPROVAL, AUTO, MANUAL, RepairAction, RepairPlan, build_plan
from .progress import STAGES, RepairReporter

__all__ = [
    "APPROVAL",
    "AUTO",
    "MANUAL",
    "RepairAction",
    "RepairPlan",
    "RepairReporter",
    "STAGES",
    "SystemSnapshot",
    "build_plan",
    "detect_system",
    "run_fix",
]
