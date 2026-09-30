"""group_soc.alerts — signal→alert decisioning (dedup/suppress/group/escalate) + lifecycle."""

from .manager import AlertManager, AlertOutcome
from .deduplication import fold_changes
from .suppression import recently_resolved_within
from .grouping import choose_group_id
from .escalation import should_escalate
from .lifecycle import transition

__all__ = [
    "AlertManager", "AlertOutcome", "fold_changes", "recently_resolved_within",
    "choose_group_id", "should_escalate", "transition",
]
