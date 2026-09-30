"""group_soc.metrics — SOC KPIs (MTTA/MTTR), detection breakdowns, pipeline performance."""

from .soc_metrics import SocMetrics
from .detection_metrics import DetectionMetrics
from .performance import performance_snapshot

__all__ = ["SocMetrics", "DetectionMetrics", "performance_snapshot"]
