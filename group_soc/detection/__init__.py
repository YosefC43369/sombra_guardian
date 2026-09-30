"""group_soc.detection — second-order detectors (threshold/rule/anomaly/sequence)."""

from .base import Detector
from .detector_manager import DetectorManager
from .threshold import JoinBurstDetector, RepeatedContentDetector
from .rule_engine import RuleEngine, Rule, default_rules
from .anomaly import ActivitySpikeDetector
from .sequence import SequenceDetector, default_sequence_detectors

__all__ = [
    "Detector", "DetectorManager", "JoinBurstDetector", "RepeatedContentDetector",
    "RuleEngine", "Rule", "default_rules", "ActivitySpikeDetector",
    "SequenceDetector", "default_sequence_detectors",
]
