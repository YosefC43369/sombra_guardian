"""
behavioral_intelligence.anomaly — deviation-from-baseline analysis.

Builds behavioural baselines from an entity's own history, detects univariate
outliers, measures distribution drift between windows, coordinates statistical
and categorical change detection, and produces an explainable 0–100 anomaly score
(a deviation measure — never a threat/criminality score) whose contributing
features are always exposed. All wording is "anomalous relative to the observed
baseline"; nothing is labelled malicious.
"""

from . import baseline, outlier, drift, change_detection, anomaly_engine
from .baseline import build_baseline, build_baselines
from .outlier import (detect_outliers, zscore_outliers, iqr_outliers,
                      mad_outliers, Outlier)
from .drift import measure_drift, measure_all_drift
from .change_detection import detect_changes
from .anomaly_engine import AnomalyEngine

__all__ = [
    "baseline", "outlier", "drift", "change_detection", "anomaly_engine",
    "build_baseline", "build_baselines", "detect_outliers", "zscore_outliers",
    "iqr_outliers", "mad_outliers", "Outlier", "measure_drift",
    "measure_all_drift", "detect_changes", "AnomalyEngine",
]
