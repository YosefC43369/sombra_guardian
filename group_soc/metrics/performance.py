"""
group_soc/metrics/performance.py — pipeline/runtime performance snapshot.

Wraps the worker's BackpressureStats and current queue depth into a small dict for
/soc health. Purely a formatter over live counters — no queries.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


def performance_snapshot(worker) -> Dict[str, Any]:
    if worker is None:
        return {"worker": "not running"}
    stats = worker.stats.as_dict()
    stats["queue_depth"] = worker.depth()
    stats["queue_maxsize"] = worker.maxsize
    return stats
