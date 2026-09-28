"""
blueteam.platform — shared cross-module infrastructure for the v0.8 Blue Team
Intelligence & Governance modules (intel / dac / posture).

Provides: typed config, an in-process metrics registry, an injectable clock, a
write-behind batcher, a persistent job scheduler, a circuit breaker, the tenancy
model, frozen event contracts, and the DI container. This layer imports nothing
from ``app.py`` and nothing telegram-specific — it is pure infrastructure.
"""

from .clock import Clock, FakeClock
from .config import V08Config, get_v08_config
from .metrics import MetricsRegistry, get_metrics
from .batcher import WriteBehindBatcher
from .scheduler import Scheduler, JobStore, InMemoryJobStore
from .circuit_breaker import CircuitBreaker
from .tenancy import Role, Tenant, TenantScope, TenantIsolationError, tenant_id_for_chat
from .container import BlueTeamContainer

__all__ = [
    "Clock", "FakeClock", "V08Config", "get_v08_config", "MetricsRegistry",
    "get_metrics", "WriteBehindBatcher", "Scheduler", "JobStore",
    "InMemoryJobStore", "CircuitBreaker", "Role", "Tenant", "TenantScope",
    "TenantIsolationError", "tenant_id_for_chat", "BlueTeamContainer",
]
