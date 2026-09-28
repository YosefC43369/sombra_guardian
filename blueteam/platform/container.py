"""
blueteam/platform/container.py — the small dependency-injection container (A1).

Holds process-wide singletons (config, metrics, clock, event emit, db path) and the
three module services, wired once in ``sg_platform`` (or in tests). Modules depend
only on this container + typing.Protocol ports — never on ``app.py`` or each other's
concrete classes. Dependencies point one way: handlers → services → adapters →
domain.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .clock import Clock
from .config import V08Config, get_v08_config
from .metrics import MetricsRegistry, get_metrics

logger = logging.getLogger("modbot.blueteam.container")

# emit(event_type, payload) -> None ; a no-op by default
EmitFn = Callable[[str, dict], None]


@dataclass
class BlueTeamContainer:
    db_path: str = "bot.db"
    config: V08Config = field(default_factory=get_v08_config)
    metrics: MetricsRegistry = field(default_factory=get_metrics)
    clock: Clock = field(default_factory=Clock)
    emit: EmitFn = field(default=lambda t, p: None)

    # module services (set during wiring; typed as Any to keep this layer port-only)
    intel: Any = None
    dac: Any = None
    posture: Any = None

    # health checks registered by modules: name -> callable() -> (healthy, detail)
    _health: Dict[str, Callable[[], Tuple[bool, str]]] = field(default_factory=dict)
    # background coroutines modules want the platform to run (name -> coro factory)
    _tasks: Dict[str, Callable[[], Any]] = field(default_factory=dict)
    # graceful-shutdown callables
    _shutdown: List[Callable[[], None]] = field(default_factory=list)

    def register_health(self, name: str, fn: Callable[[], Tuple[bool, str]]) -> None:
        self._health[name] = fn

    def register_task(self, name: str, coro_factory: Callable[[], Any]) -> None:
        self._tasks[name] = coro_factory

    def register_shutdown(self, fn: Callable[[], None]) -> None:
        self._shutdown.append(fn)

    def healthchecks(self) -> Dict[str, Tuple[bool, str]]:
        out: Dict[str, Tuple[bool, str]] = {}
        for name, fn in self._health.items():
            try:
                out[name] = fn()
            except Exception as exc:  # a broken healthcheck is itself unhealthy
                out[name] = (False, f"healthcheck error: {exc}")
        return out

    def background_tasks(self) -> Dict[str, Callable[[], Any]]:
        return dict(self._tasks)

    def shutdown(self) -> None:
        for fn in self._shutdown:
            try:
                fn()
            except Exception:
                logger.exception("CONTAINER | shutdown hook failed")


__all__ = ["BlueTeamContainer", "EmitFn"]
