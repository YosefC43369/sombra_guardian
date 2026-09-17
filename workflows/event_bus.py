"""
workflows/event_bus.py — a tiny async publish/subscribe hub.

The bus is what app.py publishes to; the workflow engine is its primary
subscriber, and plugins may subscribe their own async handlers. It exists so
producers (message handler, incident layer, member events) never import the
engine directly — they publish an :class:`Event` and the bus fans it out.

Two entry points:
  * ``await bus.publish(event)`` — await every subscriber; used in async code
    and tests where the caller wants completion/results.
  * ``bus.emit(event)`` — fire-and-forget from any context: schedules the
    publish on the running loop if there is one, else runs it to completion.
    Never raises into the caller — a workflow problem must not break the code
    path that produced the event.
"""

import asyncio
import logging
from typing import Awaitable, Callable, List

from .models import Event

logger = logging.getLogger("modbot.workflows.bus")

Subscriber = Callable[[Event], Awaitable]


class EventBus:
    def __init__(self):
        self._subscribers: List[Subscriber] = []
        # subscribers scoped to a single event type
        self._typed: dict = {}

    def subscribe(self, handler: Subscriber, event_type: str = None) -> None:
        """Register an async handler. With ``event_type`` it only receives
        events of that type; without, it receives all events."""
        if event_type is None:
            self._subscribers.append(handler)
        else:
            self._typed.setdefault(event_type, []).append(handler)

    def _handlers_for(self, event_type: str) -> List[Subscriber]:
        return list(self._subscribers) + list(self._typed.get(event_type, []))

    async def publish(self, event: Event) -> list:
        """Deliver to every matching subscriber; isolate each one's failure."""
        results = []
        for handler in self._handlers_for(event.type):
            try:
                results.append(await handler(event))
            except Exception:
                logger.exception("EVENT BUS | subscriber failed for %s", event.type)
                results.append(None)
        return results

    def emit(self, event: Event) -> None:
        """Fire-and-forget. Safe to call from a sync Telegram handler or from
        deep inside async code without awaiting."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            loop.create_task(self._safe_publish(event))
        else:
            try:
                asyncio.run(self._safe_publish(event))
            except Exception:
                logger.exception("EVENT BUS | emit failed for %s", event.type)

    async def _safe_publish(self, event: Event) -> None:
        try:
            await self.publish(event)
        except Exception:
            logger.exception("EVENT BUS | publish failed for %s", event.type)
