"""
plugins.builtin.detection_bridge — a real, non-invasive built-in plugin.

Demonstrates all three plugin hooks against the live event stream without
adding any Telegram command or changing existing behaviour:

  * a workflow action ``record_detection_note`` that any workflow can call,
  * an event subscription that counts ``detection.triggered`` events, and
  * a healthcheck that confirms the detection module imports and reports the
    running count for /plugins health.

It only observes — it never deletes, warns, mutes, or writes to another
module's tables — so if it failed to load the bot's moderation is untouched.
"""

import logging

from plugins.base import BasePlugin, PluginContext, HealthStatus, PermissionLevel

logger = logging.getLogger("modbot.plugins.detection_bridge")


class _RecordDetectionNoteAction:
    """A WorkflowAction (duck-typed: name + async execute) that logs a
    structured note for a detection event. Registered into the shared action
    registry so workflows can list it as one of their actions."""
    name = "record_detection_note"

    async def execute(self, context):
        from workflows.models import ActionResult
        event = context["event"]
        detail = event.payload.get("detection_type") or event.type
        context["logger"].info("PLUGIN detection_bridge note | %s", detail)
        return ActionResult.success(self.name, f"noted {detail}")


class DetectionBridgePlugin(BasePlugin):
    name = "detection-bridge"
    version = "1.0.0"
    description = "Observes detection events and exposes a workflow action + health."
    author = "sombra_guardian"
    permission = PermissionLevel.ADMIN

    def __init__(self):
        self._seen = 0
        self._detection_importable = None

    def setup(self, ctx: PluginContext) -> None:
        ctx.register_workflow_action(_RecordDetectionNoteAction())
        ctx.subscribe_event(self._on_detection, "detection.triggered")
        # Confirm the detection module is importable and exposes the API we
        # observe, so the healthcheck is cheap and meaningful.
        try:
            import detection
            self._detection_importable = hasattr(detection, "analyze_message")
        except Exception as exc:  # pragma: no cover - detection always present here
            self._detection_importable = False
            ctx.logger.warning("detection-bridge: detection import failed: %s", exc)

    async def _on_detection(self, event) -> None:
        self._seen += 1

    def healthcheck(self) -> HealthStatus:
        if self._detection_importable is False:
            return HealthStatus.unhealthy("detection module not importable")
        return HealthStatus.ok(f"observed {self._seen} detection event(s)")
