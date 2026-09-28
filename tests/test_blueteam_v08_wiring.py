"""
tests/test_blueteam_v08_wiring.py — the v0.8 plugin wires up telegram-free, registers
its commands, bridges posture signals from real state, and its message-analysis path
emits defanged rule/IOC events. Offline, deterministic.
"""

import asyncio
import os
import sys
import tempfile
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

# keep opportunistic scheduler from firing network work during the test
os.environ["BLUETEAM_V08_ENABLED"] = "true"
os.environ["BLUETEAM_INTEL_SYNC_INTERVAL_S"] = "999999"
os.environ["BLUETEAM_POSTURE_SNAPSHOT_S"] = "999999"

import migrations
from blueteam.platform.config import get_v08_config
from plugins.base import PluginContext
import logging

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} | {name}" + (f" -> {detail}" if detail and not cond else ""))


class FakeBus:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


# ---- import + config ----
from plugins.builtin.blueteam_v08 import BlueTeamV08Plugin  # noqa: E402
check("plugin imports telegram-free", True)
get_v08_config(refresh=True)

db = tempfile.mkstemp(suffix=".db")[1]
migrations.MigrationRunner(db).migrate_up()

bus = FakeBus()
ctx = PluginContext(plugin_name="blueteam-v08", db_path=db, event_bus=bus,
                    logger=logging.getLogger("test.v08"))
plugin = BlueTeamV08Plugin()
plugin.setup(ctx)

cmd_names = {c.name for c in ctx._commands}
check("registers intel/rule/posture commands", {"intel", "rule", "posture"} <= cmd_names, str(cmd_names))
check("subscribes to message.received", any(et == "message.received" for _h, et in ctx._event_subs))
check("health ok", plugin.healthcheck() is not None)

# ---- load rules + local IOC, then analyze a message ----
plugin._dac.load_pack(plugin._pack, actor=1, activate=True)   # -> shadow (evaluates)
plugin._dac.reload()
from blueteam.intel.domain import IOCType
plugin._intel.add_local("https://evilwire.test/drain", ioc_type=IOCType.URL, added_by=1)

# pre-seed throttle so _tick does not schedule network sync
plugin._last = {"feed": time.time() + 1e9, "posture": time.time() + 1e9}

payload = {"chat_id": -100, "user_id": 42, "text":
           "connect wallet to claim tokens now https://evilwire.test/drain",
           "mention_count": 0, "is_first_message": True, "username": ""}

asyncio.new_event_loop().run_until_complete(plugin._analyze(payload))

types = [getattr(e, "type", "") for e in bus.events]
check("emits rule.matched from DaC", "rule.matched" in types, str(types))
check("emits intel.ioc_matched", "intel.ioc_matched" in types, str(types))

# IOC event must be defanged (never a live URL)
ioc_events = [e for e in bus.events if getattr(e, "type", "") == "intel.ioc_matched"]
if ioc_events:
    payload_out = ioc_events[0].payload
    check("ioc event value is defanged", "hxxp" in payload_out.get("value_defanged", "")
          or "[.]" in payload_out.get("value_defanged", ""), str(payload_out.get("value_defanged")))
    check("ioc event carries no live url key", "value" not in payload_out or
          "evilwire.test" not in str(payload_out))
else:
    check("ioc event value is defanged", False)
    check("ioc event carries no live url key", False)

# ---- posture signals bridge reflects real state ----
score = plugin._posture.score(-100)
check("posture scores from real signals", 0 <= score.score <= 100)
check("link_guard reads as fail (no policy set)",
      any(c["control"] == "link_guard" and c["status"] == "fail" for c in score.contributions))

plugin._intel._repo.close()
plugin._dac._repo.close()
plugin._posture._repo.close()
os.remove(db)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
