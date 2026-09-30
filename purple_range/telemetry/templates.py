"""
purple_range/telemetry/templates.py — per-event-type synthetic field builders.

Every value is obviously fake and lab-safe: hostnames are ``SIMULATED-HOST-NN``,
IPs are RFC 5737 documentation ranges, domains use the reserved ``.test`` TLD and are
defanged, users are ``SIM\\lab_user``. Nothing here reads or reflects real state. Given
the same (technique, seed) the output is identical so tuning cycles are reproducible.
"""

from __future__ import annotations

import random
from typing import Any, Callable, Dict

from ..constants import TelemetryEventType

_HOST = "SIMULATED-HOST-{:02d}"
_USER = "SIM\\lab_user"


def _host(rng: random.Random) -> str:
    return _HOST.format(rng.randint(1, 9))


def _doc_ip(rng: random.Random) -> str:
    # RFC 5737 TEST-NET-1 documentation range 192.0.2.0/24
    return f"192.0.2.{rng.randint(2, 254)}"


def _proc(event_type: str, tid: str, rng: random.Random, i: int) -> Dict[str, Any]:
    return {"process_name": "sim_emulation.exe", "pid": 40000 + rng.randint(0, 9999),
            "ppid": 4000 + rng.randint(0, 999), "user": _USER, "host": _host(rng),
            "command_line": f"<synthetic-emulation technique={tid} step={i}>"}


def _proc_exit(event_type: str, tid: str, rng: random.Random, i: int) -> Dict[str, Any]:
    return {"process_name": "sim_emulation.exe", "pid": 40000 + rng.randint(0, 9999),
            "exit_code": 0, "host": _host(rng)}


def _net(event_type: str, tid: str, rng: random.Random, i: int) -> Dict[str, Any]:
    return {"src_ip": f"10.0.0.{rng.randint(2, 254)}", "dst_ip": _doc_ip(rng),
            "dst_port": rng.choice([80, 443, 8080, 53]), "proto": "tcp",
            "host": _host(rng)}


def _dns(event_type: str, tid: str, rng: random.Random, i: int) -> Dict[str, Any]:
    return {"query": f"sim-{tid.lower()}-{i}[.]lab[.]test", "qtype": "A",
            "host": _host(rng)}


def _file(event_type: str, tid: str, rng: random.Random, i: int) -> Dict[str, Any]:
    return {"path": f"C:\\sim\\lab\\{tid}\\artifact_{i}.dat", "action": "read",
            "user": _USER, "host": _host(rng)}


def _reg(event_type: str, tid: str, rng: random.Random, i: int) -> Dict[str, Any]:
    return {"key": f"HKLM\\SOFTWARE\\Sim\\Lab\\{tid}", "action": "query",
            "host": _host(rng)}


def _auth(event_type: str, tid: str, rng: random.Random, i: int) -> Dict[str, Any]:
    return {"user": _USER, "result": "failure", "logon_type": 3,
            "src_ip": _doc_ip(rng), "host": _host(rng)}


def _sysq(event_type: str, tid: str, rng: random.Random, i: int) -> Dict[str, Any]:
    return {"query_type": "system_information", "technique": tid, "host": _host(rng)}


def _svc(event_type: str, tid: str, rng: random.Random, i: int) -> Dict[str, Any]:
    return {"service_name": f"SimLabSvc{i}", "action": "create", "host": _host(rng)}


def _task(event_type: str, tid: str, rng: random.Random, i: int) -> Dict[str, Any]:
    return {"task_name": f"\\Sim\\LabTask_{tid}_{i}", "action": "create",
            "host": _host(rng)}


def _sim(event_type: str, tid: str, rng: random.Random, i: int) -> Dict[str, Any]:
    return {"note": "synthetic simulation marker", "technique": tid,
            "evidence": f"synthetic://{tid.lower()}/{i:03d}", "host": _host(rng)}


_BUILDERS: Dict[str, Callable[[str, str, random.Random, int], Dict[str, Any]]] = {
    TelemetryEventType.PROCESS_CREATE.value: _proc,
    TelemetryEventType.PROCESS_EXIT.value: _proc_exit,
    TelemetryEventType.NETWORK_CONNECTION.value: _net,
    TelemetryEventType.DNS_QUERY.value: _dns,
    TelemetryEventType.FILE_ACCESS.value: _file,
    TelemetryEventType.REGISTRY_ACCESS.value: _reg,
    TelemetryEventType.AUTHENTICATION.value: _auth,
    TelemetryEventType.SYSTEM_QUERY.value: _sysq,
    TelemetryEventType.SERVICE_EVENT.value: _svc,
    TelemetryEventType.SCHEDULED_TASK_EVENT.value: _task,
    TelemetryEventType.SIMULATION_EVENT.value: _sim,
}


def build_fields(event_type: str, technique_id: str, rng: random.Random, i: int) -> Dict[str, Any]:
    builder = _BUILDERS.get(event_type, _sim)
    return builder(event_type, technique_id, rng, i)
