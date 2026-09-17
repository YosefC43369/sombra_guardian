"""
workflows/loader.py — load workflow definitions from files.

Format policy (no new hard dependency)
--------------------------------------
Definitions are JSON by default — stdlib only, matching how the rest of the
project ships data (reference_data/*.json). YAML is *also* accepted when
PyYAML happens to be importable, because the task's examples are written in
YAML and some deployments already have it; but nothing here requires it, so a
bot with no PyYAML installed loses no functionality — it just uses the .json
files. A ``.py`` definitions module exposing ``WORKFLOWS = [ {...}, ... ]`` is
supported too, for definitions that want comments/logic.

Every file may hold a single definition dict or a list of them.
"""

import os
import json
import logging
import importlib.util
from typing import List

from .engine import WorkflowDefinition

logger = logging.getLogger("modbot.workflows.loader")

try:
    import yaml  # optional; see module docstring
    _HAVE_YAML = True
except Exception:  # pragma: no cover - depends on environment
    _HAVE_YAML = False


def _coerce(raw) -> List[dict]:
    if isinstance(raw, dict) and "workflows" in raw:
        raw = raw["workflows"]
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return list(raw)
    raise ValueError("workflow file must contain a dict or a list of dicts")


def load_file(path: str) -> List[WorkflowDefinition]:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    elif ext in (".yaml", ".yml"):
        if not _HAVE_YAML:
            logger.warning("WORKFLOW loader | PyYAML not installed; skipping %s", path)
            return []
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    elif ext == ".py":
        return _load_py(path)
    else:
        return []
    return [WorkflowDefinition.from_dict(d) for d in _coerce(raw)]


def _load_py(path: str) -> List[WorkflowDefinition]:
    spec = importlib.util.spec_from_file_location("_wf_defs", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    raw = getattr(module, "WORKFLOWS", [])
    return [WorkflowDefinition.from_dict(d) for d in _coerce(raw)]


def load_dir(directory: str) -> List[WorkflowDefinition]:
    """Load every definition file in ``directory``. A file that fails to
    parse is logged and skipped — one bad definition never blocks the rest."""
    definitions: List[WorkflowDefinition] = []
    if not os.path.isdir(directory):
        return definitions
    for name in sorted(os.listdir(directory)):
        if name.startswith("_") or name.startswith("."):
            continue
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        try:
            definitions.extend(load_file(path))
        except Exception:
            logger.exception("WORKFLOW loader | failed to load %s", path)
    return definitions
