"""
plugins/loader.py — discover BasePlugin subclasses, with failure isolation.

Two sources:
  * the built-in package ``plugins.builtin`` (ships with the bot), and
  * an optional external directory (env ``SG_PLUGINS_DIR``) so an operator can
    drop in extra plugins without editing the tree.

A module that fails to import, or a plugin class that fails to instantiate,
is logged and skipped — discovery of one plugin never blocks the others, and
never blocks the bot. That is the first half of the "isolate plugin failure"
guarantee (the second half is setup() isolation in the manager).
"""

import os
import pkgutil
import logging
import importlib
import importlib.util
from typing import List

from .base import BasePlugin

logger = logging.getLogger("modbot.plugins.loader")


def _plugin_classes_in(module) -> List[type]:
    found = []
    for attr in vars(module).values():
        if (
            isinstance(attr, type)
            and issubclass(attr, BasePlugin)
            and attr is not BasePlugin
            and attr.__module__ == module.__name__
            and getattr(attr, "name", "")
        ):
            found.append(attr)
    return found


def discover_builtin(package: str = "plugins.builtin") -> List[BasePlugin]:
    plugins: List[BasePlugin] = []
    try:
        pkg = importlib.import_module(package)
    except Exception:
        logger.exception("PLUGIN DISCOVERY | cannot import %s", package)
        return plugins
    for _finder, mod_name, _ispkg in pkgutil.iter_modules(pkg.__path__):
        if mod_name.startswith("_"):
            continue
        full = f"{package}.{mod_name}"
        try:
            module = importlib.import_module(full)
        except Exception:
            logger.exception("PLUGIN DISCOVERY | failed to import %s", full)
            continue
        plugins.extend(_instantiate(module))
    return plugins


def discover_external(directory: str) -> List[BasePlugin]:
    plugins: List[BasePlugin] = []
    if not directory or not os.path.isdir(directory):
        return plugins
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".py") or name.startswith("_"):
            continue
        path = os.path.join(directory, name)
        mod_name = f"sg_external_plugin_{name[:-3]}"
        try:
            spec = importlib.util.spec_from_file_location(mod_name, path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception:
            logger.exception("PLUGIN DISCOVERY | failed to load external %s", path)
            continue
        plugins.extend(_instantiate(module))
    return plugins


def _instantiate(module) -> List[BasePlugin]:
    instances = []
    for cls in _plugin_classes_in(module):
        try:
            instances.append(cls())
        except Exception:
            logger.exception("PLUGIN DISCOVERY | %s failed to instantiate", cls.__name__)
    return instances


def discover_all(external_dir: str = None) -> List[BasePlugin]:
    external_dir = external_dir or os.getenv("SG_PLUGINS_DIR")
    return discover_builtin() + discover_external(external_dir)
