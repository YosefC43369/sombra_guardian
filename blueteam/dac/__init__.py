"""blueteam.dac — Detection-as-Code engine (v0.8.0).

Sigma-lite rules compiled to closures with NO eval/exec/compile. Layering:
``domain`` (compiler, pure) + ``lifecycle`` (state machine, pure) + ``records``
(feature extraction, pure) -> ``matcher`` (Aho-Corasick + stateful engine, pure)
-> ``service`` (orchestration over ports) -> ``adapters`` (SQLite) / ``commands``.
"""

from .domain import compile_rule, CompiledRule, RuleError, lint_regex
from .matcher import RuleEngine, RuleHit, AhoCorasick
from .records import build_record

__all__ = ["compile_rule", "CompiledRule", "RuleError", "lint_regex",
           "RuleEngine", "RuleHit", "AhoCorasick", "build_record"]
