"""Policy engine: loads rules from a TOML file and decides each tool call.

Rules live in configuration, not code. The file names built-in matchers
(see matchers.py) and says what decision each one produces.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from guardrail.matchers import MATCHER_PARAMS, MATCHERS, UnparseableInput
from guardrail.models import Decision, ToolCall


class PolicyError(ValueError):
    """The policy file is malformed or refers to something that does not exist."""


@dataclass(frozen=True)
class Verdict:
    """The decision for one tool call, plus the reason it was reached.

    `rule` is the name of the rule that decided, or None if the default applied.
    """

    decision: Decision
    reason: str
    rule: str | None = None


@dataclass(frozen=True)
class Rule:
    name: str
    tool: str
    matcher: str
    decision: Decision
    reason: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Policy:
    rules: tuple[Rule, ...]
    default_decision: Decision = Decision.ALLOW

    def evaluate(self, call: ToolCall) -> Verdict:
        for rule in self.rules:
            if rule.tool != call.tool:
                continue
            try:
                matched = MATCHERS[rule.matcher](call.arguments, rule.params)
            except UnparseableInput as exc:
                # Fail closed: a call we cannot inspect is never allowed by default.
                return Verdict(Decision.BLOCK, f"{rule.reason} (could not inspect call: {exc})", rule.name)
            if matched:
                return Verdict(rule.decision, rule.reason, rule.name)
        return Verdict(self.default_decision, "no rule matched")


_TOP_LEVEL_KEYS = {"default_decision", "rules"}
_RULE_KEYS = {"name", "tool", "matcher", "decision", "reason", "params"}


def _parse_decision(value: Any, where: str) -> Decision:
    try:
        return Decision(value)
    except ValueError:
        valid = ", ".join(d.value for d in Decision)
        raise PolicyError(f"{where}: unknown decision {value!r} (expected one of: {valid})") from None


def _parse_rule(raw: Any, index: int) -> Rule:
    where = f"rules[{index}]"
    if not isinstance(raw, dict):
        raise PolicyError(f"{where}: must be a table")

    unknown = set(raw) - _RULE_KEYS
    if unknown:
        raise PolicyError(f"{where}: unknown keys {sorted(unknown)}")

    for key in ("name", "tool", "matcher", "decision", "reason"):
        if key not in raw:
            raise PolicyError(f"{where}: missing required key '{key}'")
        if not isinstance(raw[key], str) or not raw[key].strip():
            raise PolicyError(f"{where}: '{key}' must be a non-empty string")

    name = raw["name"]
    where = f"rule '{name}'"

    matcher = raw["matcher"]
    if matcher not in MATCHERS:
        raise PolicyError(f"{where}: unknown matcher {matcher!r}")

    params = raw.get("params", {})
    if not isinstance(params, dict):
        raise PolicyError(f"{where}: 'params' must be a table")
    allowed = MATCHER_PARAMS[matcher]
    unknown_params = set(params) - set(allowed)
    if unknown_params:
        raise PolicyError(f"{where}: unknown params {sorted(unknown_params)} for matcher {matcher!r}")
    for param, required in allowed.items():
        if required and param not in params:
            raise PolicyError(f"{where}: matcher {matcher!r} requires param '{param}'")

    return Rule(
        name=name,
        tool=raw["tool"],
        matcher=matcher,
        decision=_parse_decision(raw["decision"], where),
        reason=raw["reason"],
        params=dict(params),
    )


def load_policy(path: str | Path) -> Policy:
    """Load and validate a policy file. Raises PolicyError if anything is wrong."""
    with open(path, "rb") as f:
        data = tomllib.load(f)

    unknown = set(data) - _TOP_LEVEL_KEYS
    if unknown:
        raise PolicyError(f"unknown top-level keys {sorted(unknown)}")

    default = _parse_decision(data.get("default_decision", "allow"), "default_decision")

    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise PolicyError("'rules' must be an array of tables")
    rules = tuple(_parse_rule(raw, i) for i, raw in enumerate(raw_rules))

    names = [r.name for r in rules]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise PolicyError(f"duplicate rule names: {duplicates}")

    return Policy(rules=rules, default_decision=default)
