"""Core data types: the tool call an agent wants to make, and the four possible decisions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ExecutionError(RuntimeError):
    """An allowed call could not be carried out, for example because the program is not installed."""


@dataclass(frozen=True)
class CommandResult:
    """What an executor returns: the text to show, and whether the command succeeded."""

    text: str
    ok: bool


class Decision(str, Enum):
    """What the guardrail decides to do with a tool call."""

    ALLOW = "allow"          # safe: execute it
    BLOCK = "block"          # destructive or disallowed: refuse it
    DRY_RUN = "dry_run"      # show what it would do, without doing it
    ESCALATE = "escalate"    # pause until a human confirms


@dataclass(frozen=True)
class ToolCall:
    """A structured, parsed tool invocation. Arguments are data, never free text."""

    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.tool, str) or not self.tool.strip():
            raise ValueError("ToolCall.tool must be a non-empty string")
        if not isinstance(self.arguments, dict):
            raise TypeError("ToolCall.arguments must be a dict")
