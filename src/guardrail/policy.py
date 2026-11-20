"""Policy evaluation. Step 3: one hard-coded rule for shell commands.

Rule: block a recursive, forced `rm` aimed at the filesystem root (`/` or `/*`).
Everything else is allowed for now. Commands that cannot be parsed are blocked
(fail closed), since we cannot judge what they would do.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

from guardrail.models import Decision, ToolCall

# Shell operators that separate one simple command from the next.
_SEPARATORS = {";", "&&", "||", "|", "&"}
_ROOT_TARGETS = {"/", "/*"}


@dataclass(frozen=True)
class Verdict:
    """The decision for one tool call, plus the reason it was reached."""

    decision: Decision
    reason: str


def evaluate(call: ToolCall) -> Verdict:
    """Return the guardrail's decision for a single tool call."""
    if call.tool == "shell":
        return _evaluate_shell(call)
    return Verdict(Decision.ALLOW, "no rule matched")


def _evaluate_shell(call: ToolCall) -> Verdict:
    command = call.arguments.get("command")
    if not isinstance(command, str):
        return Verdict(Decision.BLOCK, "shell call has no string 'command' argument")

    try:
        tokens = _tokenize(command)
    except ValueError:
        return Verdict(Decision.BLOCK, "command could not be parsed")

    for segment in _segments(tokens):
        if _is_recursive_forced_rm_of_root(segment):
            return Verdict(Decision.BLOCK, "recursive forced delete of the filesystem root")

    return Verdict(Decision.ALLOW, "no rule matched")


def _tokenize(command: str) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    return list(lexer)


def _segments(tokens: list[str]) -> list[list[str]]:
    """Split a token list into simple commands at shell operators."""
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token in _SEPARATORS:
            segments.append([])
        else:
            segments[-1].append(token)
    return [s for s in segments if s]


def _is_recursive_forced_rm_of_root(tokens: list[str]) -> bool:
    if not tokens or tokens[0] != "rm":
        return False

    recursive = force = False
    targets: list[str] = []
    for arg in tokens[1:]:
        if arg == "--recursive":
            recursive = True
        elif arg == "--force":
            force = True
        elif arg.startswith("--"):
            continue  # other long options do not change the risk here
        elif arg.startswith("-"):
            recursive = recursive or any(c in "rR" for c in arg[1:])
            force = force or "f" in arg[1:]
        else:
            targets.append(arg)

    return recursive and force and any(t in _ROOT_TARGETS for t in targets)
