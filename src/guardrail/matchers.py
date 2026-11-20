"""Built-in detectors that rules in the policy file can refer to by name.

A matcher takes the call's arguments and the rule's params, and returns True
if the call matches. It raises UnparseableInput when it cannot inspect the call,
and the policy engine then fails closed.
"""

from __future__ import annotations

import shlex
from collections.abc import Callable, Mapping
from typing import Any


class UnparseableInput(Exception):
    """Raised when a matcher cannot inspect a call's arguments."""


# Shell operators that separate one simple command from the next.
_SEPARATORS = {";", "&&", "||", "|", "&"}


def _tokenize(command: str) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        return list(lexer)
    except ValueError as exc:
        raise UnparseableInput("command could not be parsed") from exc


def _segments(tokens: list[str]) -> list[list[str]]:
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token in _SEPARATORS:
            segments.append([])
        else:
            segments[-1].append(token)
    return [s for s in segments if s]


def _is_recursive_forced_rm(tokens: list[str], targets: set[str]) -> bool:
    if not tokens or tokens[0] != "rm":
        return False

    recursive = force = False
    found: list[str] = []
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
            found.append(arg)

    return recursive and force and any(t in targets for t in found)


def shell_rm_recursive_force(arguments: Mapping[str, Any], params: Mapping[str, Any]) -> bool:
    """Match a recursive, forced `rm` whose target is in params['targets']."""
    command = arguments.get("command")
    if not isinstance(command, str):
        raise UnparseableInput("shell call has no string 'command' argument")

    targets = set(params["targets"])
    return any(_is_recursive_forced_rm(seg, targets) for seg in _segments(_tokenize(command)))


MATCHERS: dict[str, Callable[[Mapping[str, Any], Mapping[str, Any]], bool]] = {
    "shell.rm_recursive_force": shell_rm_recursive_force,
}

# Parameters each matcher accepts, and whether they are required.
MATCHER_PARAMS: dict[str, dict[str, bool]] = {
    "shell.rm_recursive_force": {"targets": True},
}
