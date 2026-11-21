"""Built-in detectors that rules in the policy file can refer to by name.

A matcher takes the call's arguments and the rule's params, and returns True
if the call matches. It raises UnparseableInput when it cannot inspect the call,
and the policy engine then fails closed.

Shell matchers look at each simple command in a command line. They see through
common wrappers (sudo, env, nohup, timeout, ...) and through `sh -c "..."`
nesting, so a dangerous command is not hidden by a prefix.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable, Mapping
from typing import Any


class UnparseableInput(Exception):
    """Raised when a matcher cannot inspect a call's arguments."""


# Shell operators that separate one simple command from the next.
_SEPARATORS = {";", "&&", "||", "|", "&", "(", ")"}

# Commands that run another command given after them.
_WRAPPERS = {"sudo", "doas", "nohup", "nice", "time", "env", "command", "exec", "builtin", "timeout", "stdbuf", "!"}
# Wrapper options that take a separate value, such as `sudo -u root`.
_WRAPPER_VALUE_OPTIONS = {"-u", "-g", "-C"}
_INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh"}
_MAX_NESTING = 5

_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*")
_DURATION = re.compile(r"\d+(\.\d+)?[smhd]?")
_HARMLESS_DEVICES = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/tty"}
_REDIRECTS = {">", ">>", ">|", "&>"}


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


def _strip_wrappers(tokens: list[str]) -> list[str]:
    """Remove leading wrapper commands together with their options and arguments."""
    i = 0
    while i < len(tokens) and tokens[i] in _WRAPPERS:
        i += 1
        while i < len(tokens):
            tok = tokens[i]
            if tok in _WRAPPER_VALUE_OPTIONS:
                i += 2
            elif tok.startswith("-") or _ASSIGNMENT.fullmatch(tok) or _DURATION.fullmatch(tok):
                i += 1
            else:
                break
    return tokens[i:]


def _simple_commands(command: str, depth: int = 0) -> list[list[str]]:
    """Every simple command in a command line, with wrappers removed and `sh -c` unpacked."""
    if depth > _MAX_NESTING:
        raise UnparseableInput("command is nested too deeply to inspect")
    commands: list[list[str]] = []
    for segment in _segments(_tokenize(command)):
        segment = _strip_wrappers(segment)
        if not segment:
            continue
        if segment[0] in _INTERPRETERS:
            # `sh -c "cmd"` (also -lc, -ec, ...): the command string is the next token.
            c_flag = next(
                (i for i, t in enumerate(segment) if i > 0 and t.startswith("-") and not t.startswith("--") and "c" in t),
                None,
            )
            if c_flag is not None:
                if c_flag + 1 < len(segment):
                    commands.extend(_simple_commands(segment[c_flag + 1], depth + 1))
                continue
        commands.append(segment)
    return commands


def _commands_of(arguments: Mapping[str, Any]) -> list[list[str]]:
    command = arguments.get("command")
    if not isinstance(command, str):
        raise UnparseableInput("shell call has no string 'command' argument")
    return _simple_commands(command)


def _is_recursive(args: list[str]) -> bool:
    return any(a == "--recursive" or (a.startswith("-") and not a.startswith("--") and "R" in a) for a in args)


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
    """A recursive, forced `rm` aimed at one of params['targets']."""
    targets = set(params["targets"])
    return any(_is_recursive_forced_rm(c, targets) for c in _commands_of(arguments))


def shell_program_in(arguments: Mapping[str, Any], params: Mapping[str, Any]) -> bool:
    """The program is one of params['programs'] or starts with one of params['prefixes']."""
    programs = set(params.get("programs", []))
    prefixes = tuple(params.get("prefixes", []))
    return any(c[0] in programs or (prefixes and c[0].startswith(prefixes)) for c in _commands_of(arguments))


def shell_find_destructive(arguments: Mapping[str, Any], params: Mapping[str, Any]) -> bool:
    """`find` that deletes files, either with -delete or by running rm/unlink/shred through -exec."""
    for c in _commands_of(arguments):
        if c[0] != "find":
            continue
        if "-delete" in c:
            return True
        if "-exec" in c and any(a in {"rm", "unlink", "shred"} for a in c):
            return True
    return False


def shell_dd_to_device(arguments: Mapping[str, Any], params: Mapping[str, Any]) -> bool:
    """`dd` writing to a device file."""
    return any(
        c[0] == "dd" and any(a.startswith("of=/dev/") and a not in {"of=/dev/null"} for a in c)
        for c in _commands_of(arguments)
    )


def shell_write_to_device(arguments: Mapping[str, Any], params: Mapping[str, Any]) -> bool:
    """A shell redirect (`> /dev/sda`) that writes to a device file."""
    for c in _commands_of(arguments):
        for i, tok in enumerate(c[:-1]):
            if tok in _REDIRECTS and c[i + 1].startswith("/dev/") and c[i + 1] not in _HARMLESS_DEVICES:
                return True
    return False


def shell_recursive_on_targets(arguments: Mapping[str, Any], params: Mapping[str, Any]) -> bool:
    """A recursive command (such as chmod -R) from params['programs'] aimed at one of params['targets']."""
    programs = set(params["programs"])
    targets = set(params["targets"])
    for c in _commands_of(arguments):
        if c[0] in programs and _is_recursive(c[1:]) and any(a in targets for a in c[1:]):
            return True
    return False


def shell_fork_bomb(arguments: Mapping[str, Any], params: Mapping[str, Any]) -> bool:
    """The classic bash fork bomb, ignoring whitespace. Detection is pattern-based, so variants can slip past."""
    command = arguments.get("command")
    if not isinstance(command, str):
        raise UnparseableInput("shell call has no string 'command' argument")
    return ":(){:|:&};:" in re.sub(r"\s+", "", command)


_SCRIPT_RUNNERS = {
    "sh", "bash", "zsh", "dash", "ksh",
    "python", "python3", "py", "node", "perl", "ruby", "php", "pwsh", "powershell",
}
_HARMLESS_RUNNER_ARGS = {"--version", "-V", "-v", "-h", "--help"}
_SYSTEM_BIN_PREFIXES = ("/bin/", "/usr/bin/")


def _runs_opaque_code(command: list[str]) -> bool:
    """True if a simple command runs code the guardrail cannot read: a script file, inline
    code, code read from stdin, a program given by path, or a sourced file."""
    program, args = command[0], command[1:]
    if program in {"source", "."} and args:
        return True
    if ("/" in program or "\\" in program) and not program.startswith(_SYSTEM_BIN_PREFIXES):
        return True
    if program in _SCRIPT_RUNNERS:
        # `sh -c "..."` was already unpacked by _simple_commands, so any runner left here
        # is running a file, inline code, or stdin (no arguments means stdin).
        # Only version and help queries are harmless.
        if not args:
            return True
        return not all(a in _HARMLESS_RUNNER_ARGS for a in args)
    return False


def shell_runs_opaque_code(arguments: Mapping[str, Any], params: Mapping[str, Any]) -> bool:
    """A command runs code the guardrail cannot inspect (see _runs_opaque_code)."""
    return any(_runs_opaque_code(c) for c in _commands_of(arguments))


def _terraform_action(arguments: Mapping[str, Any]) -> str:
    action = arguments.get("action")
    if not isinstance(action, str):
        raise UnparseableInput("terraform call has no string 'action' argument")
    return action


def terraform_action_is(arguments: Mapping[str, Any], params: Mapping[str, Any]) -> bool:
    """Match when the Terraform action is one of params['actions']."""
    return _terraform_action(arguments) in set(params["actions"])


def terraform_apply_without_plan(arguments: Mapping[str, Any], params: Mapping[str, Any]) -> bool:
    """Match an apply that does not point at a saved plan file."""
    action = _terraform_action(arguments)
    plan_file = arguments.get("plan_file")
    if plan_file is not None and not isinstance(plan_file, str):
        raise UnparseableInput("terraform 'plan_file' must be a string")
    return action == "apply" and not plan_file


MATCHERS: dict[str, Callable[[Mapping[str, Any], Mapping[str, Any]], bool]] = {
    "shell.rm_recursive_force": shell_rm_recursive_force,
    "shell.program_in": shell_program_in,
    "shell.find_destructive": shell_find_destructive,
    "shell.dd_to_device": shell_dd_to_device,
    "shell.write_to_device": shell_write_to_device,
    "shell.recursive_on_targets": shell_recursive_on_targets,
    "shell.fork_bomb": shell_fork_bomb,
    "shell.runs_opaque_code": shell_runs_opaque_code,
    "terraform.action_is": terraform_action_is,
    "terraform.apply_without_plan": terraform_apply_without_plan,
}

# Parameters each matcher accepts, and whether they are required.
MATCHER_PARAMS: dict[str, dict[str, bool]] = {
    "shell.rm_recursive_force": {"targets": True},
    "shell.program_in": {"programs": False, "prefixes": False},
    "shell.find_destructive": {},
    "shell.dd_to_device": {},
    "shell.write_to_device": {},
    "shell.recursive_on_targets": {"programs": True, "targets": True},
    "shell.fork_bomb": {},
    "shell.runs_opaque_code": {},
    "terraform.action_is": {"actions": True},
    "terraform.apply_without_plan": {},
}
