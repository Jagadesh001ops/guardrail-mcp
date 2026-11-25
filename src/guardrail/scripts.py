"""Files that an escalated shell command will run, and their SHA-256 hashes.

An approval records these hashes. The gateway computes them again after approval
and refuses the call if any file changed in between.

Only host execution can run these files. The Docker sandbox cannot see host files,
so a script-file command fails there before it could run anything.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from guardrail.matchers import _SCRIPT_RUNNERS, _SYSTEM_BIN_PREFIXES, UnparseableInput, _simple_commands

# Options that mean "the code is inline", so there is no file to hash.
_INLINE_CODE_OPTIONS = {"-c", "-e", "-m"}


def referenced_files(command: str) -> list[str]:
    """Paths of script files a command line will run, as written in the command."""
    paths: list[str] = []
    for c in _simple_commands(command):
        program, args = c[0], c[1:]
        if program in {"source", "."} and args:
            paths.append(args[0])
        elif ("/" in program or "\\" in program) and not program.startswith(_SYSTEM_BIN_PREFIXES):
            paths.append(program)
        elif program in _SCRIPT_RUNNERS and not any(a in _INLINE_CODE_OPTIONS for a in args):
            file_args = [a for a in args if not a.startswith("-")]
            if file_args:
                paths.append(file_args[0])
    return paths


def _sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fingerprint(arguments: Mapping[str, Any]) -> dict[str, str | None]:
    """Map each referenced script (absolute path) to its SHA-256, or None if it does not exist.

    Non-shell calls and shell calls without script files give an empty map.
    """
    command = arguments.get("command")
    if not isinstance(command, str):
        return {}
    try:
        written_paths = referenced_files(command)
    except UnparseableInput:
        return {}  # a command the rules cannot parse has no files we can name
    result: dict[str, str | None] = {}
    for written in written_paths:
        path = Path(written).absolute()
        result[str(path)] = _sha256(path)
    return result
