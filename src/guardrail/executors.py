"""Executors: the code that actually performs a tool call the gateway allowed.

Only the gateway should call these. Nothing here checks policy.
"""

from __future__ import annotations

import subprocess

from guardrail.models import ToolCall

DEFAULT_TIMEOUT_SECONDS = 30


def run_shell(call: ToolCall, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> str:
    """Run a shell command and return its exit code, stdout and stderr as text."""
    if call.tool != "shell":
        raise ValueError(f"run_shell cannot execute tool {call.tool!r}")
    command = call.arguments.get("command")
    if not isinstance(command, str):
        raise ValueError("shell call needs a string 'command' argument")

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return f"command timed out after {timeout} seconds"

    return f"exit code: {result.returncode}\nstdout:\n{result.stdout}stderr:\n{result.stderr}"
