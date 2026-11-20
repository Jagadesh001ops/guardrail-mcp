"""Executors: the code that actually performs a tool call the gateway allowed.

Only the gateway should call these. Nothing here checks policy.
"""

from __future__ import annotations

import subprocess

from pathlib import Path

from guardrail.models import ToolCall

DEFAULT_TIMEOUT_SECONDS = 30
TERRAFORM_ACTIONS = {"plan", "apply", "destroy"}


def run_tool(call: ToolCall) -> str:
    """Dispatch an allowed call to the executor for its tool."""
    if call.tool == "shell":
        return run_shell(call)
    if call.tool == "terraform":
        return run_terraform(call)
    raise ValueError(f"no executor for tool {call.tool!r}")


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


def _check_plan_path(plan_file: str) -> None:
    if plan_file.startswith("-"):
        raise ValueError("plan_file must not start with '-'")


def run_terraform(call: ToolCall, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> str:
    """Run a Terraform action. Arguments go in a list, never through a shell."""
    if call.tool != "terraform":
        raise ValueError(f"run_terraform cannot execute tool {call.tool!r}")
    action = call.arguments.get("action")
    if action not in TERRAFORM_ACTIONS:
        raise ValueError(f"unsupported terraform action {action!r}")
    plan_file = call.arguments.get("plan_file")

    base = ["terraform", action, "-input=false", "-no-color"]
    if action == "apply":
        if not plan_file:
            raise ValueError("apply needs a saved plan file")
        _check_plan_path(plan_file)
        if not Path(plan_file).is_file():
            raise ValueError(f"plan file not found: {plan_file}")
        argv = ["terraform", "apply", "-input=false", "-no-color", plan_file]
    elif action == "plan" and plan_file:
        _check_plan_path(plan_file)
        argv = base + [f"-out={plan_file}"]
    else:
        if plan_file:
            raise ValueError(f"plan_file is only used with plan and apply, not {action}")
        argv = base

    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return f"terraform {action} timed out after {timeout} seconds"

    return f"exit code: {result.returncode}\nstdout:\n{result.stdout}stderr:\n{result.stderr}"
