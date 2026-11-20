"""Executors: the code that actually performs a tool call the gateway allowed.

Only the gateway should call these. Nothing here checks policy.
Each executor returns a CommandResult. A non-zero exit code means ok=False.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

from guardrail.models import CommandResult, ExecutionError, ToolCall
from guardrail.sandbox import run_in_sandbox

DEFAULT_TIMEOUT_SECONDS = 30
TERRAFORM_ACTIONS = {"plan", "apply", "destroy"}


def _run(argv: list[str], program: str, timeout: float, **kwargs) -> subprocess.CompletedProcess:
    """Run a program. Timeouts propagate to the caller; OS failures become ExecutionError."""
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, **kwargs)
    except FileNotFoundError:
        raise ExecutionError(f"{program} is not installed or not on PATH") from None
    except OSError as exc:
        raise ExecutionError(f"could not run {program}: {exc.strerror or exc}") from None


def format_result(returncode: int, stdout: str, stderr: str) -> CommandResult:
    text = f"exit code: {returncode}\nstdout:\n{stdout}stderr:\n{stderr}"
    return CommandResult(text=text, ok=returncode == 0, summary=f"exit code {returncode}")


def timeout_result(what: str, timeout: float) -> CommandResult:
    return CommandResult(
        text=f"{what} timed out after {timeout} seconds",
        ok=False,
        summary="timed out",
    )


def run_shell(call: ToolCall, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> CommandResult:
    """Run a shell command on this machine (development only; see make_executor)."""
    if call.tool != "shell":
        raise ValueError(f"run_shell cannot execute tool {call.tool!r}")
    command = call.arguments.get("command")
    if not isinstance(command, str):
        raise ValueError("shell call needs a string 'command' argument")

    try:
        result = _run(command, program="shell", timeout=timeout, shell=True)
    except subprocess.TimeoutExpired:
        return timeout_result("command", timeout)

    return format_result(result.returncode, result.stdout, result.stderr)


def _check_plan_path(plan_file: str) -> None:
    if plan_file.startswith("-"):
        raise ValueError("plan_file must not start with '-'")


def run_terraform(call: ToolCall, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> CommandResult:
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
        result = _run(argv, program="terraform", timeout=timeout)
    except subprocess.TimeoutExpired:
        return timeout_result(f"terraform {action}", timeout)

    return format_result(result.returncode, result.stdout, result.stderr)


SHELL_SANDBOX_MODES = {"docker", "none"}


def make_executor(shell_sandbox: str = "docker") -> Callable[[ToolCall], CommandResult]:
    """Build the function that carries out allowed calls.

    shell_sandbox="docker" (default) runs shell commands in a container.
    shell_sandbox="none" runs them directly on this machine. Use only for development.
    """
    if shell_sandbox not in SHELL_SANDBOX_MODES:
        raise ValueError(f"shell_sandbox must be one of {sorted(SHELL_SANDBOX_MODES)}, not {shell_sandbox!r}")

    def execute(call: ToolCall) -> CommandResult:
        if call.tool == "shell":
            if shell_sandbox == "docker":
                return _shell_in_sandbox(call)
            return run_shell(call)
        if call.tool == "terraform":
            return run_terraform(call)
        raise ValueError(f"no executor for tool {call.tool!r}")

    return execute


def _shell_in_sandbox(call: ToolCall) -> CommandResult:
    command = call.arguments.get("command")
    if not isinstance(command, str):
        raise ValueError("shell call needs a string 'command' argument")
    return run_in_sandbox(command)
