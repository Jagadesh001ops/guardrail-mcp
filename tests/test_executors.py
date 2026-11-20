import subprocess
import sys

import pytest

from guardrail.executors import run_shell
from guardrail.models import ToolCall


def shell(command):
    return ToolCall(tool="shell", arguments={"command": command})


def test_captures_stdout_and_zero_exit_code():
    result = run_shell(shell("echo hello"))
    assert "exit code: 0" in result.text
    assert "hello" in result.text
    assert result.ok is True


def test_captures_nonzero_exit_code_and_stderr():
    command = f'"{sys.executable}" -c "import sys; sys.stderr.write(\'boom\'); sys.exit(3)"'
    result = run_shell(shell(command))
    assert "exit code: 3" in result.text
    assert "boom" in result.text
    assert result.ok is False


def test_timeout_is_reported_not_raised():
    command = f'"{sys.executable}" -c "import time; time.sleep(5)"'
    result = run_shell(shell(command), timeout=0.5)
    assert "timed out" in result.text
    assert result.ok is False


def test_missing_shell_program_is_an_execution_error(monkeypatch):
    from guardrail.models import ExecutionError

    def missing(*a, **k):
        raise FileNotFoundError(2, "not found")

    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(ExecutionError, match="shell is not installed"):
        run_shell(shell("ls"))


def test_rejects_other_tools():
    with pytest.raises(ValueError):
        run_shell(ToolCall(tool="terraform", arguments={"command": "plan"}))


def test_rejects_missing_command():
    with pytest.raises(ValueError):
        run_shell(ToolCall(tool="shell", arguments={}))
