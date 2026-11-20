import sys

import pytest

from guardrail.executors import run_shell
from guardrail.models import ToolCall


def shell(command):
    return ToolCall(tool="shell", arguments={"command": command})


def test_captures_stdout_and_zero_exit_code():
    output = run_shell(shell("echo hello"))
    assert "exit code: 0" in output
    assert "hello" in output


def test_captures_nonzero_exit_code_and_stderr():
    command = f'"{sys.executable}" -c "import sys; sys.stderr.write(\'boom\'); sys.exit(3)"'
    output = run_shell(shell(command))
    assert "exit code: 3" in output
    assert "boom" in output


def test_timeout_is_reported_not_raised():
    command = f'"{sys.executable}" -c "import time; time.sleep(5)"'
    output = run_shell(shell(command), timeout=0.5)
    assert "timed out" in output


def test_rejects_other_tools():
    with pytest.raises(ValueError):
        run_shell(ToolCall(tool="terraform", arguments={"command": "plan"}))


def test_rejects_missing_command():
    with pytest.raises(ValueError):
        run_shell(ToolCall(tool="shell", arguments={}))
