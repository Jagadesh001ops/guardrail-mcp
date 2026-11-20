"""Real Docker tests for the shell sandbox. Skipped when Docker is not running."""

import shutil
import subprocess

import pytest

from guardrail.executors import make_executor
from guardrail.models import ToolCall
from guardrail.sandbox import run_in_sandbox


def docker_available():
    """True only for a running Linux engine. Windows-container mode cannot run the Alpine sandbox image."""
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.OSType}}"], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and result.stdout.strip() == "linux"


pytestmark = pytest.mark.skipif(not docker_available(), reason="Docker daemon is not running")


def test_command_runs_as_unprivileged_user_in_container():
    result = run_in_sandbox("id -u")
    assert result.ok is True
    assert "65534" in result.text


def test_root_filesystem_is_read_only():
    output = run_in_sandbox("touch /etc/guardrail-test && echo WROTE || echo DENIED").text
    assert "DENIED" in output
    assert "WROTE" not in output


def test_work_directory_is_writable_scratch_space():
    output = run_in_sandbox("echo scratch > /work/f && cat /work/f").text
    assert "scratch" in output


def test_network_is_unreachable():
    output = run_in_sandbox("wget -T 3 -q -O- http://example.com >/dev/null 2>&1 && echo NET || echo OFFLINE").text
    assert "OFFLINE" in output
    assert "NET" not in output


def test_destructive_command_only_affects_the_container():
    output = run_in_sandbox("rm -rf / >/dev/null 2>&1; echo finished").text
    assert "finished" in output


def test_failing_command_in_container_is_not_ok():
    result = run_in_sandbox("ls /does-not-exist")
    assert result.ok is False
    assert "exit code: 0" not in result.text


def test_shell_executor_uses_the_sandbox_by_default():
    execute = make_executor()
    result = execute(ToolCall(tool="shell", arguments={"command": "id -u"}))
    assert "65534" in result.text
