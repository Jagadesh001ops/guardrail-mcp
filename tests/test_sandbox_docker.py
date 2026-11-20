"""Real Docker tests for the shell sandbox. Skipped when Docker is not running."""

import shutil
import subprocess

import pytest

from guardrail.executors import make_executor
from guardrail.models import ToolCall
from guardrail.sandbox import run_in_sandbox


def docker_available():
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


pytestmark = pytest.mark.skipif(not docker_available(), reason="Docker daemon is not running")


def test_command_runs_as_unprivileged_user_in_container():
    output = run_in_sandbox("id -u")
    assert "exit code: 0" in output
    assert "65534" in output


def test_root_filesystem_is_read_only():
    output = run_in_sandbox("touch /etc/guardrail-test && echo WROTE || echo DENIED")
    assert "DENIED" in output
    assert "WROTE" not in output


def test_work_directory_is_writable_scratch_space():
    output = run_in_sandbox("echo scratch > /work/f && cat /work/f")
    assert "scratch" in output


def test_network_is_unreachable():
    output = run_in_sandbox("wget -T 3 -q -O- http://example.com >/dev/null 2>&1 && echo NET || echo OFFLINE")
    assert "OFFLINE" in output
    assert "NET" not in output


def test_destructive_command_only_affects_the_container():
    output = run_in_sandbox("rm -rf / >/dev/null 2>&1; echo finished")
    assert "finished" in output


def test_shell_executor_uses_the_sandbox_by_default():
    execute = make_executor()
    output = execute(ToolCall(tool="shell", arguments={"command": "id -u"}))
    assert "65534" in output
