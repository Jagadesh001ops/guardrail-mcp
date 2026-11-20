"""Sandbox command construction and failure handling. These tests do not need Docker."""

import subprocess

import pytest

from guardrail.models import ExecutionError
from guardrail import sandbox


def test_argv_locks_the_container_down():
    argv = sandbox.build_docker_argv("ls", "guardrail-test")
    joined = " ".join(argv)

    assert argv[:2] == ["docker", "run"]
    assert "--network none" in joined
    assert "--read-only" in joined
    assert "--cap-drop ALL" in joined
    assert "no-new-privileges:true" in joined
    assert "--user 65534:65534" in joined  # non-root
    assert "--memory 256m" in joined
    assert "--pids-limit 128" in joined


def test_argv_mounts_no_host_folders():
    argv = sandbox.build_docker_argv("ls", "guardrail-test")
    assert "-v" not in argv and "--volume" not in argv and "--mount" not in argv
    assert not any(a.startswith("type=bind") for a in argv)


def test_command_is_passed_as_a_single_argument_to_sh():
    argv = sandbox.build_docker_argv("echo hi; rm -rf /", "guardrail-test")
    assert argv[-3:] == ["sh", "-c", "echo hi; rm -rf /"]


def test_image_is_pinned_by_default():
    argv = sandbox.build_docker_argv("ls", "guardrail-test")
    assert sandbox.DEFAULT_IMAGE in argv
    assert sandbox.DEFAULT_IMAGE.endswith(":3.20")


def test_missing_docker_is_refused_not_run_on_host(monkeypatch):
    def missing(*a, **k):
        raise FileNotFoundError(2, "not found")

    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(ExecutionError, match="docker is not installed"):
        sandbox.run_in_sandbox("ls")


def test_docker_daemon_failure_is_an_execution_error(monkeypatch):
    def daemon_down(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 125, stdout="", stderr="cannot connect to the Docker daemon")

    monkeypatch.setattr(subprocess, "run", daemon_down)
    with pytest.raises(ExecutionError, match="could not start the sandbox"):
        sandbox.run_in_sandbox("ls")


def test_timeout_kills_the_container(monkeypatch):
    killed = []

    def fake_run(argv, **kwargs):
        if argv[:2] == ["docker", "kill"]:
            killed.append(argv[2])
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", fake_run)
    output = sandbox.run_in_sandbox("sleep 100", timeout=1)

    assert "timed out" in output
    assert len(killed) == 1 and killed[0].startswith("guardrail-")
