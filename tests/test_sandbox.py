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


def test_staged_scripts_are_mounted_read_only_as_work(tmp_path):
    argv = sandbox.build_docker_argv("sh deploy.sh", "guardrail-test", stage_dir=tmp_path)
    mount = argv[argv.index("--mount") + 1]

    assert mount == f"type=bind,source={tmp_path},target=/work,readonly"
    assert "/work:rw,size=64m,mode=1777" not in argv  # no writable /work when scripts are staged
    assert "/tmp:rw,size=64m,mode=1777" in argv  # scratch space remains


def test_stage_scripts_copies_verified_bytes(tmp_path):
    import hashlib

    base = tmp_path / "project"
    (base / "tools").mkdir(parents=True)
    script = base / "tools" / "deploy.sh"
    script.write_bytes(b"echo deploy\n")
    dest = tmp_path / "stage"
    dest.mkdir()
    digest = hashlib.sha256(b"echo deploy\n").hexdigest()

    staged = sandbox.stage_scripts({str(script): digest}, base, dest)

    assert staged is True
    assert (dest / "tools" / "deploy.sh").read_bytes() == b"echo deploy\n"


def test_stage_scripts_refuses_a_changed_file(tmp_path):
    import hashlib

    script = tmp_path / "deploy.sh"
    script.write_bytes(b"echo deploy\n")
    approved = hashlib.sha256(b"echo deploy\n").hexdigest()
    script.write_bytes(b"rm -rf ~\n")  # edited after approval
    dest = tmp_path / "stage"
    dest.mkdir()

    with pytest.raises(ExecutionError, match="changed after approval"):
        sandbox.stage_scripts({str(script): approved}, tmp_path, dest)
    assert list(dest.iterdir()) == []  # nothing was copied


def test_stage_scripts_refuses_paths_outside_the_working_directory(tmp_path):
    outside = tmp_path / "outside" / "evil.sh"
    outside.parent.mkdir()
    outside.write_bytes(b"echo hi")
    base = tmp_path / "project"
    base.mkdir()

    with pytest.raises(ExecutionError, match="outside the working directory"):
        sandbox.stage_scripts({str(outside): "0" * 64}, base, tmp_path / "stage")


def test_stage_scripts_skips_files_that_did_not_exist_at_approval(tmp_path):
    dest = tmp_path / "stage"
    dest.mkdir()
    assert sandbox.stage_scripts({str(tmp_path / "missing.sh"): None}, tmp_path, dest) is False


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
    result = sandbox.run_in_sandbox("sleep 100", timeout=1)

    assert "timed out" in result.text
    assert result.ok is False
    assert len(killed) == 1 and killed[0].startswith("guardrail-")
