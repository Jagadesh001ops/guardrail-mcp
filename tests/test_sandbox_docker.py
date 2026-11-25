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


def test_staged_script_runs_inside_the_container(tmp_path, monkeypatch):
    from guardrail.models import ExecutionError  # noqa: F401
    from guardrail.scripts import fingerprint

    monkeypatch.chdir(tmp_path)
    (tmp_path / "deploy.sh").write_text("echo from-staged-script; id -u\n", encoding="utf-8", newline="\n")
    approved = fingerprint({"command": "sh deploy.sh"})

    result = run_in_sandbox("sh deploy.sh", files=approved)

    assert result.ok is True, result.text
    assert "from-staged-script" in result.text
    assert "65534" in result.text  # still the unprivileged user


def test_staged_script_cannot_modify_itself_or_the_host_file(tmp_path, monkeypatch):
    from guardrail.scripts import fingerprint

    monkeypatch.chdir(tmp_path)
    original = "echo hi >> deploy.sh\n"
    (tmp_path / "deploy.sh").write_text(original, encoding="utf-8", newline="\n")
    approved = fingerprint({"command": "sh deploy.sh"})

    result = run_in_sandbox("sh deploy.sh", files=approved)

    assert result.ok is False  # the append fails: /work is read-only
    assert (tmp_path / "deploy.sh").read_text(encoding="utf-8") == original


def test_other_host_files_stay_invisible(tmp_path, monkeypatch):
    from guardrail.scripts import fingerprint

    monkeypatch.chdir(tmp_path)
    (tmp_path / "deploy.sh").write_text("cat secret.txt\n", encoding="utf-8", newline="\n")
    (tmp_path / "secret.txt").write_text("host secret", encoding="utf-8")
    approved = fingerprint({"command": "sh deploy.sh"})

    result = run_in_sandbox("sh deploy.sh", files=approved)

    assert result.ok is False
    assert "host secret" not in result.text


def test_script_edited_after_approval_is_refused_before_the_container_starts(tmp_path, monkeypatch):
    from guardrail.models import ExecutionError
    from guardrail.scripts import fingerprint

    monkeypatch.chdir(tmp_path)
    script = tmp_path / "deploy.sh"
    script.write_text("echo safe\n", encoding="utf-8", newline="\n")
    approved = fingerprint({"command": "sh deploy.sh"})
    script.write_text("echo tampered\n", encoding="utf-8", newline="\n")

    with pytest.raises(ExecutionError, match="changed after approval"):
        run_in_sandbox("sh deploy.sh", files=approved)


def test_approved_script_runs_end_to_end_through_the_gateway(tmp_path, monkeypatch):
    from guardrail.approvals import ApprovalStore
    from guardrail.audit import AuditLog
    from guardrail.gateway import Gateway
    from guardrail.models import Decision
    from guardrail.policy import Policy, Rule

    monkeypatch.chdir(tmp_path)
    (tmp_path / "deploy.sh").write_text("echo deployed-in-sandbox\n", encoding="utf-8", newline="\n")
    store = ApprovalStore(tmp_path / "approvals")
    audit = AuditLog(tmp_path / "audit.jsonl")
    now = [0.0]

    def sleep(seconds):
        now[0] += seconds
        for record in store.list_pending():
            store.decide(record["id"], approve=True)  # the person approves

    policy = Policy(
        rules=(
            Rule(
                name="escalate-scripts",
                tool="shell",
                matcher="shell.runs_opaque_code",
                decision=Decision.ESCALATE,
                reason="runs a script",
            ),
        )
    )
    gateway = Gateway(
        policy, audit, make_executor("docker"), approvals=store, approval_timeout=10.0,
        poll_interval=1.0, sleep=sleep, clock=lambda: now[0],
    )

    outcome = gateway.handle(ToolCall(tool="shell", arguments={"command": "sh deploy.sh"}))

    assert outcome.executed is True and outcome.failed is False, outcome.output
    assert "deployed-in-sandbox" in outcome.output
    assert [r["decision"] for r in audit.read()] == ["escalate", "allow"]


def test_shell_executor_uses_the_sandbox_by_default():
    execute = make_executor()
    result = execute(ToolCall(tool="shell", arguments={"command": "id -u"}))
    assert "65534" in result.text
