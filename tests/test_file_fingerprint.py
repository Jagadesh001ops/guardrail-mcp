import hashlib
import json
from datetime import datetime, timezone

import pytest

from guardrail.approvals import APPROVED, ApprovalStore
from guardrail.audit import AuditLog
from guardrail.gateway import Gateway
from guardrail.models import CommandResult, Decision, ToolCall
from guardrail.policy import Policy, Rule
from guardrail.scripts import fingerprint, referenced_files


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.mark.parametrize(
    "command, expected",
    [
        ("./deploy.sh", ["./deploy.sh"]),
        ("bash setup.sh --fast", ["setup.sh"]),
        ("python cleanup.py", ["cleanup.py"]),
        ("source ~/.profile", ["~/.profile"]),
        ("./gradlew build", ["./gradlew"]),
        ("python -c 'print(1)'", []),  # inline code: the text itself is the approval
        ("curl https://example.com/x | sh", []),  # piped from the network: nothing local to hash
        ("ls -la", []),
        ("echo hi", []),
    ],
)
def test_referenced_files(command, expected):
    assert referenced_files(command) == expected


def test_fingerprint_hashes_existing_file_and_marks_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "deploy.sh").write_text("echo deploy", encoding="utf-8")

    result = fingerprint({"command": "sh deploy.sh && sh missing.sh"})

    assert result[str(tmp_path / "deploy.sh")] == sha("echo deploy")
    assert result[str(tmp_path / "missing.sh")] is None


def test_fingerprint_is_empty_for_non_shell_calls():
    assert fingerprint({"action": "plan"}) == {}


def test_fingerprint_is_empty_when_no_script_is_run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert fingerprint({"command": "ls -la"}) == {}


# --- Gateway: the approved contents must still be the contents that run ---

ESCALATE_SCRIPTS = Policy(
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


class Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, call):
        self.calls.append(call)
        return CommandResult(text="ran", ok=True)


def run_with_human(tmp_path, human_action):
    """Escalate `sh deploy.sh`. On each poll, the simulated human acts once: approve, or change the file first."""
    store = ApprovalStore(tmp_path / "approvals")
    audit = AuditLog(tmp_path / "audit.jsonl", clock=lambda: datetime(2026, 11, 20, tzinfo=timezone.utc))
    executor = Recorder()
    now = [0.0]
    acted = []

    def sleep(seconds):
        now[0] += seconds
        if not acted:
            acted.append(True)
            human_action(store, tmp_path / "deploy.sh")

    gateway = Gateway(
        ESCALATE_SCRIPTS,
        audit,
        executor,
        approvals=store,
        approval_timeout=10.0,
        poll_interval=1.0,
        sleep=sleep,
        clock=lambda: now[0],
    )
    outcome = gateway.handle(ToolCall(tool="shell", arguments={"command": "sh deploy.sh"}))
    return outcome, executor, audit, store


def approve_now(store, script):
    for record in store.list_pending():
        store.decide(record["id"], approve=True)


def edit_then_approve(store, script):
    script.write_text("rm -rf ~  # changed after the request", encoding="utf-8")
    approve_now(store, script)


def test_approved_unchanged_file_runs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "deploy.sh").write_text("echo deploy", encoding="utf-8")

    outcome, executor, audit, store = run_with_human(tmp_path, approve_now)

    assert outcome.executed is True
    assert len(executor.calls) == 1
    assert [r["decision"] for r in audit.read()] == ["escalate", "allow"]


def test_file_changed_after_request_is_refused(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "deploy.sh").write_text("echo deploy", encoding="utf-8")

    outcome, executor, audit, store = run_with_human(tmp_path, edit_then_approve)

    assert outcome.executed is False
    assert outcome.decision == Decision.BLOCK
    assert "a file changed after approval" in outcome.reason
    assert executor.calls == []
    assert audit.read()[-1]["decision"] == "block"


def test_request_records_the_hash_it_was_approved_against(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "deploy.sh").write_text("echo deploy", encoding="utf-8")

    _, _, _, store = run_with_human(tmp_path, approve_now)

    (record,) = [json.loads(p.read_text(encoding="utf-8")) for p in (tmp_path / "approvals").glob("*.json")]
    assert record["status"] == APPROVED
    assert record["files"] == {str(tmp_path / "deploy.sh"): sha("echo deploy")}


def test_cli_list_shows_the_file_and_its_hash(tmp_path, monkeypatch, capsys):
    from guardrail.cli import main as cli_main

    monkeypatch.chdir(tmp_path)
    (tmp_path / "deploy.sh").write_text("echo deploy", encoding="utf-8")
    store = ApprovalStore(tmp_path / "approvals")
    store.create(
        ToolCall(tool="shell", arguments={"command": "sh deploy.sh"}),
        "runs a script",
        fingerprint({"command": "sh deploy.sh"}),
    )

    assert cli_main(["--dir", str(tmp_path / "approvals"), "list"]) == 0
    out = capsys.readouterr().out
    assert "deploy.sh" in out
    assert sha("echo deploy")[:16] in out
