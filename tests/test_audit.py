from datetime import datetime, timezone

from guardrail.audit import AuditLog
from guardrail.models import Decision, ToolCall
from guardrail.policy import Verdict

FIXED_TIME = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)


def make_log(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl", clock=lambda: FIXED_TIME)


def test_record_writes_one_json_line_with_all_fields(tmp_path):
    log = make_log(tmp_path)
    call = ToolCall(tool="shell", arguments={"command": "rm -rf /"})
    verdict = Verdict(Decision.BLOCK, "recursive forced delete of the filesystem root", "block-root")

    entry = log.record(call, verdict)

    assert entry == {
        "timestamp": FIXED_TIME.isoformat(),
        "tool": "shell",
        "arguments": {"command": "rm -rf /"},
        "decision": "block",
        "reason": "recursive forced delete of the filesystem root",
        "rule": "block-root",
    }
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1


def test_records_accumulate_and_are_never_overwritten(tmp_path):
    log = make_log(tmp_path)
    allow = Verdict(Decision.ALLOW, "no rule matched")
    block = Verdict(Decision.BLOCK, "blocked", "r1")

    log.record(ToolCall(tool="shell", arguments={"command": "ls"}), allow)
    log.record(ToolCall(tool="shell", arguments={"command": "rm -rf /"}), block)
    log.record(ToolCall(tool="shell", arguments={"command": "pwd"}), allow)

    records = log.read()
    assert [r["arguments"]["command"] for r in records] == ["ls", "rm -rf /", "pwd"]
    assert [r["decision"] for r in records] == ["allow", "block", "allow"]


def test_default_decision_has_no_rule_name(tmp_path):
    log = make_log(tmp_path)
    entry = log.record(ToolCall(tool="shell"), Verdict(Decision.ALLOW, "no rule matched"))
    assert entry["rule"] is None


def test_creates_missing_parent_directories(tmp_path):
    log = AuditLog(tmp_path / "nested" / "dir" / "audit.jsonl", clock=lambda: FIXED_TIME)
    log.record(ToolCall(tool="shell"), Verdict(Decision.ALLOW, "ok"))
    assert log.path.exists()


def test_read_on_missing_log_returns_empty_list(tmp_path):
    assert make_log(tmp_path).read() == []


def test_audit_log_has_no_edit_or_delete_methods(tmp_path):
    log = make_log(tmp_path)
    for name in ("update", "delete", "remove", "clear", "truncate", "edit"):
        assert not hasattr(log, name)
