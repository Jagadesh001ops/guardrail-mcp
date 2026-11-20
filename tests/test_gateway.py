from datetime import datetime, timezone

import pytest

from guardrail.audit import AuditLog
from guardrail.gateway import Gateway
from guardrail.models import Decision, ToolCall
from guardrail.policy import Policy, Rule


class FakeExecutor:
    def __init__(self, output="ran"):
        self.calls = []
        self.output = output

    def __call__(self, call):
        self.calls.append(call)
        return self.output


def make_gateway(tmp_path, policy, executor=None):
    audit = AuditLog(tmp_path / "audit.jsonl", clock=lambda: datetime(2026, 11, 20, tzinfo=timezone.utc))
    executor = executor or FakeExecutor()
    return Gateway(policy, audit, executor), audit, executor


def rule(decision, name="r1"):
    return Rule(
        name=name,
        tool="shell",
        matcher="shell.rm_recursive_force",
        decision=decision,
        reason=f"{decision.value} rule",
        params={"targets": ["/"]},
    )


def shell(command):
    return ToolCall(tool="shell", arguments={"command": command})


def test_allowed_call_is_executed_and_audited(tmp_path):
    gateway, audit, executor = make_gateway(tmp_path, Policy(rules=()))

    outcome = gateway.handle(shell("ls"))

    assert outcome.decision == Decision.ALLOW
    assert outcome.executed is True
    assert outcome.output == "ran"
    assert executor.calls == [shell("ls")]
    assert [r["decision"] for r in audit.read()] == ["allow"]


def test_blocked_call_never_reaches_executor(tmp_path):
    gateway, audit, executor = make_gateway(tmp_path, Policy(rules=(rule(Decision.BLOCK),)))

    outcome = gateway.handle(shell("rm -rf /"))

    assert outcome.decision == Decision.BLOCK
    assert outcome.executed is False
    assert outcome.output is None
    assert executor.calls == []
    assert [r["decision"] for r in audit.read()] == ["block"]


@pytest.mark.parametrize("decision", [Decision.DRY_RUN, Decision.ESCALATE])
def test_dry_run_and_escalate_never_reach_executor(tmp_path, decision):
    gateway, audit, executor = make_gateway(tmp_path, Policy(rules=(rule(decision),)))

    outcome = gateway.handle(shell("rm -rf /"))

    assert outcome.decision == decision
    assert outcome.executed is False
    assert executor.calls == []
    assert audit.read()[0]["decision"] == decision.value


def test_audit_is_written_before_executor_runs(tmp_path):
    seen_during_execution = []

    def executor(call):
        seen_during_execution.append(len(audit.read()))
        return "ok"

    gateway, audit, _ = make_gateway(tmp_path, Policy(rules=()), executor=executor)
    gateway.handle(shell("ls"))

    assert seen_during_execution == [1]


def test_every_call_is_recorded_in_order(tmp_path):
    gateway, audit, _ = make_gateway(tmp_path, Policy(rules=(rule(Decision.BLOCK),)))

    gateway.handle(shell("ls"))
    gateway.handle(shell("rm -rf /"))

    assert [r["arguments"]["command"] for r in audit.read()] == ["ls", "rm -rf /"]
