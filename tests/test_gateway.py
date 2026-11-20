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


class FakeClock:
    """Time moves only when the gateway sleeps, so waits are instant in tests."""

    def __init__(self):
        self.now = 0.0

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def make_escalating_gateway(tmp_path, respond, timeout=10.0):
    """respond(store, request_ids) is called on each poll, to play the human."""
    from guardrail.approvals import ApprovalStore

    store = ApprovalStore(tmp_path / "approvals")
    audit = AuditLog(tmp_path / "audit.jsonl", clock=lambda: datetime(2026, 11, 20, tzinfo=timezone.utc))
    fake_time = FakeClock()
    executor = FakeExecutor()

    def sleep(seconds):
        fake_time.sleep(seconds)
        respond(store)

    gateway = Gateway(
        Policy(rules=(rule(Decision.ESCALATE),)),
        audit,
        executor,
        approvals=store,
        approval_timeout=timeout,
        poll_interval=1.0,
        sleep=sleep,
        clock=fake_time.clock,
    )
    return gateway, audit, executor, store


def decide_first(approve):
    def respond(store):
        for record in store.list_pending():
            store.decide(record["id"], approve=approve)

    return respond


def test_escalated_call_runs_when_a_person_approves(tmp_path):
    gateway, audit, executor, store = make_escalating_gateway(tmp_path, decide_first(True))

    outcome = gateway.handle(shell("rm -rf /"))

    assert outcome.decision == Decision.ALLOW
    assert outcome.executed is True
    assert executor.calls == [shell("rm -rf /")]
    decisions = [r["decision"] for r in audit.read()]
    assert decisions == ["escalate", "allow"]


def test_escalated_call_is_refused_when_a_person_denies(tmp_path):
    gateway, audit, executor, store = make_escalating_gateway(tmp_path, decide_first(False))

    outcome = gateway.handle(shell("rm -rf /"))

    assert outcome.decision == Decision.BLOCK
    assert outcome.executed is False
    assert "not approved" in outcome.reason and "denied" in outcome.reason
    assert executor.calls == []
    assert [r["decision"] for r in audit.read()] == ["escalate", "block"]


def test_escalated_call_expires_without_an_answer(tmp_path):
    gateway, audit, executor, store = make_escalating_gateway(tmp_path, lambda store: None, timeout=3.0)

    outcome = gateway.handle(shell("rm -rf /"))

    assert outcome.executed is False
    assert "expired" in outcome.reason
    assert executor.calls == []
    request_id = outcome.reason.split("request ")[1].split(":")[0]
    assert store.status(request_id) == "expired"


def test_expired_request_cannot_be_approved_after_the_fact(tmp_path):
    gateway, audit, executor, store = make_escalating_gateway(tmp_path, lambda store: None, timeout=2.0)
    gateway.handle(shell("rm -rf /"))

    assert store.list_pending() == []  # nothing is left open for a person to approve
    (record,) = [store.get(p.stem) for p in store.directory.glob("*.json")]
    assert record["status"] == "expired"
    with pytest.raises(ValueError, match="already expired"):
        store.decide(record["id"], approve=True)
    assert executor.calls == []


def test_escalate_without_approval_store_still_refuses(tmp_path):
    gateway, audit, executor = make_gateway(tmp_path, Policy(rules=(rule(Decision.ESCALATE),)))

    outcome = gateway.handle(shell("rm -rf /"))

    assert outcome.decision == Decision.ESCALATE
    assert outcome.executed is False
    assert executor.calls == []


def test_every_call_is_recorded_in_order(tmp_path):
    gateway, audit, _ = make_gateway(tmp_path, Policy(rules=(rule(Decision.BLOCK),)))

    gateway.handle(shell("ls"))
    gateway.handle(shell("rm -rf /"))

    assert [r["arguments"]["command"] for r in audit.read()] == ["ls", "rm -rf /"]
