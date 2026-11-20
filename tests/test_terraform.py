"""Terraform rules, executor argv, and the policy/server behaviour for the terraform tool.

Terraform is never actually run here: executor tests replace subprocess.run.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

from guardrail.executors import make_executor, run_terraform
from guardrail.models import Decision, ToolCall
from guardrail.policy import load_policy

POLICY = Path(__file__).resolve().parent.parent / "policies" / "default.toml"


@pytest.fixture(scope="module")
def policy():
    return load_policy(POLICY)


def tf(action, plan_file=None):
    return ToolCall(tool="terraform", arguments={"action": action, "plan_file": plan_file})


# --- Policy rules ---


def test_destroy_is_blocked(policy):
    verdict = policy.evaluate(tf("destroy"))
    assert verdict.decision == Decision.BLOCK
    assert verdict.rule == "block-terraform-destroy"


def test_apply_without_plan_file_is_blocked(policy):
    verdict = policy.evaluate(tf("apply"))
    assert verdict.decision == Decision.BLOCK
    assert verdict.rule == "block-terraform-apply-without-plan"


def test_apply_with_empty_plan_file_is_blocked(policy):
    assert policy.evaluate(tf("apply", "")).decision == Decision.BLOCK


def test_apply_with_plan_file_needs_approval(policy):
    verdict = policy.evaluate(tf("apply", "tfplan"))
    assert verdict.decision == Decision.ESCALATE
    assert verdict.rule == "escalate-terraform-apply"


def test_plan_is_allowed_by_policy(policy):
    assert policy.evaluate(tf("plan")).decision == Decision.ALLOW
    assert policy.evaluate(tf("plan", "tfplan")).decision == Decision.ALLOW


def test_malformed_terraform_call_is_blocked(policy):
    verdict = policy.evaluate(ToolCall(tool="terraform", arguments={"action": ["apply"]}))
    assert verdict.decision == Decision.BLOCK
    assert "could not inspect call" in verdict.reason


# --- Executor argv ---


class Recorder:
    def __init__(self):
        self.argv = None

    def __call__(self, argv, **kwargs):
        self.argv = argv
        assert kwargs.get("shell") is None  # never through a shell
        return subprocess.CompletedProcess(argv, 0, stdout="done\n", stderr="")


@pytest.fixture
def recorder(monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(subprocess, "run", rec)
    return rec


def test_plan_without_file_runs_plain_plan(recorder, tmp_path):
    run_terraform(tf("plan"))
    assert recorder.argv == ["terraform", "plan", "-input=false", "-no-color"]


def test_plan_with_file_saves_the_plan(recorder):
    run_terraform(tf("plan", "tfplan"))
    assert recorder.argv == ["terraform", "plan", "-input=false", "-no-color", "-out=tfplan"]


def test_apply_runs_the_saved_plan_file(recorder, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "tfplan").write_text("plan")
    run_terraform(tf("apply", "tfplan"))
    assert recorder.argv == ["terraform", "apply", "-input=false", "-no-color", "tfplan"]


def test_apply_refuses_missing_plan_file(recorder, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match="not found"):
        run_terraform(tf("apply", "missing"))
    assert recorder.argv is None


def test_apply_without_plan_is_refused_by_executor(recorder):
    with pytest.raises(ValueError, match="saved plan file"):
        run_terraform(tf("apply"))


@pytest.mark.parametrize("bad", ["-auto-approve", "--out=x"])
def test_plan_file_cannot_look_like_an_option(recorder, bad):
    with pytest.raises(ValueError, match="must not start with '-'"):
        run_terraform(tf("plan", bad))


def test_unsupported_action_is_refused(recorder):
    with pytest.raises(ValueError, match="unsupported terraform action"):
        run_terraform(tf("init"))


def test_plan_file_on_destroy_is_refused(recorder):
    with pytest.raises(ValueError, match="only used with plan and apply"):
        run_terraform(tf("destroy", "tfplan"))


def test_missing_terraform_is_an_execution_error(monkeypatch):
    from guardrail.models import ExecutionError

    def missing(*a, **k):
        raise FileNotFoundError(2, "not found")

    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(ExecutionError, match="terraform is not installed or not on PATH"):
        run_terraform(tf("plan"))


def test_executor_dispatches_by_tool_name(recorder):
    execute = make_executor("none")
    assert execute(tf("plan")).startswith("exit code: 0")
    assert recorder.argv[1] == "plan"
    with pytest.raises(ValueError, match="no executor"):
        execute(ToolCall(tool="sql", arguments={}))


# --- Server behaviour (blocked calls never reach Terraform) ---


def test_server_refuses_destroy_and_audits_it(tmp_path, monkeypatch):
    import asyncio

    from mcp.server.mcpserver.exceptions import ToolError

    from guardrail.server import build_server, make_gateway

    def must_not_run(*args, **kwargs):
        raise AssertionError("terraform must not be run for a blocked call")

    monkeypatch.setattr(subprocess, "run", must_not_run)
    audit_path = tmp_path / "audit.jsonl"
    server = build_server(make_gateway(POLICY, audit_path))

    with pytest.raises(ToolError, match="BLOCKED: terraform destroy"):
        asyncio.run(server.call_tool("terraform", {"action": "destroy"}))

    record = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[0])
    assert record["tool"] == "terraform"
    assert record["rule"] == "block-terraform-destroy"


def test_server_refuses_apply_without_plan(tmp_path, monkeypatch):
    import asyncio

    from mcp.server.mcpserver.exceptions import ToolError

    from guardrail.server import build_server, make_gateway

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("ran")))
    server = build_server(make_gateway(POLICY, tmp_path / "audit.jsonl"))

    with pytest.raises(ToolError, match="BLOCKED: terraform apply requires a saved plan"):
        asyncio.run(server.call_tool("terraform", {"action": "apply"}))


def test_server_runs_apply_only_after_a_person_approves(tmp_path, monkeypatch):
    import asyncio
    import threading
    import time

    from guardrail.approvals import ApprovalStore
    from guardrail.server import build_server, make_gateway

    plan = tmp_path / "tfplan"
    plan.write_text("plan")
    monkeypatch.chdir(tmp_path)  # so the plan_file path is relative and inside the temp dir
    ran = []

    def fake_run(argv, **kwargs):
        ran.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="applied\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    approvals_dir = tmp_path / "approvals"
    server = build_server(
        make_gateway(POLICY, tmp_path / "audit.jsonl", approvals_dir=approvals_dir, approval_timeout=10)
    )

    def approver():
        store = ApprovalStore(approvals_dir)
        for _ in range(100):
            pending = store.list_pending()
            if pending:
                store.decide(pending[0]["id"], approve=True)
                return
            time.sleep(0.05)

    thread = threading.Thread(target=approver)
    thread.start()
    result = asyncio.run(server.call_tool("terraform", {"action": "apply", "plan_file": "tfplan"}))
    thread.join()

    assert "applied" in result.content[0].text
    assert ran == [["terraform", "apply", "-input=false", "-no-color", "tfplan"]]


def test_server_refuses_apply_when_nobody_answers(tmp_path, monkeypatch):
    import asyncio

    from mcp.server.mcpserver.exceptions import ToolError

    from guardrail.server import build_server, make_gateway

    (tmp_path / "tfplan").write_text("plan")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("ran")))
    server = build_server(
        make_gateway(POLICY, tmp_path / "audit.jsonl", approvals_dir=tmp_path / "approvals", approval_timeout=0.5)
    )

    with pytest.raises(ToolError, match="not approved"):
        asyncio.run(server.call_tool("terraform", {"action": "apply", "plan_file": "tfplan"}))


def test_server_reports_missing_terraform_as_a_clear_error(tmp_path, monkeypatch):
    import asyncio

    from mcp.server.mcpserver.exceptions import ToolError

    from guardrail.server import build_server, make_gateway

    def missing(*a, **k):
        raise FileNotFoundError(2, "not found")

    monkeypatch.setattr(subprocess, "run", missing)
    audit_path = tmp_path / "audit.jsonl"
    server = build_server(make_gateway(POLICY, audit_path, approvals_dir=tmp_path / "approvals"))

    with pytest.raises(ToolError, match="execution failed: terraform is not installed"):
        asyncio.run(server.call_tool("terraform", {"action": "plan"}))

    reasons = [json.loads(line)["reason"] for line in audit_path.read_text(encoding="utf-8").splitlines()]
    assert reasons[-1].startswith("execution failed: terraform is not installed")


def test_server_lists_terraform_tool(tmp_path):
    import asyncio

    from guardrail.server import build_server, make_gateway

    server = build_server(make_gateway(POLICY, tmp_path / "audit.jsonl"))
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert {"shell", "terraform"} <= names
