"""MCP server: exposes tools to an agent, with every call routed through the gateway.

The agent sees ordinary tools (currently just `shell`). Each call goes through
the policy, the audit log, and only then the executor.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from guardrail.approvals import ApprovalStore
from guardrail.audit import AuditLog
from guardrail.executors import make_executor
from guardrail.gateway import DEFAULT_APPROVAL_TIMEOUT_SECONDS, Gateway, Outcome
from guardrail.models import ExecutionError, ToolCall
from guardrail.policy import load_policy

DEFAULT_POLICY_PATH = Path("policies") / "default.toml"
DEFAULT_AUDIT_PATH = Path("logs") / "audit.jsonl"
DEFAULT_APPROVALS_DIR = Path("approvals")


def format_outcome(outcome: Outcome) -> str:
    """Turn a gateway outcome into the text the agent receives."""
    if outcome.executed:
        return outcome.output or ""
    label = {
        "block": "BLOCKED",
        "dry_run": "DRY RUN ONLY (not executed)",
        "escalate": "REQUIRES HUMAN APPROVAL (not executed; no approval store is configured)",
    }.get(outcome.decision.value, outcome.decision.value.upper())
    return f"{label}: {outcome.reason}"


def build_server(gateway: Gateway) -> MCPServer:
    server = MCPServer(
        "guardrail-mcp",
        instructions="Tool calls are checked against a safety policy before they run.",
    )

    def submit(call: ToolCall) -> str:
        try:
            outcome = gateway.handle(call)
        except ExecutionError as exc:
            raise ToolError(f"execution failed: {exc}") from exc
        if not outcome.executed or outcome.failed:
            # Refused calls and commands that exited non-zero are errors, so the agent
            # can tell them apart from success.
            raise ToolError(format_outcome(outcome))
        return format_outcome(outcome)

    @server.tool()
    def shell(command: str) -> str:
        """Run a shell command. The guardrail policy may block, preview, or escalate it."""
        return submit(ToolCall(tool="shell", arguments={"command": command}))

    @server.tool()
    def terraform(
        action: Literal["plan", "apply", "destroy"],
        plan_file: str | None = None,
    ) -> str:
        """Run a Terraform action. Apply needs a plan_file made by an earlier plan with plan_file set.
        Destroy is blocked by policy."""
        return submit(
            ToolCall(tool="terraform", arguments={"action": action, "plan_file": plan_file})
        )

    return server


def make_gateway(
    policy_path: str | Path | None = None,
    audit_path: str | Path | None = None,
    approvals_dir: str | Path | None = None,
    approval_timeout: float | None = None,
    shell_sandbox: str | None = None,
) -> Gateway:
    policy_path = policy_path or os.environ.get("GUARDRAIL_POLICY", DEFAULT_POLICY_PATH)
    audit_path = audit_path or os.environ.get("GUARDRAIL_AUDIT_LOG", DEFAULT_AUDIT_PATH)
    approvals_dir = approvals_dir or os.environ.get("GUARDRAIL_APPROVALS_DIR", DEFAULT_APPROVALS_DIR)
    shell_sandbox = shell_sandbox or os.environ.get("GUARDRAIL_SHELL_SANDBOX", "docker")
    if approval_timeout is None:
        approval_timeout = float(
            os.environ.get("GUARDRAIL_APPROVAL_TIMEOUT", DEFAULT_APPROVAL_TIMEOUT_SECONDS)
        )
    if shell_sandbox == "none":
        # Writing to stderr keeps stdout free for the MCP protocol.
        sys.stderr.write("WARNING: GUARDRAIL_SHELL_SANDBOX=none; shell commands run on this machine.\n")
    return Gateway(
        load_policy(policy_path),
        AuditLog(audit_path),
        executor=make_executor(shell_sandbox),
        approvals=ApprovalStore(approvals_dir),
        approval_timeout=approval_timeout,
    )


def main() -> None:
    build_server(make_gateway()).run()


if __name__ == "__main__":
    main()
