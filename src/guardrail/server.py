"""MCP server: exposes tools to an agent, with every call routed through the gateway.

The agent sees ordinary tools (currently just `shell`). Each call goes through
the policy, the audit log, and only then the executor.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from guardrail.audit import AuditLog
from guardrail.executors import run_tool
from guardrail.gateway import Gateway, Outcome
from guardrail.models import ToolCall
from guardrail.policy import load_policy

DEFAULT_POLICY_PATH = Path("policies") / "default.toml"
DEFAULT_AUDIT_PATH = Path("logs") / "audit.jsonl"


def format_outcome(outcome: Outcome) -> str:
    """Turn a gateway outcome into the text the agent receives."""
    if outcome.executed:
        return outcome.output or ""
    label = {
        "block": "BLOCKED",
        "dry_run": "DRY RUN ONLY (not executed)",
        "escalate": "REQUIRES HUMAN APPROVAL (not executed; approval is not built yet)",
    }.get(outcome.decision.value, outcome.decision.value.upper())
    return f"{label}: {outcome.reason}"


def build_server(gateway: Gateway) -> MCPServer:
    server = MCPServer(
        "guardrail-mcp",
        instructions="Tool calls are checked against a safety policy before they run.",
    )

    def submit(call: ToolCall) -> str:
        outcome = gateway.handle(call)
        if not outcome.executed:
            # Refused calls are errors, so the agent can tell them apart from success.
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
) -> Gateway:
    policy_path = policy_path or os.environ.get("GUARDRAIL_POLICY", DEFAULT_POLICY_PATH)
    audit_path = audit_path or os.environ.get("GUARDRAIL_AUDIT_LOG", DEFAULT_AUDIT_PATH)
    return Gateway(load_policy(policy_path), AuditLog(audit_path), executor=run_tool)


def main() -> None:
    build_server(make_gateway()).run()


if __name__ == "__main__":
    main()
