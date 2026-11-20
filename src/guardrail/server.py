"""MCP server: exposes tools to an agent, with every call routed through the gateway.

The agent sees ordinary tools (currently just `shell`). Each call goes through
the policy, the audit log, and only then the executor.
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from guardrail.audit import AuditLog
from guardrail.executors import run_shell
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

    @server.tool()
    def shell(command: str) -> str:
        """Run a shell command. The guardrail policy may block, preview, or escalate it."""
        outcome = gateway.handle(ToolCall(tool="shell", arguments={"command": command}))
        return format_outcome(outcome)

    return server


def make_gateway(
    policy_path: str | Path | None = None,
    audit_path: str | Path | None = None,
) -> Gateway:
    policy_path = policy_path or os.environ.get("GUARDRAIL_POLICY", DEFAULT_POLICY_PATH)
    audit_path = audit_path or os.environ.get("GUARDRAIL_AUDIT_LOG", DEFAULT_AUDIT_PATH)
    return Gateway(load_policy(policy_path), AuditLog(audit_path), executor=run_shell)


def main() -> None:
    build_server(make_gateway()).run()


if __name__ == "__main__":
    main()
