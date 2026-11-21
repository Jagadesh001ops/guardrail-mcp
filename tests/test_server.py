import asyncio
import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp.server.mcpserver.exceptions import ToolError

from guardrail.gateway import Outcome
from guardrail.models import Decision
from guardrail.server import build_server, format_outcome, make_gateway

POLICY = Path(__file__).resolve().parent.parent / "policies" / "default.toml"


def text_of(result):
    return result.content[0].text


def test_format_outcome_for_executed_call():
    assert format_outcome(Outcome(Decision.ALLOW, "ok", True, "hi")) == "hi"


@pytest.mark.parametrize(
    "decision, prefix",
    [
        (Decision.BLOCK, "BLOCKED: "),
        (Decision.DRY_RUN, "DRY RUN ONLY"),
        (Decision.ESCALATE, "REQUIRES HUMAN APPROVAL"),
    ],
)
def test_format_outcome_for_refused_call(decision, prefix):
    text = format_outcome(Outcome(decision, "some reason", False))
    assert text.startswith(prefix)
    assert text.endswith("some reason")


def test_shell_tool_runs_allowed_command(tmp_path):
    # Host execution keeps this test independent of Docker. The sandbox has its own tests.
    server = build_server(make_gateway(POLICY, tmp_path / "audit.jsonl", shell_sandbox="none"))
    result = asyncio.run(server.call_tool("shell", {"command": "echo hello"}))
    assert "hello" in text_of(result)


def test_failing_command_is_reported_as_an_error(tmp_path):
    from mcp.server.mcpserver.exceptions import ToolError

    # A permissive policy: this test is about reporting exit codes, not about the rulebook.
    allow_all = tmp_path / "allow.toml"
    allow_all.write_text('default_decision = "allow"\n', encoding="utf-8")
    server = build_server(make_gateway(allow_all, tmp_path / "audit.jsonl", shell_sandbox="none"))
    command = f'"{sys.executable}" -c "import sys; sys.stderr.write(\'bad\'); sys.exit(3)"'

    with pytest.raises(ToolError, match="exit code: 3") as info:
        asyncio.run(server.call_tool("shell", {"command": command}))
    assert "bad" in str(info.value)


def test_shell_tool_refuses_blocked_command_and_audits_it(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    server = build_server(make_gateway(POLICY, audit_path))

    with pytest.raises(ToolError, match="BLOCKED: "):
        asyncio.run(server.call_tool("shell", {"command": "rm -rf /"}))

    record = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[0])
    assert record["decision"] == "block"
    assert record["rule"] == "block-recursive-forced-rm-of-root"


def test_stdio_client_can_call_tools_end_to_end(tmp_path):
    """Start the real server as a subprocess and talk to it over MCP's stdio transport."""
    audit_path = tmp_path / "audit.jsonl"
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "guardrail.server"],
        env={
            "GUARDRAIL_POLICY": str(POLICY),
            "GUARDRAIL_AUDIT_LOG": str(audit_path),
            "GUARDRAIL_SHELL_SANDBOX": "none",  # keeps this transport test independent of Docker
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        },
    )

    async def scenario():
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                names = [t.name for t in tools.tools]
                allowed = await session.call_tool("shell", {"command": "echo end-to-end"})
                blocked = await session.call_tool("shell", {"command": "rm -rf /"})
                return names, allowed, blocked

    names, allowed, blocked = asyncio.run(scenario())

    assert "shell" in names
    assert allowed.is_error is False
    assert "end-to-end" in text_of(allowed)
    assert blocked.is_error is True
    assert "BLOCKED: recursive forced delete" in text_of(blocked)
    decisions = [json.loads(line)["decision"] for line in audit_path.read_text(encoding="utf-8").splitlines()]
    assert decisions == ["allow", "block"]
