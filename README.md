# Guardrail MCP Server

A decision layer between AI agents and the tools they call over MCP.
Every tool call is meant to be allowed, blocked, dry-run, or escalated before it runs.

**Status:** early development. Done so far: project skeleton, decision models, rulebook loader, audit log, gateway, shell executor, and an MCP server exposing a guardrailed `shell` tool. Terraform rules are next.

## How it works

1. An agent calls a tool through the MCP server.
2. The gateway asks the policy (`policies/default.toml`) for a decision.
3. The decision is appended to the audit log (`logs/audit.jsonl` by default).
4. Only an **allow** decision reaches the executor. Blocked, dry-run, and escalated calls return an MCP error that starts with the decision, such as `BLOCKED: ...`.

## Running the server

```powershell
guardrail-mcp
```

Settings come from environment variables:
- `GUARDRAIL_POLICY`: path to the rulebook (default `policies/default.toml`)
- `GUARDRAIL_AUDIT_LOG`: path to the audit log (default `logs/audit.jsonl`)

## Decisions

These were agreed for this learning project:

- **Scope:** shell commands and Terraform (cloud infrastructure).
- **Requests that match no rule:** allowed for now. Revisit once the rulebook is richer.
- **"Escalate" decisions:** a yes/no prompt in the terminal (not built yet).
- **Changing rules:** through pull requests with CI checks.
- **Audit log:** a local, append-only file with one JSON record per decision.
- **Visibility:** public. The project is for learning, so no sensitive data should be used.

## Development

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest
```
