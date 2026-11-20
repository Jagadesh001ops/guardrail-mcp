# Guardrail MCP Server

A decision layer between AI agents and the tools they call over MCP.
Every tool call is meant to be allowed, blocked, dry-run, or escalated before it runs.

**Status:** early development. Done so far: rulebook loader, audit log, gateway, shell and Terraform executors, human approval for escalated calls, and an MCP server exposing `shell` and `terraform` tools. Dry-run previews are not built yet.

## How it works

1. An agent calls a tool through the MCP server.
2. The gateway asks the policy (`policies/default.toml`) for a decision.
3. The decision is appended to the audit log (`logs/audit.jsonl` by default).
4. Only an **allow** decision reaches the executor. Blocked and dry-run calls return an MCP error that starts with the decision, such as `BLOCKED: ...`.
5. An **escalate** decision creates a pending request and waits. A person approves or denies it in their own terminal:

   ```powershell
   guardrail-approvals list
   guardrail-approvals approve <id>
   guardrail-approvals deny <id>
   ```

   If nobody answers before the timeout, the request expires and the call is refused. Expired requests can't be approved later.

Current rules: shell `rm -rf /` is blocked; Terraform `destroy` is blocked; Terraform `apply` without a saved plan is blocked; Terraform `apply` of a saved plan needs approval.

## Running the server

```powershell
guardrail-mcp
```

Settings come from environment variables:
- `GUARDRAIL_POLICY`: path to the rulebook (default `policies/default.toml`)
- `GUARDRAIL_AUDIT_LOG`: path to the audit log (default `logs/audit.jsonl`)
- `GUARDRAIL_APPROVALS_DIR`: folder for approval requests (default `approvals/`)
- `GUARDRAIL_APPROVAL_TIMEOUT`: seconds to wait for a decision (default `120`)

## Known limits

- The shell tool runs commands directly on this machine. There is no sandbox yet.
- While an escalated call waits, that tool call is blocked. Other calls may queue behind it.
- A saved plan file counts as reviewed once a person approves the apply. The guardrail does not check the plan's contents.

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
