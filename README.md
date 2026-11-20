# Guardrail MCP Server

A decision layer between AI agents and the tools they call over MCP.
Every tool call is meant to be allowed, blocked, dry-run, or escalated before it runs.

**Status:** early development. Steps 1–5 done: skeleton, models, rulebook loader, and audit log.

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
