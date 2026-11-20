# Guardrail MCP Server

A decision layer between AI agents and the tools they call over MCP.
Every tool call is meant to be allowed, blocked, dry-run, or escalated before it runs.

**Status:** early development. Step 1 (project skeleton) only.

## Development

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest
```
