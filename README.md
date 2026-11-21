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

Current rules are in `policies/default.toml`. In summary:
- **Shell, blocked:** recursive forced `rm` of `/`, system directories, or home directories; `find` that deletes files; `dd` or redirects writing to device files; `mkfs`; shutdown and reboot; recursive `chmod`/`chown` on system directories; fork bombs.
- **Shell, seen through wrappers:** these are checked even when hidden behind `sudo`, `env`, `nohup`, `timeout`, `nice`, or `sh -c "..."`.
- **Terraform:** `destroy` is blocked; `apply` without a saved plan is blocked; `apply` of a saved plan needs approval.
- **Everything else is allowed.** This is a deliberate default, so ordinary commands like `ls` still work. The shell sandbox limits what an allowed command can reach.

Known gaps in the shell rules: they look at command text, not what a command does. Command substitution (`rm -rf $(echo /)`), commands that read their targets from input (`... | xargs rm -rf`), and new or unusual syntax can get past them.

## Running the server

```powershell
guardrail-mcp
```

Settings come from environment variables:
- `GUARDRAIL_POLICY`: path to the rulebook (default `policies/default.toml`)
- `GUARDRAIL_AUDIT_LOG`: path to the audit log (default `logs/audit.jsonl`)
- `GUARDRAIL_APPROVALS_DIR`: folder for approval requests (default `approvals/`)
- `GUARDRAIL_APPROVAL_TIMEOUT`: seconds to wait for a decision (default `120`)

## Shell sandbox

Shell commands run in a new Docker container for each call, with no network, a read-only root filesystem, scratch space in `/tmp` and `/work` only, no host folders mounted, a non-root user, no Linux capabilities, and memory, CPU and process limits. Commands time out after 30 seconds, and the container is killed.

- Docker Desktop must be running. If it isn't, shell calls fail with a clear error; they never run on the host.
- Set `GUARDRAIL_SHELL_SANDBOX=none` only for development. It runs shell commands directly on this machine and prints a warning.
- The image is `alpine:3.20`. The first call pulls it.
- Terraform is not sandboxed. It runs on the host, governed by the rules.

## Known limits

- The sandbox is only as strong as Docker and its configuration. It is not a substitute for keeping sensitive data off the machine.
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
