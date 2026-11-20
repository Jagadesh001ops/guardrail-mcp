"""Gateway: the single path every tool call takes.

Order of operations for each call:
  1. the policy evaluates the call,
  2. the decision is written to the audit log,
  3. only an ALLOW decision reaches the executor (the real tool).

Because the audit record is written before anything runs, a decision is kept
even if the executor later fails.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from guardrail.audit import AuditLog
from guardrail.models import Decision, ToolCall
from guardrail.policy import Policy

Executor = Callable[[ToolCall], str]


@dataclass(frozen=True)
class Outcome:
    decision: Decision
    reason: str
    executed: bool
    output: str | None = None


class Gateway:
    def __init__(self, policy: Policy, audit: AuditLog, executor: Executor) -> None:
        self.policy = policy
        self.audit = audit
        self.executor = executor

    def handle(self, call: ToolCall) -> Outcome:
        verdict = self.policy.evaluate(call)
        self.audit.record(call, verdict)

        if verdict.decision == Decision.ALLOW:
            output = self.executor(call)
            return Outcome(Decision.ALLOW, verdict.reason, executed=True, output=output)

        # BLOCK, DRY_RUN and ESCALATE never reach the executor.
        # Dry-run previews and human approval are not built yet, so those
        # outcomes refuse the call and say why.
        return Outcome(verdict.decision, verdict.reason, executed=False)
