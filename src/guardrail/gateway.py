"""Gateway: the single path every tool call takes.

Order of operations for each call:
  1. the policy evaluates the call,
  2. the decision is written to the audit log,
  3. only an ALLOW decision reaches the executor (the real tool).

An ESCALATE decision waits for a person to approve or deny it (see approvals.py).
If nobody answers before the timeout, the request expires and the call is refused.

Because the audit record is written before anything runs, a decision is kept
even if the executor later fails.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from guardrail.approvals import APPROVED, PENDING, ApprovalStore
from guardrail.audit import AuditLog
from guardrail.models import CommandResult, Decision, ExecutionError, ToolCall
from guardrail.policy import Policy, Verdict

Executor = Callable[[ToolCall], CommandResult]

DEFAULT_APPROVAL_TIMEOUT_SECONDS = 120.0


@dataclass(frozen=True)
class Outcome:
    decision: Decision
    reason: str
    executed: bool
    output: str | None = None
    failed: bool = False  # executed, but the command exited with an error


class Gateway:
    def __init__(
        self,
        policy: Policy,
        audit: AuditLog,
        executor: Executor,
        approvals: ApprovalStore | None = None,
        approval_timeout: float = DEFAULT_APPROVAL_TIMEOUT_SECONDS,
        poll_interval: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.executor = executor
        self.approvals = approvals
        self.approval_timeout = approval_timeout
        self.poll_interval = poll_interval
        self._sleep = sleep
        self._clock = clock

    def handle(self, call: ToolCall) -> Outcome:
        verdict = self.policy.evaluate(call)
        self.audit.record(call, verdict)

        if verdict.decision == Decision.ALLOW:
            return self._execute(call, verdict.decision, verdict.reason, verdict.rule)

        if verdict.decision == Decision.ESCALATE and self.approvals is not None:
            return self._await_approval(call, verdict)

        # BLOCK, DRY_RUN, and ESCALATE without an approval store never reach the executor.
        return Outcome(verdict.decision, verdict.reason, executed=False)

    def _execute(self, call: ToolCall, decision: Decision, reason: str, rule: str | None) -> Outcome:
        try:
            result = self.executor(call)
        except ExecutionError as exc:
            # The policy allowed the call, but it did not run. Say so in the audit log.
            self.audit.record(call, Verdict(decision, f"execution failed: {exc}", rule))
            raise
        return Outcome(decision, reason, executed=True, output=result.text, failed=not result.ok)

    def _await_approval(self, call: ToolCall, verdict: Verdict) -> Outcome:
        request_id = self.approvals.create(call, verdict.reason)
        deadline = self._clock() + self.approval_timeout

        status = self.approvals.status(request_id)
        while status == PENDING and self._clock() < deadline:
            self._sleep(self.poll_interval)
            status = self.approvals.status(request_id)

        if status == PENDING:
            status = self.approvals.expire(request_id)["status"]

        if status == APPROVED:
            reason = f"approved by a person (request {request_id})"
            self.audit.record(call, Verdict(Decision.ALLOW, reason, verdict.rule))
            return self._execute(call, Decision.ALLOW, reason, verdict.rule)

        reason = f"not approved (request {request_id}: {status})"
        self.audit.record(call, Verdict(Decision.BLOCK, reason, verdict.rule))
        return Outcome(Decision.BLOCK, reason, executed=False)
