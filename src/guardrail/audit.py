"""Append-only audit log. Every decision is written as one JSON line.

The log is only ever appended to. This module has no way to edit or delete
existing lines.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from guardrail.models import ToolCall
from guardrail.policy import Verdict


class AuditLog:
    def __init__(self, path: str | Path, clock: Callable[[], datetime] | None = None) -> None:
        self.path = Path(path)
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def record(self, call: ToolCall, verdict: Verdict) -> dict:
        """Append one decision to the log and return the record that was written."""
        entry = {
            "timestamp": self._clock().isoformat(),
            "tool": call.tool,
            "arguments": call.arguments,
            "decision": verdict.decision.value,
            "reason": verdict.reason,
            "rule": verdict.rule,
        }
        line = json.dumps(entry, ensure_ascii=False, sort_keys=True)

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
        return entry

    def read(self) -> list[dict]:
        """Return every record in the log, oldest first."""
        if not self.path.exists():
            return []
        with open(self.path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
