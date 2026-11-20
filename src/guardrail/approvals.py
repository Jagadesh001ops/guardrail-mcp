"""File-based approval requests for escalated tool calls.

The MCP server cannot prompt in the terminal, because stdin and stdout carry the
MCP protocol. Instead, an escalated call writes a pending request file. A person
approves or denies it from their own terminal with `guardrail-approvals`.

Each request is one JSON file. A decision is written to a temp file and moved
into place, so a reader never sees a half-written request.
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guardrail.models import ToolCall

PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"
EXPIRED = "expired"


class ApprovalStore:
    def __init__(self, directory: str | Path, clock: Callable[[], datetime] | None = None) -> None:
        self.directory = Path(directory)
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _path(self, request_id: str) -> Path:
        # Ids are our own hex strings. Reject anything else so a path can't escape the directory.
        if not request_id or any(c not in "0123456789abcdef" for c in request_id):
            raise ValueError(f"invalid approval id: {request_id!r}")
        return self.directory / f"{request_id}.json"

    def _write(self, request_id: str, record: dict[str, Any]) -> None:
        path = self._path(request_id)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)

    def create(self, call: ToolCall, reason: str) -> str:
        """Record a new pending request and return its id."""
        self.directory.mkdir(parents=True, exist_ok=True)
        request_id = uuid.uuid4().hex
        self._write(
            request_id,
            {
                "id": request_id,
                "created": self._clock().isoformat(),
                "tool": call.tool,
                "arguments": call.arguments,
                "reason": reason,
                "status": PENDING,
            },
        )
        return request_id

    def get(self, request_id: str) -> dict[str, Any]:
        path = self._path(request_id)
        if not path.exists():
            raise KeyError(request_id)
        return json.loads(path.read_text(encoding="utf-8"))

    def status(self, request_id: str) -> str:
        return self.get(request_id)["status"]

    def _finish(self, request_id: str, status: str) -> dict[str, Any]:
        record = self.get(request_id)
        if record["status"] != PENDING:
            raise ValueError(f"request {request_id} is already {record['status']}")
        record["status"] = status
        record["decided"] = self._clock().isoformat()
        self._write(request_id, record)
        return record

    def decide(self, request_id: str, approve: bool) -> dict[str, Any]:
        """A person approves or denies a pending request."""
        return self._finish(request_id, APPROVED if approve else DENIED)

    def expire(self, request_id: str) -> dict[str, Any]:
        """Called by the gateway when nobody answered in time. Expired requests can't be approved later."""
        return self._finish(request_id, EXPIRED)

    def list_pending(self) -> list[dict[str, Any]]:
        if not self.directory.exists():
            return []
        records = [json.loads(p.read_text(encoding="utf-8")) for p in self.directory.glob("*.json")]
        return sorted((r for r in records if r["status"] == PENDING), key=lambda r: r["created"])
