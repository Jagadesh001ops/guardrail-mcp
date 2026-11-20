"""guardrail-approvals: list, approve, or deny escalated tool calls.

Run this in your own terminal while the agent is waiting:

    guardrail-approvals list
    guardrail-approvals approve <id>
    guardrail-approvals deny <id>
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from guardrail.approvals import ApprovalStore

DEFAULT_APPROVALS_DIR = "approvals"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardrail-approvals", description=__doc__.split("\n")[0])
    parser.add_argument(
        "--dir",
        default=os.environ.get("GUARDRAIL_APPROVALS_DIR", DEFAULT_APPROVALS_DIR),
        help="approvals directory (default: $GUARDRAIL_APPROVALS_DIR or ./approvals)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="show pending requests")
    for name in ("approve", "deny"):
        p = sub.add_parser(name, help=f"{name} a pending request")
        p.add_argument("request_id")

    args = parser.parse_args(argv)
    store = ApprovalStore(args.dir)

    if args.command == "list":
        pending = store.list_pending()
        if not pending:
            print("No pending requests.")
        for r in pending:
            print(f"{r['id']}  {r['created']}  {r['tool']}  {json.dumps(r['arguments'], sort_keys=True)}")
            print(f"    why: {r['reason']}")
        return 0

    try:
        record = store.decide(args.request_id, approve=args.command == "approve")
    except (KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"{record['id']} {record['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
