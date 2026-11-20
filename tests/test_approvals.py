import json
from datetime import datetime, timezone

import pytest

from guardrail.approvals import APPROVED, DENIED, EXPIRED, PENDING, ApprovalStore
from guardrail.cli import main as cli_main
from guardrail.models import ToolCall

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
CALL = ToolCall(tool="terraform", arguments={"action": "apply", "plan_file": "tfplan"})


def make_store(tmp_path):
    return ApprovalStore(tmp_path / "approvals", clock=lambda: NOW)


def test_create_writes_a_pending_request(tmp_path):
    store = make_store(tmp_path)
    request_id = store.create(CALL, "needs review")

    record = store.get(request_id)
    assert record["status"] == PENDING
    assert record["tool"] == "terraform"
    assert record["arguments"] == {"action": "apply", "plan_file": "tfplan"}
    assert record["reason"] == "needs review"
    assert store.status(request_id) == PENDING


def test_decide_approve_and_deny(tmp_path):
    store = make_store(tmp_path)
    yes = store.create(CALL, "r")
    no = store.create(CALL, "r")

    assert store.decide(yes, approve=True)["status"] == APPROVED
    assert store.decide(no, approve=False)["status"] == DENIED
    assert store.status(yes) == APPROVED
    assert store.status(no) == DENIED


def test_request_can_only_be_decided_once(tmp_path):
    store = make_store(tmp_path)
    request_id = store.create(CALL, "r")
    store.decide(request_id, approve=True)

    with pytest.raises(ValueError, match="already approved"):
        store.decide(request_id, approve=False)


def test_expired_request_cannot_be_approved_later(tmp_path):
    store = make_store(tmp_path)
    request_id = store.create(CALL, "r")
    store.expire(request_id)

    assert store.status(request_id) == EXPIRED
    with pytest.raises(ValueError, match="already expired"):
        store.decide(request_id, approve=True)


@pytest.mark.parametrize("bad_id", ["../etc/passwd", "ABC", "", "xyz", "../../x"])
def test_invalid_ids_are_rejected(tmp_path, bad_id):
    with pytest.raises(ValueError, match="invalid approval id"):
        make_store(tmp_path).get(bad_id)


def test_unknown_id_raises_key_error(tmp_path):
    with pytest.raises(KeyError):
        make_store(tmp_path).get("0" * 32)


def test_list_pending_skips_decided_requests(tmp_path):
    store = make_store(tmp_path)
    done = store.create(CALL, "done")
    open_one = store.create(CALL, "open")
    store.decide(done, approve=True)

    ids = [r["id"] for r in store.list_pending()]
    assert ids == [open_one]


def test_list_pending_on_missing_directory_is_empty(tmp_path):
    assert make_store(tmp_path).list_pending() == []


def test_cli_lists_and_approves(tmp_path, capsys):
    store = make_store(tmp_path)
    request_id = store.create(CALL, "needs review")

    assert cli_main(["--dir", str(tmp_path / "approvals"), "list"]) == 0
    out = capsys.readouterr().out
    assert request_id in out and "needs review" in out

    assert cli_main(["--dir", str(tmp_path / "approvals"), "approve", request_id]) == 0
    assert store.status(request_id) == APPROVED


def test_cli_reports_errors_without_traceback(tmp_path, capsys):
    code = cli_main(["--dir", str(tmp_path / "approvals"), "deny", "0" * 32])
    assert code == 1
    assert "error:" in capsys.readouterr().err


def test_cli_list_with_nothing_pending(tmp_path, capsys):
    assert cli_main(["--dir", str(tmp_path / "none"), "list"]) == 0
    assert "No pending requests." in capsys.readouterr().out


def test_request_file_is_plain_json(tmp_path):
    store = make_store(tmp_path)
    request_id = store.create(CALL, "r")
    raw = (tmp_path / "approvals" / f"{request_id}.json").read_text(encoding="utf-8")
    assert json.loads(raw)["id"] == request_id
