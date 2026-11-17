import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest

from ajan_kalkani.gateway import (
    GatewayApprovalConflictError,
    GatewayApprovalExpiredError,
    GatewayApprovalNotFoundError,
    GatewaySessionExpiredError,
    GatewayStore,
)
from ajan_kalkani.models import (
    GatewayAuthorizationRequest,
    GatewaySessionCreate,
    IntentContract,
    ToolCall,
)


SEND_TO_AYSE = ToolCall(
    tool="email.send",
    arguments={
        "to": "ayse@example.test",
        "subject": "Notlar",
        "body": "Notlar ekte.",
        "token": "sk-live-1234567890abcdef",
    },
    data_labels={"internal", "draft"},
)
SEND_TO_ATTACKER = SEND_TO_AYSE.model_copy(
    update={"arguments": {**SEND_TO_AYSE.arguments, "to": "notes@attacker.example"}}
)


def _request(call: ToolCall, approval_id: str | None = None) -> GatewayAuthorizationRequest:
    return GatewayAuthorizationRequest(call=call, approval_id=approval_id)


def _approved_send(store: GatewayStore, session_id: str) -> str:
    pending = store.authorize(session_id, _request(SEND_TO_AYSE))
    assert pending.approval is not None
    store.decide_approval(pending.approval.id, approved=True, approver="Ayşe")
    return pending.approval.id


def _session_request() -> GatewaySessionCreate:
    return GatewaySessionCreate(
        name="E-posta ajanı",
        contract=IntentContract(
            task="E-postayı oku ve taslak hazırla",
            allow=["email.read_latest", "email.create_draft"],
            deny=["file.*"],
            approval_required=["email.send", "webhook.*"],
        ),
        ttl_minutes=30,
    )


def test_gateway_session_persists_immutable_contract(tmp_path) -> None:
    store = GatewayStore(tmp_path / "gateway.sqlite3")
    created = store.create_session(_session_request())
    loaded = store.get_session(created.id)

    assert loaded is not None
    assert loaded.contract == created.contract
    assert loaded.contract_hash == created.contract_hash
    assert len(created.contract_hash) == 64
    assert loaded.status == "active"
    assert loaded.decision_count == 0


def test_gateway_authorizes_and_records_decisions_without_arguments(tmp_path) -> None:
    database = tmp_path / "gateway.sqlite3"
    store = GatewayStore(database)
    session = store.create_session(_session_request())

    allowed = store.authorize(
        session.id,
        GatewayAuthorizationRequest(call=ToolCall(tool="email.read_latest")),
    )
    blocked = store.authorize(
        session.id,
        GatewayAuthorizationRequest(
            call=ToolCall(
                tool="webhook.post",
                arguments={"payload": "PROD_CREDENTIAL_7F3C1"},
                data_labels={"secret"},
            )
        ),
    )

    assert allowed.sequence == 1
    assert allowed.decision.allowed is True
    assert blocked.sequence == 2
    assert blocked.decision.rule_id == "dataflow.sensitive-to-external"
    assert len(blocked.request_hash) == 64
    assert blocked.request_hash != allowed.request_hash
    assert store.get_session(session.id).decision_count == 2
    assert [item.sequence for item in store.list_decisions(session.id)] == [2, 1]

    with sqlite3.connect(database) as connection:
        serialized = json.dumps(connection.execute("SELECT * FROM gateway_decisions").fetchall())
    assert "PROD_CREDENTIAL_7F3C1" not in serialized


def test_gateway_expired_session_cannot_authorize(tmp_path) -> None:
    database = tmp_path / "gateway.sqlite3"
    store = GatewayStore(database)
    session = store.create_session(_session_request())
    expired_at = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE gateway_sessions SET expires_at = ? WHERE id = ?",
            (expired_at, session.id),
        )

    with pytest.raises(GatewaySessionExpiredError):
        store.authorize(
            session.id,
            GatewayAuthorizationRequest(call=ToolCall(tool="email.read_latest")),
        )

    assert store.get_session(session.id).status == "expired"
    assert store.list_decisions(session.id) == []


def test_gateway_session_list_is_newest_first(tmp_path) -> None:
    store = GatewayStore(tmp_path / "gateway.sqlite3")
    first = store.create_session(_session_request())
    second_request = _session_request().model_copy(update={"name": "Takvim ajanı"})
    second = store.create_session(second_request)

    sessions = store.list_sessions()

    assert [item.id for item in sessions] == [second.id, first.id]


def test_approval_required_call_opens_one_idempotent_redacted_approval(tmp_path) -> None:
    database = tmp_path / "gateway.sqlite3"
    store = GatewayStore(database)
    session = store.create_session(_session_request())

    first = store.authorize(session.id, _request(SEND_TO_AYSE))
    second = store.authorize(session.id, _request(SEND_TO_AYSE))

    assert first.decision.allowed is False
    assert first.decision.requires_approval is True
    assert first.approval is not None
    assert first.approval.status == "pending"
    assert second.approval is not None
    assert second.approval.id == first.approval.id

    pending = store.list_approvals("pending")
    assert [item.id for item in pending] == [first.approval.id]
    assert pending[0].request_hash == first.request_hash
    assert pending[0].arguments_preview["to"] == "ayse@example.test"
    assert pending[0].arguments_preview["token"] == "[REDACTED]"

    with sqlite3.connect(database) as connection:
        stored = json.dumps(connection.execute("SELECT * FROM gateway_approvals").fetchall())
    assert "sk-live-1234567890abcdef" not in stored


def test_approved_call_runs_once_and_cannot_be_replayed_or_redirected(tmp_path) -> None:
    store = GatewayStore(tmp_path / "gateway.sqlite3")
    session = store.create_session(_session_request())
    approval_id = _approved_send(store, session.id)

    redirected = store.authorize(session.id, _request(SEND_TO_ATTACKER, approval_id))
    granted = store.authorize(session.id, _request(SEND_TO_AYSE, approval_id))
    replayed = store.authorize(session.id, _request(SEND_TO_AYSE, approval_id))

    assert redirected.decision.allowed is False
    assert redirected.decision.rule_id == "approval.parameters-mismatch"
    assert granted.decision.allowed is True
    assert granted.decision.rule_id == "approval.granted"
    assert "Ayşe" in granted.decision.reason
    assert granted.approval is not None
    assert granted.approval.status == "consumed"
    assert replayed.decision.allowed is False
    assert replayed.decision.rule_id == "approval.replayed"

    approval = store.get_approval(approval_id)
    assert approval is not None
    assert approval.status == "consumed"
    assert approval.decided_by == "Ayşe"
    history = store.list_decisions(session.id)
    assert [item.decision.rule_id for item in history] == [
        "approval.replayed",
        "approval.granted",
        "approval.parameters-mismatch",
        "contract.human-approval",
    ]
    assert {item.approval.id for item in history if item.approval} == {approval_id}


def test_rejected_and_pending_approvals_do_not_authorize(tmp_path) -> None:
    store = GatewayStore(tmp_path / "gateway.sqlite3")
    session = store.create_session(_session_request())
    pending = store.authorize(session.id, _request(SEND_TO_AYSE))
    assert pending.approval is not None

    still_pending = store.authorize(session.id, _request(SEND_TO_AYSE, pending.approval.id))
    store.decide_approval(pending.approval.id, approved=False, approver="Ayşe", note="Alıcı yanlış")
    rejected = store.authorize(session.id, _request(SEND_TO_AYSE, pending.approval.id))

    assert still_pending.decision.rule_id == "approval.pending"
    assert rejected.decision.rule_id == "approval.rejected"
    assert store.get_approval(pending.approval.id).note == "Alıcı yanlış"
    assert store.list_approvals("rejected")[0].id == pending.approval.id


def test_approval_cannot_cross_sessions_or_leak_their_state(tmp_path) -> None:
    store = GatewayStore(tmp_path / "gateway.sqlite3")
    first = store.create_session(_session_request())
    second = store.create_session(_session_request())
    approval_id = _approved_send(store, first.id)

    crossed = store.authorize(second.id, _request(SEND_TO_AYSE, approval_id))

    assert crossed.decision.rule_id == "approval.session-mismatch"
    assert crossed.approval is None
    assert store.get_approval(approval_id).status == "approved"


def test_expired_approval_is_rejected_at_use_and_at_decision_time(tmp_path) -> None:
    database = tmp_path / "gateway.sqlite3"
    store = GatewayStore(database)
    session = store.create_session(_session_request())
    approved_id = _approved_send(store, session.id)
    pending = store.authorize(session.id, _request(SEND_TO_ATTACKER))
    assert pending.approval is not None
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE gateway_approvals SET expires_at = ?", (past,))

    expired_use = store.authorize(session.id, _request(SEND_TO_AYSE, approved_id))

    assert expired_use.decision.rule_id == "approval.expired"
    with pytest.raises(GatewayApprovalExpiredError):
        store.decide_approval(pending.approval.id, approved=True, approver="Ayşe")
    assert {item.id for item in store.list_approvals("expired")} == {approved_id, pending.approval.id}
    assert store.list_approvals("pending") == []


def test_approval_lifetime_never_exceeds_the_session(tmp_path) -> None:
    store = GatewayStore(tmp_path / "gateway.sqlite3", approval_ttl_minutes=120)
    session = store.create_session(_session_request())

    pending = store.authorize(session.id, _request(SEND_TO_AYSE))

    assert pending.approval is not None
    assert pending.approval.expires_at == session.expires_at


def test_decisions_on_missing_or_already_decided_approvals_fail(tmp_path) -> None:
    store = GatewayStore(tmp_path / "gateway.sqlite3")
    session = store.create_session(_session_request())
    approval_id = _approved_send(store, session.id)

    with pytest.raises(GatewayApprovalConflictError):
        store.decide_approval(approval_id, approved=False, approver="Mehmet")
    with pytest.raises(GatewayApprovalNotFoundError):
        store.decide_approval("missing", approved=True, approver="Mehmet")


def test_denied_calls_never_open_an_approval(tmp_path) -> None:
    store = GatewayStore(tmp_path / "gateway.sqlite3")
    session = store.create_session(_session_request())

    exfiltration = store.authorize(
        session.id,
        _request(
            ToolCall(
                tool="webhook.post",
                arguments={"payload": "PROD_CREDENTIAL_7F3C1"},
                data_labels={"secret"},
            )
        ),
    )

    assert exfiltration.decision.rule_id == "dataflow.sensitive-to-external"
    assert exfiltration.approval is None
    assert store.list_approvals("all") == []


def test_parallel_requests_cannot_spend_one_approval_twice(tmp_path) -> None:
    database = tmp_path / "gateway.sqlite3"
    store = GatewayStore(database)
    session = store.create_session(_session_request())
    approval_id = _approved_send(store, session.id)
    barrier = threading.Barrier(4)
    rule_ids: list[str] = []
    lock = threading.Lock()

    def spend() -> None:
        barrier.wait()
        record = GatewayStore(database).authorize(session.id, _request(SEND_TO_AYSE, approval_id))
        with lock:
            rule_ids.append(record.decision.rule_id)

    threads = [threading.Thread(target=spend) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(rule_ids) == ["approval.granted"] + ["approval.replayed"] * 3
