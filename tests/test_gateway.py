import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from ajan_kalkani.gateway import GatewaySessionExpiredError, GatewayStore
from ajan_kalkani.models import (
    GatewayAuthorizationRequest,
    GatewaySessionCreate,
    IntentContract,
    ToolCall,
)


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
