import pytest
from fastapi.testclient import TestClient

from ajan_kalkani.api import app


client = TestClient(app)
APPROVER_TOKEN = "onaylayici-test-jetonu-0123456789abcdef"
AUTH = {"Authorization": f"Bearer {APPROVER_TOKEN}"}
SEND = {
    "tool": "email.send",
    "arguments": {"to": "ayse@example.test", "subject": "Notlar", "password": "gizli-parola"},
    "data_labels": ["internal"],
}


@pytest.fixture(autouse=True)
def isolated_gateway(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AJAN_KALKANI_AUDIT_DB", str(tmp_path / "audit.sqlite3"))
    monkeypatch.setenv("AJAN_KALKANI_APPROVER_TOKEN", APPROVER_TOKEN)
    monkeypatch.setenv("AJAN_KALKANI_APPROVER_NAME", "Ayşe (güvenlik)")


def _session() -> str:
    response = client.post(
        "/api/gateway/sessions",
        json={
            "name": "Onay testi",
            "contract": {
                "task": "Notları Ayşe'ye gönder",
                "allow": ["email.read_latest"],
                "deny": ["file.*"],
                "approval_required": ["email.send", "webhook.*"],
            },
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def _authorize(session_id: str, call: dict, approval_id: str | None = None) -> dict:
    body = {"call": call} if approval_id is None else {"call": call, "approval_id": approval_id}
    response = client.post(f"/api/gateway/sessions/{session_id}/authorize", json=body)
    assert response.status_code == 200
    return response.json()


def test_approval_endpoints_fail_closed_without_a_strong_approver_token(monkeypatch) -> None:
    session_id = _session()
    approval_id = _authorize(session_id, SEND)["approval"]["id"]

    monkeypatch.delenv("AJAN_KALKANI_APPROVER_TOKEN")
    missing = client.post(f"/api/gateway/approvals/{approval_id}/decision", json={"approved": True})
    monkeypatch.setenv("AJAN_KALKANI_APPROVER_TOKEN", "kisa")
    weak = client.post(
        f"/api/gateway/approvals/{approval_id}/decision",
        json={"approved": True},
        headers={"Authorization": "Bearer kisa"},
    )

    assert missing.status_code == 503
    assert weak.status_code == 503
    assert client.get(f"/api/gateway/approvals/{approval_id}").json()["status"] == "pending"


def test_approval_endpoints_require_the_approver_token() -> None:
    session_id = _session()
    approval_id = _authorize(session_id, SEND)["approval"]["id"]

    anonymous = client.post(f"/api/gateway/approvals/{approval_id}/decision", json={"approved": True})
    wrong = client.post(
        f"/api/gateway/approvals/{approval_id}/decision",
        json={"approved": True},
        headers={"Authorization": "Bearer yanlis-jeton-0123456789abcdefghijklmn"},
    )
    queue = client.get("/api/gateway/approvals")

    assert anonymous.status_code == 401
    assert anonymous.headers["www-authenticate"] == "Bearer"
    assert wrong.status_code == 401
    assert queue.status_code == 401


def test_full_human_approval_flow_over_http() -> None:
    session_id = _session()

    requested = _authorize(session_id, SEND)
    approval_id = requested["approval"]["id"]
    queue = client.get("/api/gateway/approvals", headers=AUTH)
    decided = client.post(
        f"/api/gateway/approvals/{approval_id}/decision",
        json={"approved": True, "note": "Alıcı ve içerik doğru."},
        headers=AUTH,
    )
    granted = _authorize(session_id, SEND, approval_id)
    replayed = _authorize(session_id, SEND, approval_id)
    final_state = client.get(f"/api/gateway/approvals/{approval_id}").json()

    assert requested["decision"]["requires_approval"] is True
    assert requested["approval"]["status"] == "pending"
    assert queue.status_code == 200
    assert [item["id"] for item in queue.json()] == [approval_id]
    assert queue.json()[0]["arguments_preview"]["password"] == "[REDACTED]"
    assert "gizli-parola" not in queue.text
    assert decided.status_code == 200
    assert decided.json()["status"] == "approved"
    assert decided.json()["decided_by"] == "Ayşe (güvenlik)"
    assert granted["decision"]["allowed"] is True
    assert granted["decision"]["rule_id"] == "approval.granted"
    assert replayed["decision"]["allowed"] is False
    assert replayed["decision"]["rule_id"] == "approval.replayed"
    assert final_state["status"] == "consumed"
    assert final_state["note"] == "Alıcı ve içerik doğru."


def test_approval_decision_errors_map_to_http_status_codes() -> None:
    session_id = _session()
    approval_id = _authorize(session_id, SEND)["approval"]["id"]
    first = client.post(f"/api/gateway/approvals/{approval_id}/decision", json={"approved": False}, headers=AUTH)
    second = client.post(f"/api/gateway/approvals/{approval_id}/decision", json={"approved": True}, headers=AUTH)
    missing = client.post("/api/gateway/approvals/missing/decision", json={"approved": True}, headers=AUTH)

    assert first.status_code == 200
    assert first.json()["status"] == "rejected"
    assert second.status_code == 409
    assert missing.status_code == 404
    assert client.get("/api/gateway/approvals/missing").status_code == 404


def test_sensitive_egress_is_denied_and_never_reaches_the_approver() -> None:
    session_id = _session()

    decision = _authorize(
        session_id,
        {"tool": "webhook.post", "arguments": {"payload": "PROD_CREDENTIAL_7F3C1"}, "data_labels": ["secret"]},
    )

    assert decision["decision"]["rule_id"] == "dataflow.sensitive-to-external"
    assert decision["approval"] is None
    assert client.get("/api/gateway/approvals?status=all", headers=AUTH).json() == []


def test_openapi_documents_approval_endpoints_and_bearer_scheme() -> None:
    schema = client.get("/openapi.json").json()

    assert {
        "/api/gateway/approvals",
        "/api/gateway/approvals/{approval_id}",
        "/api/gateway/approvals/{approval_id}/decision",
    } <= set(schema["paths"])
    assert schema["components"]["securitySchemes"]["OnaylayiciJetonu"]["scheme"] == "bearer"
