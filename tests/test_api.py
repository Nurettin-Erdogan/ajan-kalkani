from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

from ajan_kalkani.api import app


client = TestClient(app)


def _csp_hosts(policy: str, directive: str) -> set[str]:
    values = next(
        part.strip().split()[1:]
        for part in policy.split(";")
        if part.strip().startswith(f"{directive} ")
    )
    return {
        host
        for value in values
        if (host := urlparse(value).hostname) is not None
    }


@pytest.fixture(autouse=True)
def isolated_audit_database(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AJAN_KALKANI_AUDIT_DB", str(tmp_path / "audit.sqlite3"))


def test_health() -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["version"] == "0.3.0"
    assert response.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_api_docs_have_an_isolated_asset_policy() -> None:
    response = client.get("/docs")
    assert response.status_code == 200
    assert _csp_hosts(response.headers["content-security-policy"], "script-src") == {
        "cdn.jsdelivr.net"
    }
    assert "swagger-ui" in response.text.lower()

    dashboard = client.get("/")
    assert _csp_hosts(
        dashboard.headers["content-security-policy"], "script-src"
    ) == set()
    assert 'href="/static/favicon.svg"' in dashboard.text
    assert client.get("/static/favicon.svg").status_code == 200


def test_dashboard_supports_head_requests() -> None:
    response = client.head("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.content == b""


def test_openapi_contract_contains_all_public_endpoints() -> None:
    schema = client.get("/openapi.json").json()
    paths = schema["paths"]
    assert {
        "/api/health",
        "/api/scenarios",
        "/api/runs",
        "/api/evaluations",
        "/api/policy/evaluate",
        "/api/gateway/sessions",
        "/api/gateway/sessions/{session_id}",
        "/api/gateway/sessions/{session_id}/authorize",
        "/api/gateway/sessions/{session_id}/decisions",
        "/api/audit/runs",
        "/api/audit/runs/{run_id}",
        "/api/audit/evaluations",
        "/api/audit/integrity",
    } <= set(paths)

    scenarios_schema = paths["/api/scenarios"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]
    assert scenarios_schema["items"]["$ref"].endswith("/ScenarioSummary")


def test_scenarios_and_comparison_run() -> None:
    scenarios_response = client.get("/api/scenarios")
    assert scenarios_response.status_code == 200
    scenarios = scenarios_response.json()
    assert len(scenarios) >= 3

    scenario_id = next(
        item["id"] for item in scenarios if item["id"] == "email_prompt_injection"
    )
    baseline = client.post(
        "/api/runs",
        json={"scenario_id": scenario_id, "mode": "unprotected"},
    )
    guarded = client.post(
        "/api/runs",
        json={"scenario_id": scenario_id, "mode": "guarded"},
    )

    assert baseline.status_code == 200
    assert guarded.status_code == 200
    assert baseline.json()["attack_success"] is True
    assert guarded.json()["attack_success"] is False
    assert "PROD_CREDENTIAL_7F3C1" not in baseline.text
    assert "PROD_CREDENTIAL_7F3C1" not in guarded.text


def test_unknown_scenario_returns_404() -> None:
    response = client.post(
        "/api/runs",
        json={"scenario_id": "does-not-exist", "mode": "guarded"},
    )
    assert response.status_code == 404


def test_evaluation_endpoint_runs_the_agent_ci_suite() -> None:
    response = client.post("/api/evaluations")

    assert response.status_code == 200
    payload = response.json()
    assert payload["passed"] is True
    assert payload["metrics"]["scenario_count"] >= 3
    assert payload["metrics"]["guarded_attack_success_rate"] == 0.0
    assert len(payload["comparisons"]) == payload["metrics"]["scenario_count"]
    assert response.headers["cache-control"] == "no-store"


def test_run_history_endpoints_return_redacted_persisted_result() -> None:
    created = client.post(
        "/api/runs",
        json={"scenario_id": "email_prompt_injection", "mode": "unprotected"},
    )
    assert created.status_code == 200

    history = client.get("/api/audit/runs?limit=5")
    assert history.status_code == 200
    assert history.json()[0]["id"] == created.json()["id"]
    assert "PROD_CREDENTIAL_7F3C1" not in history.text

    loaded = client.get(f"/api/audit/runs/{created.json()['id']}")
    assert loaded.status_code == 200
    assert loaded.json()["id"] == created.json()["id"]
    assert "PROD_CREDENTIAL_7F3C1" not in loaded.text

    missing = client.get("/api/audit/runs/not-a-real-run")
    assert missing.status_code == 404

    integrity = client.get("/api/audit/integrity")
    assert integrity.status_code == 200
    assert integrity.json()["valid"] is True
    assert integrity.json()["run_count"] == 1

    invalid_limit = client.get("/api/audit/runs?limit=101")
    assert invalid_limit.status_code == 422


def test_policy_laboratory_endpoint_evaluates_custom_contract() -> None:
    response = client.post(
        "/api/policy/evaluate",
        json={
            "contract": {
                "task": "Dosyayı incele",
                "allow": ["file.read", "webhook.*"],
                "deny": [],
                "approval_required": [],
            },
            "calls": [
                {"tool": "file.read", "data_labels": ["secret"]},
                {"tool": "webhook.post", "data_labels": ["secret"]},
            ],
            "mode": "guarded",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["allowed_calls"] == 1
    assert payload["summary"]["blocked_calls"] == 1
    assert payload["results"][1]["decision"]["rule_id"] == "dataflow.sensitive-to-external"
    assert any(
        item["code"] == "contract.broad-allow-pattern"
        for item in payload["findings"]
    )


def test_policy_laboratory_rejects_empty_or_oversized_batches() -> None:
    base = {
        "contract": {"task": "Test", "allow": []},
        "mode": "guarded",
    }
    empty = client.post("/api/policy/evaluate", json={**base, "calls": []})
    oversized = client.post(
        "/api/policy/evaluate",
        json={**base, "calls": [{"tool": "calendar.list"}] * 51},
    )

    assert empty.status_code == 422
    assert oversized.status_code == 422


def test_runtime_gateway_session_authorizes_and_audits_calls() -> None:
    created = client.post(
        "/api/gateway/sessions",
        json={
            "name": "Test ajanı",
            "contract": {
                "task": "E-posta taslağı hazırla",
                "allow": ["email.read_latest"],
                "deny": ["file.*"],
                "approval_required": ["email.send"],
            },
            "ttl_minutes": 15,
        },
    )
    assert created.status_code == 201
    session_id = created.json()["id"]

    allowed = client.post(
        f"/api/gateway/sessions/{session_id}/authorize",
        json={"call": {"tool": "email.read_latest"}},
    )
    blocked = client.post(
        f"/api/gateway/sessions/{session_id}/authorize",
        json={
            "call": {
                "tool": "file.read",
                "arguments": {"path": "/secret"},
                "data_labels": ["secret"],
            }
        },
    )

    assert allowed.status_code == 200
    assert allowed.json()["decision"]["allowed"] is True
    assert blocked.status_code == 200
    assert blocked.json()["decision"]["rule_id"] == "contract.explicit-deny"
    assert len(blocked.json()["request_hash"]) == 64
    assert "/secret" not in blocked.text

    detail = client.get(f"/api/gateway/sessions/{session_id}")
    decisions = client.get(f"/api/gateway/sessions/{session_id}/decisions")
    sessions = client.get("/api/gateway/sessions")
    assert detail.json()["decision_count"] == 2
    assert [item["sequence"] for item in decisions.json()] == [2, 1]
    assert sessions.json()[0]["id"] == session_id


def test_runtime_gateway_missing_session_and_limits() -> None:
    missing = client.post(
        "/api/gateway/sessions/missing/authorize",
        json={"call": {"tool": "calendar.list"}},
    )
    decisions = client.get("/api/gateway/sessions/missing/decisions")
    invalid_limit = client.get("/api/gateway/sessions?limit=101")

    assert missing.status_code == 404
    assert decisions.status_code == 404
    assert invalid_limit.status_code == 422
