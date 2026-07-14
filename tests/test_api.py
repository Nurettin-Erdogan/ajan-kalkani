from fastapi.testclient import TestClient

from agentguard.api import app


client = TestClient(app)


def test_health() -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_api_docs_have_an_isolated_asset_policy() -> None:
    response = client.get("/docs")
    assert response.status_code == 200
    assert "https://cdn.jsdelivr.net" in response.headers["content-security-policy"]
    assert "swagger-ui" in response.text.lower()

    dashboard = client.get("/")
    assert "https://cdn.jsdelivr.net" not in dashboard.headers["content-security-policy"]


def test_openapi_contract_contains_all_public_endpoints() -> None:
    schema = client.get("/openapi.json").json()
    paths = schema["paths"]
    assert {"/api/health", "/api/scenarios", "/api/runs", "/api/evaluations"} <= set(paths)

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
