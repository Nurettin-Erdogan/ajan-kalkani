"""Canlı demo duman testinin varsayımlarını uygulamanın kendisine karşı doğrular.

Canlı kontrol (scripts/live_smoke.py) uygulamadan bağımsız çalışır. Bu testler,
uygulama değiştiğinde canlı kontrolün sessizce yanlış şeyi doğrulamaya
başlamasını önler.
"""

import importlib.util
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ajan_kalkani import __version__
from ajan_kalkani.api import app

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "live_smoke.py"
spec = importlib.util.spec_from_file_location("live_smoke", SCRIPT)
assert spec is not None and spec.loader is not None
live_smoke = importlib.util.module_from_spec(spec)
# dataclass, sınıfın modülünü sys.modules üzerinden çözer.
sys.modules[spec.name] = live_smoke
spec.loader.exec_module(live_smoke)

client = TestClient(app)


@pytest.fixture(autouse=True)
def isolated_audit_database(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AJAN_KALKANI_AUDIT_DB", str(tmp_path / "audit.sqlite3"))


def app_fetch(method, path, body):
    response = client.request(method, path, json=body)
    headers = {key.lower(): value for key, value in response.headers.items()}
    return live_smoke.Response(response.status_code, headers, response.content)


def test_live_checks_pass_against_the_application() -> None:
    passed = live_smoke.run_checks(app_fetch, live_smoke.expected_version())

    assert passed == [
        f"/api/health ve sürüm {__version__}",
        "dashboard ve Content-Security-Policy",
        "gizli verinin dışarı sızdırılması engelleniyor",
    ]


def test_pyproject_version_matches_package_version() -> None:
    assert live_smoke.expected_version() == __version__


def test_live_checks_pass_in_public_demo_mode(monkeypatch) -> None:
    monkeypatch.setenv("AJAN_KALKANI_PUBLIC_DEMO", "1")

    assert len(live_smoke.run_checks(app_fetch, __version__)) == 3


def test_stale_deployment_is_reported() -> None:
    with pytest.raises(live_smoke.SmokeFailure, match="takılı kalmış"):
        live_smoke.run_checks(app_fetch, "0.0.0")


def test_missing_exfiltration_block_is_reported() -> None:
    def leaky_fetch(method, path, body):
        response = app_fetch(method, path, body)
        if path != "/api/policy/evaluate":
            return response
        payload = response.json()
        payload["results"][1]["decision"].update(allowed=True, rule_id="allow.contract")
        return live_smoke.Response(
            response.status, response.headers, live_smoke.json.dumps(payload).encode()
        )

    with pytest.raises(live_smoke.SmokeFailure, match="engellenmedi"):
        live_smoke.run_checks(leaky_fetch, __version__)
