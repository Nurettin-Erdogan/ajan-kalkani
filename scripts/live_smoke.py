#!/usr/bin/env python3
"""Ajan Kalkanı canlı demo duman testi.

Canlı sürümün ayakta olduğunu, depodaki sürümü çalıştırdığını ve ürünün temel
güvenlik vaadini gerçekten uyguladığını doğrular: hassas veriyi okuyan bir
ajanın bu veriyi dış bir uca göndermesi engellenmelidir.

Yalnızca standart kütüphane kullanır; CI'da paket kurmadan çalışır.

    python scripts/live_smoke.py
    LIVE_BASE_URL=http://127.0.0.1:8000 python scripts/live_smoke.py
"""

from __future__ import annotations

import json
import os
import sys
import tomllib
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASE_URL = "https://ajan-kalkani.vercel.app"
EXFILTRATION_RULE = "dataflow.sensitive-to-external"

# Sözleşme iki araca da izin veriyor; buna rağmen gizli etiketli verinin
# webhook'a gitmesi veri akışı kuralıyla engellenmelidir.
EXFILTRATION_PROBE: dict[str, Any] = {
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
}


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)


Fetch = Callable[[str, str, dict[str, Any] | None], Response]


class SmokeFailure(AssertionError):
    """Canlı sürüm beklenen davranışı göstermedi."""


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeFailure(message)


def expected_version() -> str:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(pyproject["project"]["version"])


def run_checks(fetch: Fetch, version: str) -> list[str]:
    """Kontrolleri çalıştırır; geçen kontrollerin adlarını döndürür."""
    passed: list[str] = []

    health = fetch("GET", "/api/health", None)
    expect(health.status == 200, f"/api/health {health.status} döndürdü.")
    payload = health.json()
    expect(payload.get("status") == "ok", f"/api/health durumu {payload.get('status')!r}.")
    expect(
        payload.get("version") == version,
        f"Canlıda {payload.get('version')!r} sürümü çalışıyor, beklenen {version!r}. "
        "Dağıtım eski bir sürümde takılı kalmış olabilir.",
    )
    passed.append(f"/api/health ve sürüm {version}")

    dashboard = fetch("GET", "/", None)
    expect(dashboard.status == 200, f"Dashboard {dashboard.status} döndürdü.")
    expect(
        dashboard.headers.get("content-type", "").startswith("text/html"),
        "Dashboard HTML döndürmedi.",
    )
    expect(
        "frame-ancestors 'none'" in dashboard.headers.get("content-security-policy", ""),
        "Dashboard'un Content-Security-Policy başlığında frame-ancestors 'none' yok.",
    )
    passed.append("dashboard ve Content-Security-Policy")

    probe = fetch("POST", "/api/policy/evaluate", EXFILTRATION_PROBE)
    expect(probe.status == 200, f"/api/policy/evaluate {probe.status} döndürdü.")
    decisions = [item["decision"] for item in probe.json()["results"]]
    expect(len(decisions) == 2, f"İki karar bekleniyordu, {len(decisions)} geldi.")
    expect(decisions[0]["allowed"] is True, "Sözleşmenin izin verdiği file.read engellendi.")
    expect(
        decisions[1]["allowed"] is False and decisions[1]["rule_id"] == EXFILTRATION_RULE,
        "Gizli verinin webhook'a gönderilmesi engellenmedi "
        f"(karar: {decisions[1]['allowed']!r}, kural: {decisions[1]['rule_id']!r}).",
    )
    passed.append("gizli verinin dışarı sızdırılması engelleniyor")

    return passed


def http_fetch(base_url: str, timeout: float) -> Fetch:
    def fetch(method: str, path: str, body: dict[str, Any] | None) -> Response:
        request = urllib.request.Request(
            base_url + path,
            data=None if body is None else json.dumps(body).encode("utf-8"),
            method=method,
            headers={
                "Accept": "application/json, text/html",
                "Content-Type": "application/json",
                "User-Agent": "ajan-kalkani-live-check",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                headers = {key.lower(): value for key, value in response.headers.items()}
                return Response(response.status, headers, response.read())
        except urllib.error.HTTPError as error:
            headers = {key.lower(): value for key, value in error.headers.items()}
            return Response(error.code, headers, error.read())

    return fetch


def main() -> int:
    # Windows konsolu (ör. cp1254) "✓" karakterini yazamaz.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    base_url = os.environ.get("LIVE_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    timeout = float(os.environ.get("LIVE_TIMEOUT_SECONDS", "60"))
    print(f"Kontrol ediliyor: {base_url}")

    try:
        passed = run_checks(http_fetch(base_url, timeout), expected_version())
    except (SmokeFailure, urllib.error.URLError, TimeoutError, ValueError, KeyError) as error:
        print(f"Canlı demo kontrolü başarısız: {error}", file=sys.stderr)
        return 1

    for name in passed:
        print(f"✓ {name}")
    print("Canlı demo kontrolü geçti.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
