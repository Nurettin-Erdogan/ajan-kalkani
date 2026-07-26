"""Ajan Kalkanı runtime gateway için yalnızca standart kütüphane kullanan örnek."""

from __future__ import annotations

import json
from urllib.request import Request, urlopen


BASE_URL = "http://127.0.0.1:8000"


def post(path: str, payload: dict[str, object]) -> dict[str, object]:
    request = Request(
        f"{BASE_URL}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=5) as response:
        return json.load(response)


session = post(
    "/api/gateway/sessions",
    {
        "name": "E-posta ajanım",
        "ttl_minutes": 30,
        "contract": {
            "task": "Son e-postayı oku ve yalnızca taslak hazırla",
            "allow": ["email.read_latest", "email.create_draft"],
            "deny": ["file.*"],
            "approval_required": ["email.send", "webhook.*"],
        },
    },
)

decision = post(
    f"/api/gateway/sessions/{session['id']}/authorize",
    {
        "call": {
            "tool": "webhook.post",
            "arguments": {"url": "https://example.test", "payload": "saklanmaz"},
            "origin": "my-agent",
            "data_labels": ["secret"],
        }
    },
)

print(json.dumps(decision, ensure_ascii=False, indent=2))
if not decision["decision"]["allowed"]:
    raise SystemExit("Araç çağrısı Ajan Kalkanı tarafından engellendi.")
