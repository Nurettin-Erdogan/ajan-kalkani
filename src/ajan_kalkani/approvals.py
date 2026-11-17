"""Kimlikli, süreli, tek kullanımlı ve parametreye bağlı insan onayı.

Bir onay "bu ajan e-posta gönderebilir" demek değildir; "bu ajan, şu oturumda,
şu alıcıya, şu içerikle, şu süre içinde, bir kez e-posta gönderebilir" demektir.
Runtime gateway (kalıcı SQLite) ve senaryo laboratuvarı (bellek içi simülasyon)
aynı karar fonksiyonunu kullanır; demoda görülen davranış API davranışıyla aynıdır.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from typing import Literal

from ajan_kalkani.models import PolicyDecision, ToolCall


DEFAULT_APPROVAL_TTL_MINUTES = 10

ApprovalStatus = Literal["pending", "approved", "rejected"]


def call_fingerprint(call: ToolCall) -> str:
    """Bir araç çağrısının kanonik SHA-256 özetini döndürür.

    Kanonik biçim: anahtarları sıralı, boşluksuz (`,` ve `:`) ve
    `ensure_ascii=False` JSON. `data_labels` bir küme olduğu için sıralı listeye
    çevrilir: string kümelerinin dolaşım sırası Python süreçleri arasında
    değişebilir (hash randomization) ve sıralanmadığında aynı çağrı farklı
    süreçlerde farklı özet üretir. Onay bu özete bağlandığından, kanonikleştirme
    olmadan meşru onaylar rastgele reddedilirdi.
    """

    payload = call.model_dump(mode="json")
    payload["data_labels"] = sorted(call.data_labels)
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ApprovalState:
    """Karar için gereken asgari onay bilgisi; depolama biçiminden bağımsızdır."""

    id: str
    session_id: str
    request_hash: str
    status: ApprovalStatus
    expires_at: datetime
    consumed: bool = False
    decided_by: str | None = None


def _blocked(rule_id: str, reason: str, risk: Literal["high", "critical"]) -> PolicyDecision:
    return PolicyDecision(allowed=False, reason=reason, rule_id=rule_id, risk=risk)


def evaluate_presented_approval(
    base: PolicyDecision,
    approval: ApprovalState | None,
    *,
    session_id: str,
    request_hash: str,
    now: datetime,
) -> PolicyDecision:
    """Ajanın sunduğu onayla birlikte çağrının nihai kararını verir.

    Onay yalnızca politikanın `requires_approval` dediği çağrıyı açabilir. Açık
    ret, hassas veri çıkışı veya varsayılan ret bir onayla asla ezilmez; zaten
    izinli bir çağrı için sunulan onay ise tüketilmez.

    Kontrol sırası bilinçlidir: önce oturum ve onaylayıcı kararı, sonra süre,
    sonra parametre bağı ve en son tek kullanım. Böylece başka parametrelerle
    yeniden kullanılmak istenen bir onay, daha önce tüketilmiş olsa bile
    `approval.parameters-mismatch` olarak raporlanır ve olay izi saldırıyı doğru
    adlandırır.
    """

    if not base.requires_approval:
        return base
    if approval is None:
        return _blocked("approval.not-found", "Sunulan onay kaydı bulunamadı.", "high")
    if approval.session_id != session_id:
        return _blocked(
            "approval.session-mismatch",
            "Onay başka bir gateway oturumuna ait; oturumlar arasında taşınamaz.",
            "critical",
        )
    if approval.status == "rejected":
        return _blocked(
            "approval.rejected",
            "Onaylayıcı bu çağrıyı reddetti; araç çalıştırılmaz.",
            "high",
        )
    if approval.status == "pending":
        return PolicyDecision(
            allowed=False,
            requires_approval=True,
            reason="Onay henüz verilmedi; onaylayıcının kararı bekleniyor.",
            rule_id="approval.pending",
            risk="high",
        )
    if approval.expires_at <= now:
        return _blocked(
            "approval.expired",
            "Onayın süresi doldu; çağrı için yeni onay istenmeli.",
            "high",
        )
    if approval.request_hash != request_hash:
        return _blocked(
            "approval.parameters-mismatch",
            (
                "Onay farklı parametrelere ait: onaylanan çağrının özeti "
                f"{approval.request_hash[:12]}…, sunulan çağrınınki {request_hash[:12]}…. "
                "Onay belirli bir eyleme bağlıdır; boş çek değildir."
            ),
            "critical",
        )
    if approval.consumed:
        return _blocked(
            "approval.replayed",
            "Bu onay daha önce kullanıldı; tek kullanımlık onay ikinci kez geçerli değildir.",
            "critical",
        )
    approver = approval.decided_by or "bilinmiyor"
    return PolicyDecision(
        allowed=True,
        reason=(
            f"İnsan onayı geçerli (onaylayan: {approver}). Onay yalnızca bu "
            "çağrının birebir parametreleri için verilmişti ve bu kullanımla tüketildi."
        ),
        rule_id="approval.granted",
        risk=base.risk,
    )
