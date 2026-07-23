"""Özel capability sözleşmelerini yan etki oluşturmadan değerlendirme servisi."""

from __future__ import annotations

from fnmatch import fnmatchcase

from ajan_kalkani.models import (
    ContractFinding,
    IntentContract,
    PolicyEvaluationItem,
    PolicyEvaluationRequest,
    PolicyEvaluationResponse,
    PolicyEvaluationSummary,
)
from ajan_kalkani.policy import HIGH_RISK_TOOLS, PolicyEngine


_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _matches_any(tool: str, patterns: list[str]) -> bool:
    return any(fnmatchcase(tool, pattern) for pattern in patterns)


def analyze_contract(contract: IntentContract) -> list[ContractFinding]:
    """Yaygın sözleşme hatalarını, gerçek araç çalıştırmadan görünür kılar."""

    findings: list[ContractFinding] = []
    allow = list(dict.fromkeys(contract.allow))
    deny = list(dict.fromkeys(contract.deny))
    approval = list(dict.fromkeys(contract.approval_required))

    if not allow:
        findings.append(
            ContractFinding(
                code="contract.no-allow-rules",
                severity="warning",
                message="İzin listesi boş; korumalı modda bütün araç çağrıları engellenir.",
            )
        )

    if "*" in allow:
        findings.append(
            ContractFinding(
                code="contract.global-allow",
                severity="critical",
                message="'*' bütün capability'leri kapsar ve en az yetki ilkesini bozar.",
                patterns=["*"],
            )
        )

    duplicate_rules = sorted(
        {
            pattern
            for rules in (contract.allow, contract.deny, contract.approval_required)
            for pattern in rules
            if rules.count(pattern) > 1
        }
    )
    if duplicate_rules:
        findings.append(
            ContractFinding(
                code="contract.duplicate-rules",
                severity="info",
                message="Tekrarlanan kurallar davranışı değiştirmez; sözleşme sadeleştirilebilir.",
                patterns=duplicate_rules,
            )
        )

    deny_conflicts = sorted(set(allow) & set(deny))
    if deny_conflicts:
        findings.append(
            ContractFinding(
                code="contract.allow-deny-conflict",
                severity="warning",
                message="Aynı kalıp izin ve ret listesinde; açık ret her zaman kazanır.",
                patterns=deny_conflicts,
            )
        )

    approval_conflicts = sorted(set(allow) & set(approval))
    if approval_conflicts:
        findings.append(
            ContractFinding(
                code="contract.allow-approval-conflict",
                severity="warning",
                message="Aynı kalıp izin ve onay listesinde; onay kuralı izinden önce uygulanır.",
                patterns=approval_conflicts,
            )
        )

    exposed_high_risk = sorted(
        tool
        for tool in HIGH_RISK_TOOLS
        if _matches_any(tool, allow)
        and not _matches_any(tool, deny)
        and not _matches_any(tool, approval)
    )
    if exposed_high_risk:
        findings.append(
            ContractFinding(
                code="contract.high-risk-without-approval",
                severity="critical",
                message="Yüksek etkili capability'ler onay veya açık ret olmadan çalışabilir.",
                patterns=exposed_high_risk,
            )
        )

    broad_rules = sorted(
        pattern
        for pattern in allow
        if pattern != "*" and ("*" in pattern or "?" in pattern)
    )
    if broad_rules:
        findings.append(
            ContractFinding(
                code="contract.broad-allow-pattern",
                severity="warning",
                message="Joker karakterli izinler yeni eklenecek araçları da fark edilmeden kapsayabilir.",
                patterns=broad_rules,
            )
        )

    if approval:
        findings.append(
            ContractFinding(
                code="contract.approval-is-blocking",
                severity="info",
                message="MVP'de gerçek onay akışı yoktur; onay gerektiren çağrılar güvenli biçimde engellenir.",
                patterns=approval,
            )
        )

    return findings


def evaluate_policy(request: PolicyEvaluationRequest) -> PolicyEvaluationResponse:
    """Bir araç çağrısı grubunu aynı sözleşmeye karşı salt-okunur değerlendirir."""

    engine = PolicyEngine()
    results: list[PolicyEvaluationItem] = []
    for position, call in enumerate(request.calls, start=1):
        decision = engine.evaluate(call, request.contract, request.mode)
        results.append(
            PolicyEvaluationItem(
                position=position,
                tool=call.tool,
                origin=call.origin,
                data_labels=sorted(call.data_labels),
                decision=decision,
            )
        )

    risks = [item.decision.risk for item in results]
    highest_risk = max(risks, key=_RISK_ORDER.__getitem__)
    return PolicyEvaluationResponse(
        mode=request.mode,
        summary=PolicyEvaluationSummary(
            total_calls=len(results),
            allowed_calls=sum(item.decision.allowed for item in results),
            blocked_calls=sum(not item.decision.allowed for item in results),
            approval_requests=sum(item.decision.requires_approval for item in results),
            highest_risk=highest_risk,
        ),
        findings=analyze_contract(request.contract),
        results=results,
    )
