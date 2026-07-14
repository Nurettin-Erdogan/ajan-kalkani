from __future__ import annotations

from fnmatch import fnmatchcase

from agentguard.models import IntentContract, PolicyDecision, RunMode, ToolCall


SENSITIVE_LABELS = {"secret", "credential", "personal", "financial", "sensitive"}
EXTERNAL_SINK_PATTERNS = {
    "webhook.*",
    "email.send",
    "email.forward",
    "payment.*",
    "http.*",
    "network.*",
}
# Kept as a public compatibility constant for adapters that need the common
# concrete sink names. Policy enforcement uses the patterns above.
EXTERNAL_SINKS = {"webhook.post", "email.send", "payment.create", "http.request"}
HIGH_RISK_TOOLS = {
    "calendar.delete_all",
    "email.send",
    "file.delete",
    "payment.create",
    "webhook.post",
}


def _matches(tool: str, patterns: list[str]) -> bool:
    return any(fnmatchcase(tool, pattern) for pattern in patterns)


def is_external_sink(tool: str) -> bool:
    return any(fnmatchcase(tool, pattern) for pattern in EXTERNAL_SINK_PATTERNS)


class PolicyEngine:
    """Deterministic, task-bound authorization for tool calls.

    The model never decides whether its own action is authorized. Rules are
    evaluated outside the agent in a stable order so decisions can be tested.
    """

    def evaluate(
        self,
        call: ToolCall,
        contract: IntentContract,
        mode: RunMode,
    ) -> PolicyDecision:
        if mode == RunMode.UNPROTECTED:
            return PolicyDecision(
                allowed=True,
                reason="Korumasız karşılaştırma modu tüm araç çağrılarını geçirir.",
                rule_id="mode.bypass",
                risk=self._risk_for(call),
            )

        if _matches(call.tool, contract.deny):
            return PolicyDecision(
                allowed=False,
                reason=f"{call.tool} görev sözleşmesinde açıkça yasaklı.",
                rule_id="contract.explicit-deny",
                risk="critical" if call.tool in HIGH_RISK_TOOLS else "high",
            )

        if is_external_sink(call.tool) and call.data_labels & SENSITIVE_LABELS:
            labels = ", ".join(sorted(call.data_labels & SENSITIVE_LABELS))
            return PolicyDecision(
                allowed=False,
                reason=(
                    "Hassas veri harici bir hedefe gönderilemez "
                    f"(etiketler: {labels})."
                ),
                rule_id="dataflow.sensitive-to-external",
                risk="critical",
            )

        if _matches(call.tool, contract.approval_required):
            return PolicyDecision(
                allowed=False,
                requires_approval=True,
                reason=f"{call.tool} için açık kullanıcı onayı gerekli.",
                rule_id="contract.human-approval",
                risk="high",
            )

        if _matches(call.tool, contract.allow):
            return PolicyDecision(
                allowed=True,
                reason=f"{call.tool} bu görevin izin kapsamı içinde.",
                rule_id="contract.allow",
                risk=self._risk_for(call),
            )

        return PolicyDecision(
            allowed=False,
            reason=f"{call.tool} görev sözleşmesinde tanımlı değil; varsayılan ret uygulandı.",
            rule_id="contract.default-deny",
            risk="high",
        )

    @staticmethod
    def _risk_for(call: ToolCall) -> str:
        if call.tool in HIGH_RISK_TOOLS:
            return "critical"
        if call.data_labels & SENSITIVE_LABELS:
            return "high"
        if call.tool.endswith((".read", ".list", ".read_latest")):
            return "low"
        return "medium"
