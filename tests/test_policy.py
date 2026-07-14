from agentguard.models import IntentContract, RunMode, ToolCall
from agentguard.policy import PolicyEngine


ENGINE = PolicyEngine()
CONTRACT = IntentContract(
    task="E-posta taslağı hazırla",
    allow=["email.read_latest", "email.create_draft", "webhook.post"],
    deny=["file.read"],
    approval_required=["webhook.*", "email.send"],
)


def test_explicit_deny_has_highest_precedence() -> None:
    decision = ENGINE.evaluate(
        ToolCall(tool="file.read", data_labels={"secret"}),
        CONTRACT,
        RunMode.GUARDED,
    )
    assert decision.allowed is False
    assert decision.rule_id == "contract.explicit-deny"


def test_sensitive_external_flow_precedes_approval() -> None:
    decision = ENGINE.evaluate(
        ToolCall(tool="webhook.post", data_labels={"secret"}),
        CONTRACT,
        RunMode.GUARDED,
    )
    assert decision.allowed is False
    assert decision.requires_approval is False
    assert decision.rule_id == "dataflow.sensitive-to-external"


def test_approval_and_default_deny() -> None:
    approval = ENGINE.evaluate(
        ToolCall(tool="email.send"),
        CONTRACT,
        RunMode.GUARDED,
    )
    unknown = ENGINE.evaluate(
        ToolCall(tool="shell.execute"),
        CONTRACT,
        RunMode.GUARDED,
    )
    assert approval.requires_approval is True
    assert unknown.rule_id == "contract.default-deny"


def test_unprotected_mode_bypasses_contract() -> None:
    decision = ENGINE.evaluate(
        ToolCall(tool="file.read", data_labels={"secret"}),
        CONTRACT,
        RunMode.UNPROTECTED,
    )
    assert decision.allowed is True
    assert decision.rule_id == "mode.bypass"


def test_sensitive_egress_patterns_cover_new_network_tools() -> None:
    contract = IntentContract(
        task="Veriyi işle",
        allow=["network.*", "email.forward", "http.*"],
    )

    for tool in ("network.upload", "email.forward", "http.post"):
        decision = ENGINE.evaluate(
            ToolCall(tool=tool, data_labels={"personal"}),
            contract,
            RunMode.GUARDED,
        )
        assert decision.allowed is False
        assert decision.rule_id == "dataflow.sensitive-to-external"
