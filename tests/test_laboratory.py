from ajan_kalkani.laboratory import analyze_contract, evaluate_policy
from ajan_kalkani.models import (
    IntentContract,
    PolicyEvaluationRequest,
    RunMode,
    ToolCall,
)


def test_batch_policy_evaluation_explains_mixed_decisions() -> None:
    request = PolicyEvaluationRequest(
        contract=IntentContract(
            task="E-posta taslağı hazırla",
            allow=["email.read_latest", "email.create_draft"],
            deny=["file.*"],
            approval_required=["email.send"],
        ),
        calls=[
            ToolCall(tool="email.read_latest"),
            ToolCall(tool="file.read", data_labels={"secret"}),
            ToolCall(tool="email.send"),
        ],
    )

    response = evaluate_policy(request)

    assert response.mode == RunMode.GUARDED
    assert response.summary.total_calls == 3
    assert response.summary.allowed_calls == 1
    assert response.summary.blocked_calls == 2
    assert response.summary.approval_requests == 1
    assert response.summary.highest_risk == "high"
    assert [item.decision.rule_id for item in response.results] == [
        "contract.allow",
        "contract.explicit-deny",
        "contract.human-approval",
    ]


def test_sensitive_arguments_are_not_echoed_in_policy_response() -> None:
    request = PolicyEvaluationRequest(
        contract=IntentContract(task="Veriyi işle", allow=["webhook.post"]),
        calls=[
            ToolCall(
                tool="webhook.post",
                arguments={"payload": "PROD_CREDENTIAL_7F3C1"},
                data_labels={"secret"},
            )
        ],
    )

    serialized = evaluate_policy(request).model_dump_json()

    assert "PROD_CREDENTIAL_7F3C1" not in serialized
    assert "dataflow.sensitive-to-external" in serialized


def test_contract_analyzer_flags_dangerous_and_conflicting_rules() -> None:
    findings = analyze_contract(
        IntentContract(
            task="Her şeyi yap",
            allow=["*", "email.send", "email.send"],
            deny=["email.send"],
            approval_required=["*"],
        )
    )
    codes = {finding.code for finding in findings}

    assert "contract.global-allow" in codes
    assert "contract.duplicate-rules" in codes
    assert "contract.allow-deny-conflict" in codes
    assert "contract.allow-approval-conflict" in codes
    assert "contract.approval-is-blocking" in codes


def test_high_risk_allow_without_approval_is_critical() -> None:
    findings = analyze_contract(
        IntentContract(task="E-posta gönder", allow=["email.send"])
    )

    finding = next(
        item for item in findings if item.code == "contract.high-risk-without-approval"
    )
    assert finding.severity == "critical"
    assert finding.patterns == ["email.send"]
