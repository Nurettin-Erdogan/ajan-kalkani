import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest

from ajan_kalkani.approvals import ApprovalState, call_fingerprint, evaluate_presented_approval
from ajan_kalkani.models import PolicyDecision, ToolCall


NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
SEND = ToolCall(
    tool="email.send",
    arguments={"to": "ayse@example.test", "body": "Notlar ekte."},
    data_labels={"internal", "draft", "personal", "untrusted"},
)
APPROVAL_REQUIRED = PolicyDecision(
    allowed=False,
    requires_approval=True,
    reason="email.send için açık kullanıcı onayı gerekli.",
    rule_id="contract.human-approval",
    risk="high",
)


def _approval(**overrides) -> ApprovalState:
    values = {
        "id": "approval-1",
        "session_id": "session-1",
        "request_hash": call_fingerprint(SEND),
        "status": "approved",
        "expires_at": NOW + timedelta(minutes=10),
        "consumed": False,
        "decided_by": "Ayşe (güvenlik)",
    }
    values.update(overrides)
    return ApprovalState(**values)


def _decide(approval: ApprovalState | None, call: ToolCall = SEND, **kwargs) -> PolicyDecision:
    return evaluate_presented_approval(
        kwargs.get("base", APPROVAL_REQUIRED),
        approval,
        session_id=kwargs.get("session_id", "session-1"),
        request_hash=call_fingerprint(call),
        now=kwargs.get("now", NOW),
    )


def test_fingerprint_is_identical_across_processes_with_different_hash_seeds() -> None:
    """Regresyon: etiket kümesi sırası süreçten sürece değişiyordu."""
    script = (
        "from ajan_kalkani.approvals import call_fingerprint\n"
        "from ajan_kalkani.models import ToolCall\n"
        "print(call_fingerprint(ToolCall(tool='email.send', "
        "arguments={'to': 'ayse@example.test', 'body': 'Notlar ekte.'}, "
        "data_labels={'internal', 'draft', 'personal', 'untrusted'})))\n"
    )
    digests = set()
    for seed in ("1", "2", "3", "4", "5"):
        completed = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        digests.add(completed.stdout.strip())

    assert digests == {call_fingerprint(SEND)}


def test_fingerprint_changes_when_any_parameter_changes() -> None:
    swapped = SEND.model_copy(update={"arguments": {**SEND.arguments, "to": "notes@attacker.example"}})
    relabelled = SEND.model_copy(update={"data_labels": {"internal"}})
    other_origin = SEND.model_copy(update={"origin": "untrusted_email"})

    digests = {call_fingerprint(call) for call in (SEND, swapped, relabelled, other_origin)}

    assert len(digests) == 4
    assert all(len(digest) == 64 for digest in digests)


def test_valid_approval_allows_exactly_the_approved_call() -> None:
    decision = _decide(_approval())

    assert decision.allowed is True
    assert decision.rule_id == "approval.granted"
    assert "Ayşe (güvenlik)" in decision.reason


@pytest.mark.parametrize(
    ("approval", "kwargs", "rule_id", "risk"),
    [
        (None, {}, "approval.not-found", "high"),
        (_approval(session_id="session-2"), {}, "approval.session-mismatch", "critical"),
        (_approval(status="rejected"), {}, "approval.rejected", "high"),
        (_approval(status="pending"), {}, "approval.pending", "high"),
        (_approval(), {"now": NOW + timedelta(minutes=10)}, "approval.expired", "high"),
        (_approval(consumed=True), {}, "approval.replayed", "critical"),
    ],
)
def test_invalid_approvals_are_blocked_with_specific_rules(approval, kwargs, rule_id, risk) -> None:
    decision = _decide(approval, **kwargs)

    assert decision.allowed is False
    assert decision.rule_id == rule_id
    assert decision.risk == risk


def test_approval_is_bound_to_parameters_not_to_the_tool() -> None:
    swapped = SEND.model_copy(update={"arguments": {**SEND.arguments, "to": "notes@attacker.example"}})

    decision = _decide(_approval(), call=swapped)

    assert decision.allowed is False
    assert decision.rule_id == "approval.parameters-mismatch"
    assert decision.risk == "critical"


def test_reusing_a_consumed_approval_for_new_parameters_is_reported_as_parameter_misuse() -> None:
    swapped = SEND.model_copy(update={"arguments": {**SEND.arguments, "to": "notes@attacker.example"}})

    decision = _decide(_approval(consumed=True), call=swapped)

    assert decision.rule_id == "approval.parameters-mismatch"


def test_approval_never_overrides_a_deny() -> None:
    deny = PolicyDecision(
        allowed=False,
        reason="Hassas veri harici bir hedefe gönderilemez.",
        rule_id="dataflow.sensitive-to-external",
        risk="critical",
    )

    decision = _decide(_approval(), base=deny)

    assert decision == deny


def test_approval_is_ignored_for_calls_that_are_already_allowed() -> None:
    allow = PolicyDecision(allowed=True, reason="İzinli.", rule_id="contract.allow", risk="low")

    assert _decide(_approval(), base=allow) == allow
