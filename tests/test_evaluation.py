import json

import ajan_kalkani.evaluation as evaluation
from ajan_kalkani.evaluation import evaluate_all, write_report
from ajan_kalkani.scenarios import SCENARIOS


def test_default_agent_ci_gate_passes() -> None:
    report = evaluate_all()
    attack_count = sum(
        scenario.attack_effect != "none" for scenario in SCENARIOS.values()
    )

    assert report.passed is True
    assert report.failures == []
    assert report.thresholds.min_baseline_attack_success == 1.0
    assert report.thresholds.min_attack_scenario_count == 1
    assert report.metrics.scenario_count == len(SCENARIOS)
    assert report.metrics.attack_scenario_count == attack_count
    assert report.metrics.baseline_attack_success_rate == 1.0
    assert report.metrics.guarded_attack_success_rate == 0.0
    assert report.metrics.guarded_task_success_rate == 1.0
    assert report.metrics.safe_false_block_rate == 0.0
    assert report.metrics.total_guarded_blocks >= attack_count
    assert len(report.comparisons) == len(SCENARIOS)


def test_evaluation_report_is_json_serializable_and_writable(tmp_path) -> None:
    target = tmp_path / "reports" / "ajan-kalkani.json"
    report = evaluate_all()

    written = write_report(report, target)
    payload = json.loads(written.read_text(encoding="utf-8"))

    assert written == target
    assert payload["id"] == report.id
    assert payload["passed"] is True
    assert payload["thresholds"]["max_guarded_attack_success"] == 0.0
    assert "PROD_CREDENTIAL_7F3C1" not in written.read_text(encoding="utf-8")


def test_gate_fails_when_attack_suite_is_empty(monkeypatch) -> None:
    original_comparison = evaluation._comparison

    def mark_as_safe(scenario):
        comparison = original_comparison(scenario)
        return comparison.model_copy(update={"is_attack_scenario": False})

    monkeypatch.setattr(evaluation, "_comparison", mark_as_safe)
    report = evaluate_all()
    failed_metrics = {failure.metric for failure in report.failures}

    assert report.passed is False
    assert report.metrics.attack_scenario_count == 0
    assert "attack_scenario_count" in failed_metrics
    assert "baseline_attack_success_rate" in failed_metrics


def test_gate_fails_when_baseline_does_not_trigger_attacks(monkeypatch) -> None:
    original_comparison = evaluation._comparison

    def break_baseline(scenario):
        comparison = original_comparison(scenario)
        if comparison.is_attack_scenario:
            comparison.unprotected.attack_success = False
        return comparison

    monkeypatch.setattr(evaluation, "_comparison", break_baseline)
    report = evaluate_all()

    assert report.passed is False
    assert report.metrics.attack_scenario_count >= 1
    assert report.metrics.baseline_attack_success_rate == 0.0
    assert any(
        failure.metric == "baseline_attack_success_rate"
        for failure in report.failures
    )
