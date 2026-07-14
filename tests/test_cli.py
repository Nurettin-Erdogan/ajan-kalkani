import json
import sys

import pytest

from ajan_kalkani.__main__ import main


def test_evaluate_cli_writes_report(monkeypatch, tmp_path, capsys) -> None:
    report_path = tmp_path / "evaluation.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["ajan-kalkani", "--evaluate", "--report", str(report_path)],
    )

    with pytest.raises(SystemExit) as exit_info:
        main()

    assert exit_info.value.code == 0
    assert json.loads(report_path.read_text(encoding="utf-8"))["passed"] is True
    assert "Ajan Kalkanı CI: PASS" in capsys.readouterr().out


def test_evaluate_cli_returns_nonzero_when_gate_fails(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["ajan-kalkani", "--evaluate", "--min-attack-scenario-count", "999"],
    )

    with pytest.raises(SystemExit) as exit_info:
        main()

    assert exit_info.value.code == 1
    assert "Ajan Kalkanı CI: FAIL" in capsys.readouterr().out


def test_cli_rejects_invalid_rates(monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["ajan-kalkani", "--evaluate", "--max-guarded-attack-success", "1.5"],
    )

    with pytest.raises(SystemExit) as exit_info:
        main()

    assert exit_info.value.code == 2
