import sqlite3

from ajan_kalkani.audit import AuditStore
from ajan_kalkani.evaluation import evaluate_all
from ajan_kalkani.models import RunMode
from ajan_kalkani.service import run_scenario


def test_run_is_persisted_redacted_and_can_be_loaded(tmp_path) -> None:
    database = tmp_path / "audit" / "records.sqlite3"
    store = AuditStore(database)
    result = run_scenario("email_prompt_injection", RunMode.UNPROTECTED)

    store.record_run(result)
    loaded = store.get_run(result.id)
    summaries = store.list_runs()

    assert loaded is not None
    assert loaded.id == result.id
    assert summaries[0]["id"] == result.id
    assert summaries[0]["attack_success"] == 1
    assert store.verify_integrity()["valid"] is True

    with sqlite3.connect(database) as connection:
        payload = connection.execute("SELECT payload FROM runs WHERE id = ?", (result.id,)).fetchone()[0]
    assert "PROD_CREDENTIAL_7F3C1" not in payload
    assert "[REDACTED]" in payload


def test_integrity_check_detects_modified_payload(tmp_path) -> None:
    database = tmp_path / "records.sqlite3"
    store = AuditStore(database)
    result = run_scenario("safe_email_draft", RunMode.GUARDED)
    store.record_run(result)

    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE runs SET payload = ? WHERE id = ?", ("{}", result.id))

    report = store.verify_integrity()
    assert report["valid"] is False
    assert report["broken_record_ids"] == [result.id]


def test_integrity_check_detects_deleted_tail_record(tmp_path) -> None:
    database = tmp_path / "records.sqlite3"
    store = AuditStore(database)
    first = run_scenario("safe_email_draft", RunMode.GUARDED)
    second = run_scenario("safe_calendar_read", RunMode.GUARDED)
    store.record_run(first)
    store.record_run(second)

    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM runs WHERE id = ?", (second.id,))

    report = store.verify_integrity()
    assert report["valid"] is False
    assert "runs:head" in report["broken_record_ids"]


def test_evaluation_summary_is_persisted(tmp_path) -> None:
    store = AuditStore(tmp_path / "records.sqlite3")
    report = evaluate_all()

    store.record_evaluation(report)

    assert store.list_evaluations() == [
        {"id": report.id, "created_at": report.created_at.isoformat(), "passed": 1}
    ]
