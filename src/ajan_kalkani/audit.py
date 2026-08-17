"""Redakte edilmiş, yerel denetim kayıtları için SQLite deposu."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from hashlib import sha256
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ajan_kalkani.evaluation import EvaluationReport
from ajan_kalkani.models import RunResult
from ajan_kalkani.storage import open_sqlite


DEFAULT_AUDIT_DB = Path("data") / "ajan-kalkani-audit.sqlite3"
_SECRET_VALUE = re.compile(r"(?i)(sk-[a-z0-9._-]{8,}|bearer\s+[a-z0-9._-]{8,})")
_SENSITIVE_KEY_MARKERS = (
    "api_key",
    "authorization",
    "content",
    "credential",
    "password",
    "payload",
    "secret",
    "token",
)


def _redact(value: Any, key: str | None = None) -> Any:
    """Kayıt katmanında ikinci bir savunma hattı olarak hassas değerleri maskeler."""

    if key and any(marker in key.lower() for marker in _SENSITIVE_KEY_MARKERS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(item_key): _redact(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        return _SECRET_VALUE.sub("[REDACTED]", value)
    return value


class AuditStore:
    """Her işlemde kısa ömürlü SQLite bağlantısı kullanan yerel denetim deposu."""

    def __init__(self, path: str | Path | None = None) -> None:
        configured_path = path or os.getenv("AJAN_KALKANI_AUDIT_DB") or DEFAULT_AUDIT_DB
        self.path = Path(configured_path).expanduser()

    def record_run(self, result: RunResult) -> None:
        payload = _redact(result.model_dump(mode="json"))
        created_at = datetime.now(timezone.utc).isoformat()
        with self._connection() as connection:
            # The previous head and the new record must be written as one
            # serialized operation. A deferred transaction lets concurrent
            # requests read the same head and create a forked hash chain.
            connection.execute("BEGIN IMMEDIATE")
            previous_hash = self._last_hash(connection, "runs")
            entry_hash = self._entry_hash("run", result.id, created_at, payload, previous_hash)
            connection.execute(
                """
                INSERT INTO runs
                    (id, created_at, scenario_id, scenario_name, mode, status, task_success, attack_success, payload, previous_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.id,
                    created_at,
                    result.scenario_id,
                    result.scenario_name,
                    result.mode.value,
                    result.status,
                    int(result.task_success),
                    int(result.attack_success),
                    json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                    previous_hash,
                    entry_hash,
                ),
            )
            self._sync_metadata(connection, "runs")

    def record_evaluation(self, report: EvaluationReport) -> None:
        payload = _redact(report.model_dump(mode="json"))
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            created_at = report.created_at.isoformat()
            previous_hash = self._last_hash(connection, "evaluations")
            entry_hash = self._entry_hash("evaluation", report.id, created_at, payload, previous_hash)
            connection.execute(
                """
                INSERT INTO evaluations (id, created_at, passed, payload, previous_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    report.id,
                    created_at,
                    int(report.passed),
                    json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                    previous_hash,
                    entry_hash,
                ),
            )
            self._sync_metadata(connection, "evaluations")

    def get_run(self, run_id: str) -> RunResult | None:
        with self._connection() as connection:
            row = connection.execute("SELECT payload FROM runs WHERE id = ?", (run_id,)).fetchone()
        return RunResult.model_validate_json(row["payload"]) if row else None

    def list_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 100))
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id, created_at, scenario_id, scenario_name, mode, status, task_success, attack_success
                FROM runs ORDER BY created_at DESC LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_evaluations(self, limit: int = 20) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 100))
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT id, created_at, passed FROM evaluations ORDER BY created_at DESC LIMIT ?",
                (safe_limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def verify_integrity(self) -> dict[str, Any]:
        """Yerel kayıtlardaki silme/değiştirme izlerini hash zinciriyle denetler.

        Bu kontrol, diske tam yazma yetkisi olan saldırgana karşı güvenlik sınırı
        değildir; merkezi, imzalı bir audit sistemi için görünürlük sağlar.
        """

        broken_record_ids: list[str] = []
        counts = {"runs": 0, "evaluations": 0}
        with self._connection() as connection:
            for table, kind in (("runs", "run"), ("evaluations", "evaluation")):
                previous_hash = ""
                rows = connection.execute(
                    f"SELECT * FROM {table} ORDER BY rowid ASC"
                ).fetchall()
                for row in rows:
                    summary_matches = False
                    counts[table] += 1
                    try:
                        payload = json.loads(row["payload"])
                        expected_hash = self._entry_hash(kind, row["id"], row["created_at"], payload, previous_hash)
                        summary_matches = self._summary_matches_payload(table, row, payload)
                    except (json.JSONDecodeError, TypeError):
                        expected_hash = ""
                    if (
                        row["previous_hash"] != previous_hash
                        or row["entry_hash"] != expected_hash
                        or not summary_matches
                    ):
                        broken_record_ids.append(row["id"])
                    previous_hash = row["entry_hash"]
                metadata = connection.execute(
                    "SELECT record_count, head_hash FROM audit_metadata WHERE record_type = ?",
                    (table,),
                ).fetchone()
                if (
                    metadata is None
                    or metadata["record_count"] != counts[table]
                    or metadata["head_hash"] != previous_hash
                ):
                    broken_record_ids.append(f"{table}:head")
        return {
            "valid": not broken_record_ids,
            "run_count": counts["runs"],
            "evaluation_count": counts["evaluations"],
            "broken_record_ids": broken_record_ids,
        }

    @staticmethod
    def _summary_matches_payload(
        table: str,
        row: sqlite3.Row,
        payload: dict[str, Any],
    ) -> bool:
        """Materialized list fields must agree with the hash-protected payload."""

        if not isinstance(payload, dict):
            return False
        if table == "runs":
            return (
                row["scenario_id"] == payload.get("scenario_id")
                and row["scenario_name"] == payload.get("scenario_name")
                and row["mode"] == payload.get("mode")
                and row["status"] == payload.get("status")
                and bool(row["task_success"]) is bool(payload.get("task_success"))
                and bool(row["attack_success"]) is bool(payload.get("attack_success"))
            )
        if table == "evaluations":
            return bool(row["passed"]) is bool(payload.get("passed"))
        return False

    @staticmethod
    def _entry_hash(
        kind: str,
        record_id: str,
        created_at: str,
        payload: dict[str, Any],
        previous_hash: str,
    ) -> str:
        canonical = json.dumps(
            {
                "kind": kind,
                "id": record_id,
                "created_at": created_at,
                "payload": payload,
                "previous_hash": previous_hash,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _last_hash(connection: sqlite3.Connection, table: str) -> str:
        row = connection.execute(
            "SELECT head_hash FROM audit_metadata WHERE record_type = ?", (table,)
        ).fetchone()
        return str(row["head_hash"]) if row else ""

    def _connection(self) -> sqlite3.Connection:
        return open_sqlite(
            self.path,
            schema="audit-v2",
            initialize=self._initialize_schema,
        )

    def _initialize_schema(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                scenario_id TEXT NOT NULL,
                scenario_name TEXT NOT NULL,
                mode TEXT NOT NULL,
                status TEXT NOT NULL,
                task_success INTEGER NOT NULL,
                attack_success INTEGER NOT NULL,
                payload TEXT NOT NULL,
                previous_hash TEXT NOT NULL DEFAULT '',
                entry_hash TEXT NOT NULL DEFAULT ''
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_metadata (
                record_type TEXT PRIMARY KEY,
                record_count INTEGER NOT NULL,
                head_hash TEXT NOT NULL
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS runs_created_at_idx ON runs(created_at DESC)")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS evaluations (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                passed INTEGER NOT NULL,
                payload TEXT NOT NULL,
                previous_hash TEXT NOT NULL DEFAULT '',
                entry_hash TEXT NOT NULL DEFAULT ''
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS evaluations_created_at_idx ON evaluations(created_at DESC)"
        )
        self._ensure_hash_columns(connection, "runs")
        self._ensure_hash_columns(connection, "evaluations")
        self._backfill_hashes(connection, "runs", "run")
        self._backfill_hashes(connection, "evaluations", "evaluation")
        self._ensure_metadata(connection, "runs")
        self._ensure_metadata(connection, "evaluations")

    @staticmethod
    def _ensure_hash_columns(connection: sqlite3.Connection, table: str) -> None:
        columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
        if "previous_hash" not in columns:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN previous_hash TEXT NOT NULL DEFAULT ''")
        if "entry_hash" not in columns:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN entry_hash TEXT NOT NULL DEFAULT ''")

    def _backfill_hashes(self, connection: sqlite3.Connection, table: str, kind: str) -> None:
        """Eski sürümden kalan hash'siz kayıtları ilk açılışta zincire taşır."""

        previous_hash = ""
        rows = connection.execute(
            f"SELECT id, created_at, payload, previous_hash, entry_hash FROM {table} ORDER BY rowid ASC"
        ).fetchall()
        for row in rows:
            if row["entry_hash"]:
                # Populated hashes are evidence, even when they do not match
                # the current chain. Rewriting them here would erase a
                # tampering signal during application startup.
                previous_hash = row["entry_hash"]
                continue
            payload = json.loads(row["payload"])
            entry_hash = self._entry_hash(kind, row["id"], row["created_at"], payload, previous_hash)
            connection.execute(
                f"UPDATE {table} SET previous_hash = ?, entry_hash = ? WHERE id = ?",
                (previous_hash, entry_hash, row["id"]),
            )
            previous_hash = entry_hash

    @staticmethod
    def _sync_metadata(connection: sqlite3.Connection, table: str) -> None:
        row = connection.execute(
            f"SELECT COUNT(*) AS record_count, COALESCE((SELECT entry_hash FROM {table} ORDER BY rowid DESC LIMIT 1), '') AS head_hash FROM {table}"
        ).fetchone()
        connection.execute(
            """
            INSERT INTO audit_metadata (record_type, record_count, head_hash)
            VALUES (?, ?, ?)
            ON CONFLICT(record_type) DO UPDATE SET
                record_count = excluded.record_count,
                head_hash = excluded.head_hash
            """,
            (table, row["record_count"], row["head_hash"]),
        )

    def _ensure_metadata(self, connection: sqlite3.Connection, table: str) -> None:
        exists = connection.execute(
            "SELECT 1 FROM audit_metadata WHERE record_type = ?", (table,)
        ).fetchone()
        if exists is None:
            self._sync_metadata(connection, table)
