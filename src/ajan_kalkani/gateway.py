"""Kalıcı, sözleşmeye bağlı runtime yetkilendirme oturumları."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from ajan_kalkani.audit import DEFAULT_AUDIT_DB
from ajan_kalkani.models import (
    GatewayAuthorizationRequest,
    GatewayDecisionRecord,
    GatewaySessionCreate,
    GatewaySessionDetail,
    GatewaySessionSummary,
    IntentContract,
    RunMode,
)
from ajan_kalkani.policy import PolicyEngine
from ajan_kalkani.storage import open_sqlite


class GatewaySessionNotFoundError(LookupError):
    pass


class GatewaySessionExpiredError(RuntimeError):
    pass


class GatewayStore:
    """Ajan oturumlarını ve redakte karar kayıtlarını SQLite'ta saklar."""

    def __init__(self, path: str | Path | None = None) -> None:
        configured_path = path or os.getenv("AJAN_KALKANI_AUDIT_DB") or DEFAULT_AUDIT_DB
        self.path = Path(configured_path).expanduser()

    def create_session(self, request: GatewaySessionCreate) -> GatewaySessionDetail:
        created_at = datetime.now(timezone.utc)
        expires_at = created_at + timedelta(minutes=request.ttl_minutes)
        contract_payload = request.contract.model_dump(mode="json")
        contract_json = json.dumps(
            contract_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        contract_hash = sha256(contract_json.encode("utf-8")).hexdigest()
        session_id = str(uuid4())

        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO gateway_sessions
                    (id, name, created_at, expires_at, contract_json, contract_hash)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    request.name,
                    created_at.isoformat(),
                    expires_at.isoformat(),
                    contract_json,
                    contract_hash,
                ),
            )
        return GatewaySessionDetail(
            id=session_id,
            name=request.name,
            created_at=created_at,
            expires_at=expires_at,
            status="active",
            contract_hash=contract_hash,
            decision_count=0,
            contract=request.contract,
        )

    def get_session(self, session_id: str) -> GatewaySessionDetail | None:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT s.*, COUNT(d.sequence) AS decision_count
                FROM gateway_sessions AS s
                LEFT JOIN gateway_decisions AS d ON d.session_id = s.id
                WHERE s.id = ?
                GROUP BY s.id
                """,
                (session_id,),
            ).fetchone()
        return self._session_from_row(row) if row else None

    def list_sessions(self, limit: int = 20) -> list[GatewaySessionSummary]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT s.id, s.name, s.created_at, s.expires_at, s.contract_hash,
                       COUNT(d.sequence) AS decision_count
                FROM gateway_sessions AS s
                LEFT JOIN gateway_decisions AS d ON d.session_id = s.id
                GROUP BY s.id
                ORDER BY s.created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._session_summary_from_row(row) for row in rows]

    def authorize(
        self,
        session_id: str,
        request: GatewayAuthorizationRequest,
    ) -> GatewayDecisionRecord:
        created_at = datetime.now(timezone.utc)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            session = connection.execute(
                "SELECT contract_json, expires_at FROM gateway_sessions WHERE id = ?",
                (session_id,),
            ).fetchone()
            if session is None:
                raise GatewaySessionNotFoundError(f"Gateway oturumu bulunamadı: {session_id}")
            if datetime.fromisoformat(session["expires_at"]) <= created_at:
                raise GatewaySessionExpiredError(f"Gateway oturumunun süresi doldu: {session_id}")

            contract = IntentContract.model_validate_json(session["contract_json"])
            decision = PolicyEngine().evaluate(request.call, contract, RunMode.GUARDED)
            call_json = json.dumps(
                request.call.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            request_hash = sha256(call_json.encode("utf-8")).hexdigest()
            sequence = int(
                connection.execute(
                    "SELECT COALESCE(MAX(sequence), 0) + 1 FROM gateway_decisions WHERE session_id = ?",
                    (session_id,),
                ).fetchone()[0]
            )
            labels_json = json.dumps(sorted(request.call.data_labels), ensure_ascii=False)
            decision_json = decision.model_dump_json()
            connection.execute(
                """
                INSERT INTO gateway_decisions
                    (session_id, sequence, created_at, tool, origin, data_labels_json, request_hash, decision_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    sequence,
                    created_at.isoformat(),
                    request.call.tool,
                    request.call.origin,
                    labels_json,
                    request_hash,
                    decision_json,
                ),
            )

        return GatewayDecisionRecord(
            session_id=session_id,
            sequence=sequence,
            created_at=created_at,
            tool=request.call.tool,
            origin=request.call.origin,
            data_labels=sorted(request.call.data_labels),
            request_hash=request_hash,
            decision=decision,
        )

    def list_decisions(self, session_id: str, limit: int = 50) -> list[GatewayDecisionRecord]:
        with self._connection() as connection:
            exists = connection.execute(
                "SELECT 1 FROM gateway_sessions WHERE id = ?", (session_id,)
            ).fetchone()
            if exists is None:
                raise GatewaySessionNotFoundError(f"Gateway oturumu bulunamadı: {session_id}")
            rows = connection.execute(
                """
                SELECT session_id, sequence, created_at, tool, origin,
                       data_labels_json, request_hash, decision_json
                FROM gateway_decisions
                WHERE session_id = ?
                ORDER BY sequence DESC
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()
        return [
            GatewayDecisionRecord(
                session_id=row["session_id"],
                sequence=row["sequence"],
                created_at=row["created_at"],
                tool=row["tool"],
                origin=row["origin"],
                data_labels=json.loads(row["data_labels_json"]),
                request_hash=row["request_hash"],
                decision=json.loads(row["decision_json"]),
            )
            for row in rows
        ]

    @staticmethod
    def _status(expires_at: datetime) -> str:
        return "expired" if expires_at <= datetime.now(timezone.utc) else "active"

    def _session_summary_from_row(self, row: sqlite3.Row) -> GatewaySessionSummary:
        expires_at = datetime.fromisoformat(row["expires_at"])
        return GatewaySessionSummary(
            id=row["id"],
            name=row["name"],
            created_at=row["created_at"],
            expires_at=expires_at,
            status=self._status(expires_at),
            contract_hash=row["contract_hash"],
            decision_count=row["decision_count"],
        )

    def _session_from_row(self, row: sqlite3.Row) -> GatewaySessionDetail:
        summary = self._session_summary_from_row(row)
        return GatewaySessionDetail(
            **summary.model_dump(),
            contract=IntentContract.model_validate_json(row["contract_json"]),
        )

    def _connection(self) -> sqlite3.Connection:
        return open_sqlite(
            self.path,
            schema="gateway-v1",
            initialize=self._initialize_schema,
        )

    @staticmethod
    def _initialize_schema(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS gateway_sessions (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                contract_json TEXT NOT NULL,
                contract_hash TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS gateway_sessions_created_at_idx ON gateway_sessions(created_at DESC)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS gateway_decisions (
                session_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                tool TEXT NOT NULL,
                origin TEXT NOT NULL,
                data_labels_json TEXT NOT NULL,
                request_hash TEXT NOT NULL DEFAULT '',
                decision_json TEXT NOT NULL,
                PRIMARY KEY (session_id, sequence),
                FOREIGN KEY (session_id) REFERENCES gateway_sessions(id) ON DELETE RESTRICT
            )
            """
        )
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(gateway_decisions)")
        }
        if "request_hash" not in columns:
            connection.execute(
                "ALTER TABLE gateway_decisions ADD COLUMN request_hash TEXT NOT NULL DEFAULT ''"
            )
