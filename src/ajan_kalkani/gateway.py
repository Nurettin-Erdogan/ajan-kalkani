"""Kalıcı, sözleşmeye bağlı runtime yetkilendirme oturumları ve insan onayları."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from ajan_kalkani.approvals import (
    DEFAULT_APPROVAL_TTL_MINUTES,
    ApprovalState,
    call_fingerprint,
    evaluate_presented_approval,
)
from ajan_kalkani.audit import DEFAULT_AUDIT_DB
from ajan_kalkani.models import (
    ApprovalDisplayStatus,
    ApprovalStatusFilter,
    GatewayApprovalRecord,
    GatewayApprovalSummary,
    GatewayAuthorizationRequest,
    GatewayDecisionRecord,
    GatewaySessionCreate,
    GatewaySessionDetail,
    GatewaySessionSummary,
    IntentContract,
    RunMode,
)
from ajan_kalkani.policy import SENSITIVE_LABELS, PolicyEngine
from ajan_kalkani.redaction import redact
from ajan_kalkani.storage import open_sqlite


class GatewaySessionNotFoundError(LookupError):
    pass


class GatewaySessionExpiredError(RuntimeError):
    pass


class GatewayApprovalNotFoundError(LookupError):
    pass


class GatewayApprovalConflictError(RuntimeError):
    pass


class GatewayApprovalExpiredError(RuntimeError):
    pass


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class GatewayStore:
    """Ajan oturumlarını, redakte karar kayıtlarını ve insan onaylarını SQLite'ta saklar."""

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        approval_ttl_minutes: int = DEFAULT_APPROVAL_TTL_MINUTES,
    ) -> None:
        configured_path = path or os.getenv("AJAN_KALKANI_AUDIT_DB") or DEFAULT_AUDIT_DB
        self.path = Path(configured_path).expanduser()
        self.approval_ttl = timedelta(minutes=approval_ttl_minutes)

    def create_session(self, request: GatewaySessionCreate) -> GatewaySessionDetail:
        created_at = datetime.now(timezone.utc)
        expires_at = created_at + timedelta(minutes=request.ttl_minutes)
        contract_json = _canonical_json(request.contract.model_dump(mode="json"))
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
            # Tek yazıcı kilidi: aynı onayı paralel iki isteğin birlikte
            # tüketmesi (çifte harcama) bu işlem sınırı içinde mümkün değildir.
            connection.execute("BEGIN IMMEDIATE")
            session = connection.execute(
                "SELECT contract_json, expires_at FROM gateway_sessions WHERE id = ?",
                (session_id,),
            ).fetchone()
            if session is None:
                raise GatewaySessionNotFoundError(f"Gateway oturumu bulunamadı: {session_id}")
            session_expires_at = datetime.fromisoformat(session["expires_at"])
            if session_expires_at <= created_at:
                raise GatewaySessionExpiredError(f"Gateway oturumunun süresi doldu: {session_id}")

            contract = IntentContract.model_validate_json(session["contract_json"])
            base_decision = PolicyEngine().evaluate(request.call, contract, RunMode.GUARDED)
            request_hash = call_fingerprint(request.call)
            sequence = int(
                connection.execute(
                    "SELECT COALESCE(MAX(sequence), 0) + 1 FROM gateway_decisions WHERE session_id = ?",
                    (session_id,),
                ).fetchone()[0]
            )

            decision = base_decision
            approval_row: sqlite3.Row | None = None
            if base_decision.requires_approval and request.approval_id is None:
                approval_row = self._pending_approval_for(
                    connection,
                    session_id=session_id,
                    request=request,
                    request_hash=request_hash,
                    now=created_at,
                    session_expires_at=session_expires_at,
                )
            elif base_decision.requires_approval:
                presented = connection.execute(
                    "SELECT * FROM gateway_approvals WHERE id = ?",
                    (request.approval_id,),
                ).fetchone()
                decision = evaluate_presented_approval(
                    base_decision,
                    self._approval_state(presented) if presented else None,
                    session_id=session_id,
                    request_hash=request_hash,
                    now=created_at,
                )
                if decision.allowed:
                    consumed = connection.execute(
                        """
                        UPDATE gateway_approvals
                        SET consumed_at = ?, consumed_by_sequence = ?
                        WHERE id = ? AND consumed_at IS NULL
                        """,
                        (created_at.isoformat(), sequence, presented["id"]),
                    ).rowcount
                    if consumed != 1:
                        raise RuntimeError("Onay tüketilemedi; işlem geri alındı.")
                    presented = connection.execute(
                        "SELECT * FROM gateway_approvals WHERE id = ?",
                        (presented["id"],),
                    ).fetchone()
                # Başka oturumun onayı hakkında durum bilgisi sızdırma.
                if presented is not None and presented["session_id"] == session_id:
                    approval_row = presented

            connection.execute(
                """
                INSERT INTO gateway_decisions
                    (session_id, sequence, created_at, tool, origin, data_labels_json,
                     request_hash, decision_json, approval_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    sequence,
                    created_at.isoformat(),
                    request.call.tool,
                    request.call.origin,
                    json.dumps(sorted(request.call.data_labels), ensure_ascii=False),
                    request_hash,
                    decision.model_dump_json(),
                    request.approval_id or (approval_row["id"] if approval_row else None),
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
            approval=self._approval_summary(approval_row, created_at) if approval_row else None,
        )

    def list_decisions(self, session_id: str, limit: int = 50) -> list[GatewayDecisionRecord]:
        now = datetime.now(timezone.utc)
        with self._connection() as connection:
            exists = connection.execute(
                "SELECT 1 FROM gateway_sessions WHERE id = ?", (session_id,)
            ).fetchone()
            if exists is None:
                raise GatewaySessionNotFoundError(f"Gateway oturumu bulunamadı: {session_id}")
            rows = connection.execute(
                """
                SELECT d.session_id, d.sequence, d.created_at, d.tool, d.origin,
                       d.data_labels_json, d.request_hash, d.decision_json,
                       a.id AS approval_id, a.status AS approval_status,
                       a.expires_at AS approval_expires_at,
                       a.consumed_at AS approval_consumed_at
                FROM gateway_decisions AS d
                LEFT JOIN gateway_approvals AS a
                    ON a.id = d.approval_id AND a.session_id = d.session_id
                WHERE d.session_id = ?
                ORDER BY d.sequence DESC
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
                approval=(
                    GatewayApprovalSummary(
                        id=row["approval_id"],
                        status=self._display_status(
                            row["approval_status"],
                            datetime.fromisoformat(row["approval_expires_at"]),
                            row["approval_consumed_at"],
                            now,
                        ),
                        expires_at=row["approval_expires_at"],
                    )
                    if row["approval_id"]
                    else None
                ),
            )
            for row in rows
        ]

    def get_approval(self, approval_id: str) -> GatewayApprovalRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM gateway_approvals WHERE id = ?",
                (approval_id,),
            ).fetchone()
        return self._approval_record(row, datetime.now(timezone.utc)) if row else None

    def list_approvals(
        self,
        status: ApprovalStatusFilter = "pending",
        limit: int = 20,
    ) -> list[GatewayApprovalRecord]:
        now = datetime.now(timezone.utc)
        now_text = now.isoformat()
        # Her filtre sabit, tam bir sorgudur; kullanıcı girdisi SQL metnine
        # karışmaz. Zaman damgaları aynı biçimde (UTC isoformat) yazıldığından
        # metin karşılaştırması kronolojik sırayla aynıdır.
        queries: dict[str, tuple[str, tuple[object, ...]]] = {
            "pending": (
                "SELECT * FROM gateway_approvals WHERE status = 'pending' AND expires_at > ? "
                "ORDER BY created_at DESC LIMIT ?",
                (now_text, limit),
            ),
            "approved": (
                "SELECT * FROM gateway_approvals WHERE status = 'approved' AND consumed_at IS NULL "
                "AND expires_at > ? ORDER BY created_at DESC LIMIT ?",
                (now_text, limit),
            ),
            "rejected": (
                "SELECT * FROM gateway_approvals WHERE status = 'rejected' "
                "ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ),
            "consumed": (
                "SELECT * FROM gateway_approvals WHERE consumed_at IS NOT NULL "
                "ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ),
            "expired": (
                "SELECT * FROM gateway_approvals WHERE status IN ('pending', 'approved') "
                "AND consumed_at IS NULL AND expires_at <= ? ORDER BY created_at DESC LIMIT ?",
                (now_text, limit),
            ),
            "all": (
                "SELECT * FROM gateway_approvals ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ),
        }
        query, parameters = queries[status]
        with self._connection() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._approval_record(row, now) for row in rows]

    def decide_approval(
        self,
        approval_id: str,
        *,
        approved: bool,
        approver: str,
        note: str | None = None,
    ) -> GatewayApprovalRecord:
        decided_at = datetime.now(timezone.utc)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM gateway_approvals WHERE id = ?",
                (approval_id,),
            ).fetchone()
            if row is None:
                raise GatewayApprovalNotFoundError(f"Onay kaydı bulunamadı: {approval_id}")
            if row["status"] != "pending":
                raise GatewayApprovalConflictError(
                    f"Onay zaten karara bağlanmış: {row['status']}"
                )
            if datetime.fromisoformat(row["expires_at"]) <= decided_at:
                raise GatewayApprovalExpiredError(f"Onay isteğinin süresi doldu: {approval_id}")
            connection.execute(
                """
                UPDATE gateway_approvals
                SET status = ?, decided_at = ?, decided_by = ?, note = ?
                WHERE id = ? AND status = 'pending'
                """,
                (
                    "approved" if approved else "rejected",
                    decided_at.isoformat(),
                    approver,
                    note,
                    approval_id,
                ),
            )
            row = connection.execute(
                "SELECT * FROM gateway_approvals WHERE id = ?",
                (approval_id,),
            ).fetchone()
        return self._approval_record(row, decided_at)

    def _pending_approval_for(
        self,
        connection: sqlite3.Connection,
        *,
        session_id: str,
        request: GatewayAuthorizationRequest,
        request_hash: str,
        now: datetime,
        session_expires_at: datetime,
    ) -> sqlite3.Row:
        """Aynı çağrı için açık bir onay isteği varsa onu, yoksa yenisini döndürür.

        Ajan aynı çağrıyı tekrar tekrar sorduğunda onaylayıcının kuyruğu
        çoğalmaz; istek idempotent'tir.
        """

        candidates = connection.execute(
            """
            SELECT * FROM gateway_approvals
            WHERE session_id = ? AND request_hash = ? AND status = 'pending'
            ORDER BY created_at DESC
            """,
            (session_id, request_hash),
        ).fetchall()
        for candidate in candidates:
            if datetime.fromisoformat(candidate["expires_at"]) > now:
                return candidate

        approval_id = str(uuid4())
        expires_at = min(now + self.approval_ttl, session_expires_at)
        preview = redact(
            request.call.arguments,
            force_sensitive=bool(request.call.data_labels & SENSITIVE_LABELS),
        )
        connection.execute(
            """
            INSERT INTO gateway_approvals
                (id, session_id, tool, origin, data_labels_json, arguments_preview_json,
                 request_hash, status, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
            """,
            (
                approval_id,
                session_id,
                request.call.tool,
                request.call.origin,
                json.dumps(sorted(request.call.data_labels), ensure_ascii=False),
                _canonical_json(preview),
                request_hash,
                now.isoformat(),
                expires_at.isoformat(),
            ),
        )
        return connection.execute(
            "SELECT * FROM gateway_approvals WHERE id = ?",
            (approval_id,),
        ).fetchone()

    @staticmethod
    def _approval_state(row: sqlite3.Row) -> ApprovalState:
        return ApprovalState(
            id=row["id"],
            session_id=row["session_id"],
            request_hash=row["request_hash"],
            status=row["status"],
            expires_at=datetime.fromisoformat(row["expires_at"]),
            consumed=row["consumed_at"] is not None,
            decided_by=row["decided_by"],
        )

    @staticmethod
    def _display_status(
        status: str,
        expires_at: datetime,
        consumed_at: str | None,
        now: datetime,
    ) -> ApprovalDisplayStatus:
        if consumed_at is not None:
            return "consumed"
        if status in {"pending", "approved"} and expires_at <= now:
            return "expired"
        return status  # type: ignore[return-value]

    def _approval_summary(self, row: sqlite3.Row, now: datetime) -> GatewayApprovalSummary:
        return GatewayApprovalSummary(
            id=row["id"],
            status=self._display_status(
                row["status"],
                datetime.fromisoformat(row["expires_at"]),
                row["consumed_at"],
                now,
            ),
            expires_at=row["expires_at"],
        )

    def _approval_record(self, row: sqlite3.Row, now: datetime) -> GatewayApprovalRecord:
        return GatewayApprovalRecord(
            id=row["id"],
            session_id=row["session_id"],
            tool=row["tool"],
            origin=row["origin"],
            data_labels=json.loads(row["data_labels_json"]),
            arguments_preview=json.loads(row["arguments_preview_json"]),
            request_hash=row["request_hash"],
            status=self._display_status(
                row["status"],
                datetime.fromisoformat(row["expires_at"]),
                row["consumed_at"],
                now,
            ),
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            decided_at=row["decided_at"],
            decided_by=row["decided_by"],
            note=row["note"],
            consumed_at=row["consumed_at"],
        )

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
            schema="gateway-v2",
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
                approval_id TEXT,
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
        if "approval_id" not in columns:
            connection.execute("ALTER TABLE gateway_decisions ADD COLUMN approval_id TEXT")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS gateway_approvals (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                origin TEXT NOT NULL,
                data_labels_json TEXT NOT NULL,
                arguments_preview_json TEXT NOT NULL,
                request_hash TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                decided_at TEXT,
                decided_by TEXT,
                note TEXT,
                consumed_at TEXT,
                consumed_by_sequence INTEGER,
                FOREIGN KEY (session_id) REFERENCES gateway_sessions(id) ON DELETE RESTRICT
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS gateway_approvals_lookup_idx
            ON gateway_approvals(session_id, request_hash, status)
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS gateway_approvals_created_at_idx ON gateway_approvals(created_at DESC)"
        )
