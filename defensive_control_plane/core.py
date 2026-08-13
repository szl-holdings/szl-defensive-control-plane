from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import tempfile
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = 2
PACKAGE_VERSION = "0.4.0"
ZERO_HASH = "0" * 64
MAX_EVENT_BYTES = 256 * 1024
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")


class ControlPlaneError(Exception):
    """Base class for fail-closed control-plane errors."""


class ValidationError(ControlPlaneError):
    """Input failed the explicit defensive contract."""


class ConflictError(ControlPlaneError):
    """Input conflicts with durable state or replay rules."""


class NotFoundError(ControlPlaneError):
    """A referenced object does not exist in the requested tenant."""


class AuthorizationError(ControlPlaneError):
    """A human approval or tenant binding was not valid."""


class EvidenceState(str, Enum):
    MODELED = "MODELED"
    VERIFIED_LOCAL = "VERIFIED_LOCAL"
    VERIFIED_CONNECTOR = "VERIFIED_CONNECTOR"
    VERIFIED_RUNTIME = "VERIFIED_RUNTIME"
    PARTIAL = "PARTIAL"
    QUEUED = "QUEUED"
    BLOCKED = "BLOCKED"
    UNAVAILABLE = "UNAVAILABLE"
    STALE = "STALE"
    DIVERGENT = "DIVERGENT"
    FAILED = "FAILED"
    FAILED_CLOSED = "FAILED_CLOSED"


class IngestDisposition(str, Enum):
    ACCEPTED = "ACCEPTED"
    REPLAYED = "REPLAYED"
    QUARANTINED = "QUARANTINED"


class _ClosingConnection(sqlite3.Connection):
    """Make ``with store.connect()`` close the Windows file handle on exit."""

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc, traceback))
        finally:
            self.close()


@dataclass(frozen=True)
class EventIngestResult:
    accepted: bool
    duplicate: bool
    quarantined: bool
    event_id: str | None
    alert_ids: tuple[str, ...] = ()
    case_ids: tuple[str, ...] = ()
    reason: str | None = None
    disposition: IngestDisposition = IngestDisposition.QUARANTINED


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    tenant_id: str
    identity: str
    roles: tuple[str, ...]
    expires_at: str
    assertion: str


@dataclass(frozen=True)
class DefensiveControlEnvelopeV1:
    id: str
    schema: str
    tenant_id: str
    action_type: str
    target_refs: tuple[str, ...]
    parameters: dict[str, Any]
    dry_run: bool
    policy_revision: str
    requested_by: str
    idempotency_key: str
    expires_at: str
    canonical_request_hash: str
    created_at: str
    case_id: str | None = None

    def public_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["target_refs"] = list(self.target_refs)
        return value


@dataclass(frozen=True)
class ApprovalGrant:
    approval_id: str
    envelope_id: str
    token: str
    approver: str
    expires_at: str
    bound_hash: str


@dataclass(frozen=True)
class ExecutionResult:
    execution_id: str | None
    envelope_id: str
    status: str
    remote_id: str | None
    result: dict[str, Any]
    replayed: bool = False


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ValidationError("value is not canonical JSON") from exc


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _rfc3339(value: datetime | None = None) -> str:
    current = (value or _utcnow()).astimezone(timezone.utc)
    return current.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_rfc3339(value: str, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field} must be a non-empty RFC3339 timestamp")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValidationError(f"{field} must be a valid RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise ValidationError(f"{field} is not a valid bounded identifier")
    return value


class SQLiteStore:
    """Small connection factory with durable, fail-closed SQLite defaults."""

    def __init__(self, db_path: str | os.PathLike[str]) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.db_path,
            timeout=10,
            isolation_level=None,
            check_same_thread=False,
            factory=_ClosingConnection,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def _migrate(self) -> None:
        with self.connect() as connection:
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            metadata_exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='metadata'"
            ).fetchone()
            existing_version = 0
            if metadata_exists:
                try:
                    version_row = connection.execute(
                        "SELECT value FROM metadata WHERE key='schema_version'"
                    ).fetchone()
                    if not version_row:
                        raise ConflictError("database schema version marker is missing")
                    existing_version = int(version_row["value"])
                except (sqlite3.Error, TypeError, ValueError) as exc:
                    raise ConflictError("database schema version is unreadable") from exc
                if existing_version != SCHEMA_VERSION:
                    direction = "newer" if existing_version > SCHEMA_VERSION else "unsupported"
                    raise ConflictError(
                        f"database schema is {direction}; explicit migration is required"
                    )
                if user_version != existing_version:
                    raise ConflictError("database schema version markers diverge")
            elif user_version != 0:
                raise ConflictError("database user_version exists without schema metadata")
            if existing_version == SCHEMA_VERSION:
                self._validate_schema(connection)
                return
            connection.executescript(
                """
                BEGIN IMMEDIATE;

                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS assets (
                    tenant_id TEXT NOT NULL,
                    asset_ref TEXT NOT NULL,
                    source TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, asset_ref)
                );

                CREATE TABLE IF NOT EXISTS principals (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    identity TEXT NOT NULL,
                    roles_json TEXT NOT NULL,
                    salt_hex TEXT NOT NULL,
                    credential_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE (tenant_id, identity)
                );

                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    source_event_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    asset_ref TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    body_hash TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE (tenant_id, source, source_event_id)
                );

                CREATE TABLE IF NOT EXISTS quarantined_events (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    source_event_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    body_hash TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    asset_ref TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    event_id TEXT NOT NULL REFERENCES events(id),
                    case_id TEXT NOT NULL REFERENCES cases(id),
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE (event_id, rule_id)
                );

                CREATE TABLE IF NOT EXISTS envelopes (
                    id TEXT PRIMARY KEY,
                    schema_name TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    case_id TEXT REFERENCES cases(id),
                    action_type TEXT NOT NULL,
                    target_refs_json TEXT NOT NULL,
                    parameters_json TEXT NOT NULL,
                    dry_run INTEGER NOT NULL CHECK (dry_run IN (0, 1)),
                    policy_revision TEXT NOT NULL,
                    requested_by TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    canonical_request_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE (tenant_id, idempotency_key)
                );

                CREATE TABLE IF NOT EXISTS approvals (
                    id TEXT PRIMARY KEY,
                    envelope_id TEXT NOT NULL UNIQUE REFERENCES envelopes(id),
                    tenant_id TEXT NOT NULL,
                    bound_hash TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    approver TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    used_at TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS executions (
                    id TEXT PRIMARY KEY,
                    envelope_id TEXT NOT NULL UNIQUE REFERENCES envelopes(id),
                    tenant_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    remote_id TEXT,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS evidence (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    case_id TEXT NOT NULL REFERENCES cases(id),
                    kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS verification_receipts (
                    id TEXT PRIMARY KEY,
                    suite TEXT NOT NULL,
                    evidence_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TRIGGER IF NOT EXISTS evidence_no_update
                BEFORE UPDATE ON evidence
                BEGIN
                    SELECT RAISE(ABORT, 'evidence is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS evidence_no_delete
                BEFORE DELETE ON evidence
                BEGIN
                    SELECT RAISE(ABORT, 'evidence is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS envelope_no_update
                BEFORE UPDATE ON envelopes
                BEGIN
                    SELECT RAISE(ABORT, 'approved action envelopes are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS envelope_no_delete
                BEFORE DELETE ON envelopes
                BEGIN
                    SELECT RAISE(ABORT, 'approved action envelopes are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS alert_tenant_insert
                BEFORE INSERT ON alerts
                WHEN COALESCE((SELECT tenant_id FROM events WHERE id=NEW.event_id), '') <> NEW.tenant_id
                  OR COALESCE((SELECT tenant_id FROM cases WHERE id=NEW.case_id), '') <> NEW.tenant_id
                BEGIN
                    SELECT RAISE(ABORT, 'alert tenant binding diverged');
                END;

                CREATE TRIGGER IF NOT EXISTS alert_tenant_update
                BEFORE UPDATE OF tenant_id, event_id, case_id ON alerts
                WHEN COALESCE((SELECT tenant_id FROM events WHERE id=NEW.event_id), '') <> NEW.tenant_id
                  OR COALESCE((SELECT tenant_id FROM cases WHERE id=NEW.case_id), '') <> NEW.tenant_id
                BEGIN
                    SELECT RAISE(ABORT, 'alert tenant binding diverged');
                END;

                CREATE TRIGGER IF NOT EXISTS envelope_case_tenant_insert
                BEFORE INSERT ON envelopes
                WHEN NEW.case_id IS NOT NULL
                 AND COALESCE((SELECT tenant_id FROM cases WHERE id=NEW.case_id), '') <> NEW.tenant_id
                BEGIN
                    SELECT RAISE(ABORT, 'envelope tenant binding diverged');
                END;

                CREATE TRIGGER IF NOT EXISTS approval_tenant_insert
                BEFORE INSERT ON approvals
                WHEN COALESCE((SELECT tenant_id FROM envelopes WHERE id=NEW.envelope_id), '') <> NEW.tenant_id
                BEGIN
                    SELECT RAISE(ABORT, 'approval tenant binding diverged');
                END;

                CREATE TRIGGER IF NOT EXISTS approval_tenant_update
                BEFORE UPDATE OF tenant_id, envelope_id ON approvals
                WHEN COALESCE((SELECT tenant_id FROM envelopes WHERE id=NEW.envelope_id), '') <> NEW.tenant_id
                BEGIN
                    SELECT RAISE(ABORT, 'approval tenant binding diverged');
                END;

                CREATE TRIGGER IF NOT EXISTS execution_tenant_insert
                BEFORE INSERT ON executions
                WHEN COALESCE((SELECT tenant_id FROM envelopes WHERE id=NEW.envelope_id), '') <> NEW.tenant_id
                BEGIN
                    SELECT RAISE(ABORT, 'execution tenant binding diverged');
                END;

                CREATE TRIGGER IF NOT EXISTS execution_tenant_update
                BEFORE UPDATE OF tenant_id, envelope_id ON executions
                WHEN COALESCE((SELECT tenant_id FROM envelopes WHERE id=NEW.envelope_id), '') <> NEW.tenant_id
                BEGIN
                    SELECT RAISE(ABORT, 'execution tenant binding diverged');
                END;

                CREATE TRIGGER IF NOT EXISTS evidence_tenant_insert
                BEFORE INSERT ON evidence
                WHEN COALESCE((SELECT tenant_id FROM cases WHERE id=NEW.case_id), '') <> NEW.tenant_id
                BEGIN
                    SELECT RAISE(ABORT, 'evidence tenant binding diverged');
                END;
                """
            )
            if existing_version == 0:
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES('schema_version', ?)",
                    (str(SCHEMA_VERSION),),
                )
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self._validate_schema(connection)
            connection.commit()

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> None:
        expected_columns = {
            "metadata": ("key", "value"),
            "assets": ("tenant_id", "asset_ref", "source", "last_seen"),
            "principals": (
                "id", "tenant_id", "identity", "roles_json", "salt_hex",
                "credential_hash", "created_at",
            ),
            "events": (
                "id", "tenant_id", "source", "source_event_id", "event_type",
                "occurred_at", "actor_id", "asset_ref", "severity", "body_hash",
                "raw_json", "created_at",
            ),
            "quarantined_events": (
                "id", "tenant_id", "source", "source_event_id", "reason",
                "body_hash", "raw_json", "created_at",
            ),
            "cases": (
                "id", "tenant_id", "asset_ref", "title", "severity", "state",
                "created_at", "updated_at",
            ),
            "alerts": (
                "id", "tenant_id", "event_id", "case_id", "rule_id", "title",
                "severity", "created_at",
            ),
            "envelopes": (
                "id", "schema_name", "tenant_id", "case_id", "action_type",
                "target_refs_json", "parameters_json", "dry_run", "policy_revision",
                "requested_by", "idempotency_key", "expires_at",
                "canonical_request_hash", "created_at",
            ),
            "approvals": (
                "id", "envelope_id", "tenant_id", "bound_hash", "token_hash",
                "approver", "expires_at", "status", "used_at", "created_at",
            ),
            "executions": (
                "id", "envelope_id", "tenant_id", "status", "remote_id",
                "result_json", "created_at", "completed_at",
            ),
            "evidence": (
                "id", "tenant_id", "case_id", "kind", "payload_json",
                "previous_hash", "entry_hash", "created_at",
            ),
            "verification_receipts": (
                "id", "suite", "evidence_digest", "created_at",
            ),
        }
        expected_table_hashes = {
            "alerts": "2e822c89bda5117a47e396e37c1eb4b89202f5694dc95afb0477ab9a9be51118",
            "approvals": "5ea9a32700974722e771562552b493aa83584293d463a6a3b25c293d3b993484",
            "assets": "ff5b3c9116bce0a4c25bcdb419c09e306ac929fb8fba82a60efd8ff1668beb2b",
            "cases": "325abd90b23410194eb53d289cfd7f06874acd1db1d74ed50a959fdc8d018498",
            "envelopes": "c84eb8a8bd8f204e31d62b473b532eb2d54d82d8ed691d11627f1c36fe0e6a1d",
            "events": "6676587ffabf2c78734025a50f08f9977e36ce274e5ff797b7322de19125e753",
            "evidence": "0eba3c9487384ba3ab53e66d0f0f267525bbf02ad1d9a1bfbe680c8e12996a02",
            "executions": "46468c783684f894a5e44e944f2713349e4766a778e375f150e87ebbc54a54a4",
            "metadata": "cdb572ffd11b2ba49840b449dd6bad1dfd49c061f16650e192c9feb3a63dffb7",
            "principals": "71e47732b1a4a4dd2b1fc67c699349bb94cd06de286538515f5c58a36146a3ea",
            "quarantined_events": "135132eb38dd21bca5437fcedd4a553fef9923bccec97e7b830ea0d06b23c04f",
            "verification_receipts": "3e4dfa54a7b58c7450c36ed54869f16e8b9798bac29f58c24233c971a9db349c",
        }
        actual_table_hashes = {
            row["name"]: _sha256(
                re.sub(r"\s+", " ", str(row["sql"] or "").lower())
                .strip()
                .encode("utf-8")
            )
            for row in connection.execute(
                """
                SELECT name, sql FROM sqlite_master
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
                """
            )
        }
        if actual_table_hashes != expected_table_hashes:
            raise ConflictError("database table definitions diverge")
        expected_primary_keys = {
            "metadata": ("key",),
            "assets": ("tenant_id", "asset_ref"),
            **{
                table: ("id",)
                for table in expected_columns
                if table not in {"metadata", "assets"}
            },
        }
        expected_nullable = {
            "metadata": {"key"},
            "assets": set(),
            "principals": {"id"},
            "events": {"id"},
            "quarantined_events": {"id"},
            "cases": {"id"},
            "alerts": {"id"},
            "envelopes": {"id", "case_id"},
            "approvals": {"id", "used_at"},
            "executions": {"id", "remote_id", "completed_at"},
            "evidence": {"id"},
            "verification_receipts": {"id"},
        }
        for table, columns in expected_columns.items():
            info = connection.execute(f"PRAGMA table_info({table})").fetchall()
            actual_columns = tuple(row["name"] for row in info)
            if actual_columns != columns:
                raise ConflictError(f"database table {table} columns diverge")
            actual_types = {
                row["name"]: str(row["type"]).upper() for row in info
            }
            expected_types = {
                column: (
                    "INTEGER" if table == "envelopes" and column == "dry_run" else "TEXT"
                )
                for column in columns
            }
            if actual_types != expected_types:
                raise ConflictError(f"database table {table} column types diverge")
            nullable = {row["name"] for row in info if int(row["notnull"]) == 0}
            if nullable != expected_nullable[table]:
                raise ConflictError(f"database table {table} nullability diverges")
            primary_key = tuple(
                row["name"]
                for row in sorted(info, key=lambda item: int(item["pk"]))
                if int(row["pk"]) > 0
            )
            if primary_key != expected_primary_keys[table]:
                raise ConflictError(f"database table {table} primary key diverges")

        expected_unique = {
            "metadata": {("key",)},
            "assets": {("tenant_id", "asset_ref")},
            "principals": {("id",), ("tenant_id", "identity")},
            "events": {("id",), ("tenant_id", "source", "source_event_id")},
            "quarantined_events": {("id",)},
            "cases": {("id",)},
            "alerts": {("id",), ("event_id", "rule_id")},
            "envelopes": {("id",), ("tenant_id", "idempotency_key")},
            "approvals": {("id",), ("envelope_id",)},
            "executions": {("id",), ("envelope_id",)},
            "evidence": {("id",)},
            "verification_receipts": {("id",)},
        }
        for table, expected_indexes in expected_unique.items():
            actual_unique: set[tuple[str, ...]] = set()
            for index in connection.execute(f"PRAGMA index_list({table})"):
                if int(index["unique"]) != 1:
                    raise ConflictError(
                        f"database table {table} contains an unexpected index"
                    )
                index_name = str(index["name"]).replace('"', '""')
                columns = tuple(
                    row["name"]
                    for row in connection.execute(
                        f'PRAGMA index_info("{index_name}")'
                    )
                )
                actual_unique.add(columns)
            if actual_unique != expected_indexes:
                raise ConflictError(f"database table {table} uniqueness diverges")

        expected_foreign_keys = {
            "alerts": {("event_id", "events", "id"), ("case_id", "cases", "id")},
            "envelopes": {("case_id", "cases", "id")},
            "approvals": {("envelope_id", "envelopes", "id")},
            "executions": {("envelope_id", "envelopes", "id")},
            "evidence": {("case_id", "cases", "id")},
        }
        for table in expected_columns:
            expected = expected_foreign_keys.get(table, set())
            actual = {
                (row["from"], row["table"], row["to"])
                for row in connection.execute(f"PRAGMA foreign_key_list({table})")
            }
            if actual != expected:
                raise ConflictError(f"database table {table} foreign keys diverge")

        envelope_sql_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='envelopes'"
        ).fetchone()
        envelope_sql = re.sub(
            r"\s+", " ", str(envelope_sql_row["sql"] if envelope_sql_row else "").lower()
        )
        if "check (dry_run in (0, 1))" not in envelope_sql:
            raise ConflictError("database envelope mode constraint diverges")

        expected_trigger_hashes = {
            "alert_tenant_insert": "7f6131523a07688b1d9f82dcb6d6996a7e69635576dd584eb4ad2e200eeaf6bc",
            "alert_tenant_update": "08416b4d5ed3489d6b1dcc2eed6f0dd351428620b5e23cfff0b8162d4e4bad9d",
            "approval_tenant_insert": "37705ec3698b4900555678383fab74a97decc5f53215848b8636052057daa114",
            "approval_tenant_update": "29387f0bc950b1049138e48efe87679322d8353bf1ffdaeee8fa45673bec59a1",
            "envelope_case_tenant_insert": "37788ef2f03a4c625ca35808e51a181a9f5ce41fb9a81a8ac3ef1ab434c0b5ac",
            "envelope_no_delete": "a3718cfdd98786db33677f96f8cbe971ab11992e0f7597280b4bbc59eb40da81",
            "envelope_no_update": "d529317a0952bf965830124a9f20c64bf616b40cf2c89d168424641662e456be",
            "evidence_no_delete": "86c454eb5e59f998506dd261cdbcf07322d5ffa8097f3b1038b397a8c3df411b",
            "evidence_no_update": "7dd13298ae56778b3ae4c889557c56973bd3bd77d3cd157f84888aa567f60759",
            "evidence_tenant_insert": "71c37e61ff7facf0ad540f0c58e2fa375d806a17e2ec947c938981a7862e0882",
            "execution_tenant_insert": "6e33819376bc515539c9400ebbe46fcda46695fe5b40fa5122ea4bd4a145609b",
            "execution_tenant_update": "2bfe19d049456fef4be68808deae30c1434450f96fa90f36d245685612d9644a",
        }
        trigger_rows = {
            row["name"]: _sha256(
                re.sub(r"\s+", " ", str(row["sql"] or "").lower())
                .strip()
                .encode("utf-8")
            )
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='trigger'"
            )
        }
        if trigger_rows != expected_trigger_hashes:
            raise ConflictError("database trigger definitions diverge")

        version = connection.execute(
            "SELECT value FROM metadata WHERE key='schema_version'"
        ).fetchone()
        if not version or int(version["value"]) != SCHEMA_VERSION:
            raise ConflictError("database schema version does not match the implementation")
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if user_version != SCHEMA_VERSION:
            raise ConflictError("database user_version does not match the implementation")

    @staticmethod
    def _tenant_bindings_valid(connection: sqlite3.Connection) -> bool:
        checks = (
            """
            SELECT COUNT(*) FROM alerts a
            LEFT JOIN events e ON e.id=a.event_id
            LEFT JOIN cases c ON c.id=a.case_id
            WHERE e.id IS NULL OR c.id IS NULL
               OR a.tenant_id<>e.tenant_id OR a.tenant_id<>c.tenant_id
            """,
            """
            SELECT COUNT(*) FROM envelopes x
            LEFT JOIN cases c ON c.id=x.case_id
            WHERE x.case_id IS NOT NULL
              AND (c.id IS NULL OR x.tenant_id<>c.tenant_id)
            """,
            """
            SELECT COUNT(*) FROM approvals a
            LEFT JOIN envelopes x ON x.id=a.envelope_id
            WHERE x.id IS NULL OR a.tenant_id<>x.tenant_id
            """,
            """
            SELECT COUNT(*) FROM executions e
            LEFT JOIN envelopes x ON x.id=e.envelope_id
            WHERE x.id IS NULL OR e.tenant_id<>x.tenant_id
            """,
            """
            SELECT COUNT(*) FROM evidence e
            LEFT JOIN cases c ON c.id=e.case_id
            WHERE c.id IS NULL OR e.tenant_id<>c.tenant_id
            """,
        )
        return all(int(connection.execute(query).fetchone()[0]) == 0 for query in checks)


class FakeTicketConnector:
    """In-memory, non-network connector for a disposable test-ticket target."""

    def __init__(self, fail: bool = False) -> None:
        self.calls: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._fail = fail
        self._results_by_idempotency_key: dict[str, dict[str, Any]] = {}

    def preview(self, envelope: DefensiveControlEnvelopeV1) -> dict[str, Any]:
        return {
            "connector": "DISPOSABLE_TEST_TRACKER",
            "predictedEffect": "create one local fake test ticket",
            "reversible": True,
            "targetRefs": list(envelope.target_refs),
            "mutationCalls": len(self.calls),
            "state": EvidenceState.MODELED.value,
        }

    @staticmethod
    def provider_idempotency_key(envelope: DefensiveControlEnvelopeV1) -> str:
        protected = {
            "schema": "DisposableTicketProviderKeyV1",
            "connector": "DISPOSABLE_TEST_TRACKER",
            "tenantId": envelope.tenant_id,
            "envelopeId": envelope.id,
            "actionType": envelope.action_type,
            "canonicalRequestHash": envelope.canonical_request_hash,
            "clientIdempotencyKey": envelope.idempotency_key,
        }
        return _sha256(_canonical_bytes(protected))

    def perform(self, envelope: DefensiveControlEnvelopeV1) -> dict[str, Any]:
        provider_key = self.provider_idempotency_key(envelope)
        with self._lock:
            existing = self._results_by_idempotency_key.get(provider_key)
            if existing:
                return dict(existing)
            if self._fail:
                raise RuntimeError("simulated connector failure")
            remote_id = "fake-ticket-" + hashlib.sha256(
                provider_key.encode("utf-8")
            ).hexdigest()[:16]
            call = {
                "remoteId": remote_id,
                "tenantId": envelope.tenant_id,
                "envelopeId": envelope.id,
                "actionType": envelope.action_type,
                "targetRefs": list(envelope.target_refs),
                "idempotencyKey": envelope.idempotency_key,
                "providerIdempotencyKey": provider_key,
                "canonicalRequestHash": envelope.canonical_request_hash,
            }
            self.calls.append(call)
            result = {
                **call,
                "connector": "DISPOSABLE_TEST_TRACKER",
                "state": EvidenceState.VERIFIED_LOCAL.value,
            }
            self._results_by_idempotency_key[provider_key] = result
            return dict(result)

    def lookup(self, envelope: DefensiveControlEnvelopeV1) -> dict[str, Any] | None:
        """Read back a provider result without issuing another mutation."""

        provider_key = self.provider_idempotency_key(envelope)
        with self._lock:
            result = self._results_by_idempotency_key.get(provider_key)
            return dict(result) if result is not None else None


class ControlPlane:
    EVENT_SCHEMA = "NormalizedSecurityEventV1"
    ENVELOPE_SCHEMA = "DefensiveControlEnvelopeV1"
    ALLOWED_ACTION = "OPEN_TEST_TICKET"
    POLICY_REVISION = "defensive-policy-v1"

    _CASE_TRANSITIONS = {
        "NEW": {"TRIAGED", "CLOSED"},
        "TRIAGED": {"CONTAINMENT_APPROVED", "CLOSED"},
        "CONTAINMENT_APPROVED": {"CONTAINED"},
        "CONTAINED": {"RECOVERING"},
        "RECOVERING": {"RECOVERED"},
        "RECOVERED": {"CLOSED"},
        "CLOSED": {"NEW"},
    }

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        event_signing_key: bytes,
        evidence_signing_key: bytes | None = None,
        ticket_connector: FakeTicketConnector | None = None,
    ) -> None:
        if not isinstance(event_signing_key, bytes) or len(event_signing_key) < 16:
            raise ValidationError("event_signing_key must be at least 16 bytes")
        if not isinstance(evidence_signing_key, bytes) or len(evidence_signing_key) < 16:
            raise ValidationError("a distinct evidence_signing_key of at least 16 bytes is required")
        if hmac.compare_digest(event_signing_key, evidence_signing_key):
            raise ValidationError("event and evidence signing keys must be distinct")
        self.store = SQLiteStore(db_path)
        self._event_signing_key = event_signing_key
        self._evidence_signing_key = evidence_signing_key
        self._principal_assertion_key = hmac.new(
            evidence_signing_key,
            b"defensive-control-plane/principal-assertion/v1",
            hashlib.sha256,
        ).digest()
        if ticket_connector is not None and not isinstance(
            ticket_connector, FakeTicketConnector
        ):
            raise ValidationError("ticket_connector must implement the local fake connector contract")
        self._ticket_connector = ticket_connector or FakeTicketConnector()

    @staticmethod
    def derive_event_source_key(root_key: bytes, tenant_id: str, source: str) -> bytes:
        if not isinstance(root_key, bytes) or len(root_key) < 16:
            raise ValidationError("root_key must be at least 16 bytes")
        tenant = _identifier(tenant_id, "tenant_id")
        source_id = _identifier(source, "source")
        context = f"event-source/v1\0{tenant}\0{source_id}".encode("utf-8")
        return hmac.new(root_key, context, hashlib.sha256).digest()

    @staticmethod
    def sign_event(event: Mapping[str, Any], key: bytes) -> str:
        if not isinstance(key, bytes) or not key:
            raise ValidationError("key must be non-empty bytes")
        message_key = key
        tenant_id = event.get("tenantId") if isinstance(event, Mapping) else None
        source = event.get("source") if isinstance(event, Mapping) else None
        if isinstance(tenant_id, str) and isinstance(source, str):
            message_key = ControlPlane.derive_event_source_key(key, tenant_id, source)
        return hmac.new(message_key, _canonical_bytes(event), hashlib.sha256).hexdigest()

    def bootstrap_tenant(
        self,
        tenant_id: str,
        principals: Mapping[str, Mapping[str, Any]],
    ) -> None:
        tenant_id = _identifier(tenant_id, "tenant_id")
        if not isinstance(principals, Mapping) or not principals:
            raise ValidationError("principals must be a non-empty mapping")
        allowed_roles = {"requester", "approver", "analyst", "auditor"}
        prepared: list[tuple[str, str, tuple[str, ...], str, str]] = []
        for identity, config in principals.items():
            identity_id = _identifier(identity, "principal.identity")
            if not isinstance(config, Mapping):
                raise ValidationError("principal configuration must be an object")
            secret_value = config.get("secret")
            secret_bytes = (
                secret_value.encode("utf-8")
                if isinstance(secret_value, str)
                else secret_value
            )
            if not isinstance(secret_bytes, bytes) or len(secret_bytes) < 16:
                raise ValidationError("principal bootstrap secret must be at least 16 bytes")
            roles_value = config.get("roles")
            if not isinstance(roles_value, Sequence) or isinstance(
                roles_value, (str, bytes)
            ):
                raise ValidationError("principal roles must be a sequence")
            roles = tuple(sorted({_identifier(role, "principal.role") for role in roles_value}))
            if not roles or not set(roles).issubset(allowed_roles):
                raise ValidationError("principal roles contain an unsupported role")
            salt = secrets.token_bytes(16)
            credential_hash = hashlib.pbkdf2_hmac(
                "sha256", secret_bytes, salt, 240_000
            ).hex()
            prepared.append(
                (identity_id, json.dumps(roles), roles, salt.hex(), credential_hash)
            )
        connection = self.store.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT COUNT(*) FROM principals WHERE tenant_id=?", (tenant_id,)
            ).fetchone()[0]
            if existing:
                raise ConflictError("tenant principals are already bootstrapped")
            created_at = _rfc3339()
            for identity, roles_json, _roles, salt_hex, credential_hash in prepared:
                connection.execute(
                    """
                    INSERT INTO principals(
                        id, tenant_id, identity, roles_json, salt_hex,
                        credential_hash, created_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        tenant_id,
                        identity,
                        roles_json,
                        salt_hex,
                        credential_hash,
                        created_at,
                    ),
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _principal_claim(
        self, tenant_id: str, identity: str, roles: Sequence[str], expires_at: str
    ) -> dict[str, Any]:
        return {
            "schema": "AuthenticatedPrincipalV1",
            "tenantId": tenant_id,
            "identity": identity,
            "roles": list(roles),
            "expiresAt": expires_at,
        }

    def authenticate_principal(
        self,
        tenant_id: str,
        identity: str,
        secret: str | bytes,
        ttl_seconds: int = 900,
    ) -> AuthenticatedPrincipal:
        tenant_id = _identifier(tenant_id, "tenant_id")
        identity = _identifier(identity, "identity")
        secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
        if not isinstance(secret_bytes, bytes) or len(secret_bytes) < 16:
            raise AuthorizationError("principal credentials are invalid")
        if not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= 3600:
            raise ValidationError("principal ttl_seconds must be between 1 and 3600")
        with self.store.connect() as connection:
            row = connection.execute(
                "SELECT * FROM principals WHERE tenant_id=? AND identity=?",
                (tenant_id, identity),
            ).fetchone()
        if not row:
            raise AuthorizationError("principal credentials are invalid")
        salt = bytes.fromhex(row["salt_hex"])
        candidate = hashlib.pbkdf2_hmac("sha256", secret_bytes, salt, 240_000).hex()
        if not hmac.compare_digest(candidate, row["credential_hash"]):
            raise AuthorizationError("principal credentials are invalid")
        roles = tuple(json.loads(row["roles_json"]))
        expires_at = _rfc3339(_utcnow() + timedelta(seconds=ttl_seconds))
        claim = self._principal_claim(tenant_id, identity, roles, expires_at)
        assertion = hmac.new(
            self._principal_assertion_key, _canonical_bytes(claim), hashlib.sha256
        ).hexdigest()
        return AuthenticatedPrincipal(
            tenant_id=tenant_id,
            identity=identity,
            roles=roles,
            expires_at=expires_at,
            assertion=assertion,
        )

    def _require_principal(
        self,
        principal: AuthenticatedPrincipal,
        tenant_id: str,
        roles: set[str],
    ) -> str:
        if not isinstance(principal, AuthenticatedPrincipal):
            raise AuthorizationError("an authenticated principal is required")
        if principal.tenant_id != tenant_id or not roles.intersection(principal.roles):
            raise AuthorizationError("principal is not authorized for this tenant and role")
        if _parse_rfc3339(principal.expires_at, "principal.expires_at") <= _utcnow():
            raise AuthorizationError("principal assertion is expired")
        claim = self._principal_claim(
            principal.tenant_id,
            principal.identity,
            principal.roles,
            principal.expires_at,
        )
        expected = hmac.new(
            self._principal_assertion_key, _canonical_bytes(claim), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, principal.assertion):
            raise AuthorizationError("principal assertion is invalid")
        return principal.identity

    def _quarantine(
        self,
        connection: sqlite3.Connection,
        event: Mapping[str, Any],
        body_hash: str,
        reason: str,
    ) -> EventIngestResult:
        tenant_id = str(event.get("tenantId") or "unknown")[:128]
        source = str(event.get("source") or "unknown")[:128]
        source_event_id = str(event.get("sourceEventId") or "unknown")[:128]
        quarantine_id = str(uuid.uuid4())
        connection.execute(
            """
            INSERT INTO quarantined_events(
                id, tenant_id, source, source_event_id, reason, body_hash, raw_json, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                quarantine_id,
                tenant_id,
                source,
                source_event_id,
                reason,
                body_hash,
                _canonical_bytes(event).decode("utf-8"),
                _rfc3339(),
            ),
        )
        return EventIngestResult(
            accepted=False,
            duplicate=False,
            quarantined=True,
            event_id=None,
            reason=reason,
            disposition=IngestDisposition.QUARANTINED,
        )

    def _validate_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        required = {
            "schema",
            "tenantId",
            "source",
            "sourceEventId",
            "eventType",
            "occurredAt",
            "actor",
            "assetRef",
            "severity",
            "attributes",
        }
        missing = sorted(required - set(event))
        if missing:
            raise ValidationError("missing event fields: " + ", ".join(missing))
        if event["schema"] != self.EVENT_SCHEMA:
            raise ValidationError("unsupported event schema")
        tenant_id = _identifier(event["tenantId"], "tenantId")
        source = _identifier(event["source"], "source")
        source_event_id = _identifier(event["sourceEventId"], "sourceEventId")
        event_type = _identifier(event["eventType"], "eventType")
        asset_ref = _identifier(event["assetRef"], "assetRef")
        severity = str(event["severity"]).lower()
        if severity not in {"low", "medium", "high", "critical"}:
            raise ValidationError("severity must be low, medium, high, or critical")
        actor = event["actor"]
        if not isinstance(actor, Mapping):
            raise ValidationError("actor must be an object")
        actor_id = _identifier(actor.get("id"), "actor.id")
        attributes = event["attributes"]
        if not isinstance(attributes, Mapping):
            raise ValidationError("attributes must be an object")
        occurred = _parse_rfc3339(event["occurredAt"], "occurredAt")
        if occurred > _utcnow() + timedelta(minutes=5):
            raise ValidationError("occurredAt is too far in the future")
        return {
            "tenant_id": tenant_id,
            "source": source,
            "source_event_id": source_event_id,
            "event_type": event_type,
            "occurred_at": _rfc3339(occurred),
            "actor_id": actor_id,
            "asset_ref": asset_ref,
            "severity": severity,
            "attributes": dict(attributes),
        }

    def _detections(self, normalized: Mapping[str, Any]) -> list[tuple[str, str, str]]:
        event_type = str(normalized["event_type"])
        attributes = normalized["attributes"]
        rules: list[tuple[str, str, str]] = []

        def number(name: str, default: float = 0.0) -> float:
            value = attributes.get(name, default)
            if isinstance(value, bool):
                return default
            try:
                return float(value)
            except (TypeError, ValueError, OverflowError):
                return default

        if event_type == "auth.brute_force" or (
            event_type == "auth.failed" and number("attempts") >= 5
        ):
            rules.append(("DET-AUTH-BRUTE-FORCE", "high", "Suspicious authentication burst"))
        if event_type == "auth.impossible_travel" or (
            number("distanceKm") >= 500
            and number("minutesApart", 10_000) <= 60
        ):
            rules.append(("DET-IMPOSSIBLE-TRAVEL", "high", "Impossible travel"))
        if event_type == "iam.privilege_escalation":
            rules.append(("DET-PRIVILEGE-ESCALATION", "critical", "Privilege escalation"))
        if event_type == "data.exfiltration" or (
            event_type == "data.transfer"
            and number("bytes") >= 10 * 1024 * 1024
        ):
            rules.append(("DET-DATA-EXFILTRATION", "critical", "Unusual data transfer"))
        if event_type == "oauth.abuse" or attributes.get("highRiskConsent") is True:
            rules.append(("DET-OAUTH-ABUSE", "high", "OAuth application abuse"))
        if event_type == "security.control_disabled":
            rules.append(("DET-CONTROL-DISABLED", "critical", "Security control disabled"))
        if event_type == "backup.failed":
            rules.append(("DET-BACKUP-FAILURE", "high", "Backup failure"))
        if event_type in {"malware.detected", "process.suspicious"}:
            rules.append(("DET-ENDPOINT-THREAT", "critical", "Endpoint malware or suspicious process"))
        return rules

    def _append_evidence(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        case_id: str,
        kind: str,
        payload: Mapping[str, Any],
    ) -> str:
        previous = connection.execute(
            "SELECT entry_hash FROM evidence WHERE tenant_id=? AND case_id=? ORDER BY rowid DESC LIMIT 1",
            (tenant_id, case_id),
        ).fetchone()
        previous_hash = previous["entry_hash"] if previous else ZERO_HASH
        created_at = _rfc3339()
        protected = {
            "tenantId": tenant_id,
            "caseId": case_id,
            "kind": kind,
            "payload": dict(payload),
            "previousHash": previous_hash,
            "createdAt": created_at,
        }
        entry_hash = _sha256(_canonical_bytes(protected))
        evidence_id = str(uuid.uuid4())
        connection.execute(
            """
            INSERT INTO evidence(
                id, tenant_id, case_id, kind, payload_json,
                previous_hash, entry_hash, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                tenant_id,
                case_id,
                kind,
                _canonical_bytes(payload).decode("utf-8"),
                previous_hash,
                entry_hash,
                created_at,
            ),
        )
        return evidence_id

    def ingest_event(
        self, event: Mapping[str, Any], signature: str
    ) -> EventIngestResult:
        if not isinstance(event, Mapping):
            raise ValidationError("event must be an object")
        raw = _canonical_bytes(event)
        if len(raw) > MAX_EVENT_BYTES:
            raise ValidationError("event exceeds the 256 KiB limit")
        body_hash = _sha256(raw)
        message_key = self._event_signing_key
        raw_tenant = event.get("tenantId")
        raw_source = event.get("source")
        if isinstance(raw_tenant, str) and isinstance(raw_source, str):
            try:
                message_key = self.derive_event_source_key(
                    self._event_signing_key, raw_tenant, raw_source
                )
            except ValidationError:
                message_key = self._event_signing_key
        expected = hmac.new(message_key, raw, hashlib.sha256).hexdigest()

        connection = self.store.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            if not isinstance(signature, str) or not hmac.compare_digest(expected, signature):
                result = self._quarantine(connection, event, body_hash, "INVALID_SIGNATURE")
                connection.commit()
                return result
            try:
                normalized = self._validate_event(event)
            except ValidationError as exc:
                result = self._quarantine(connection, event, body_hash, str(exc))
                connection.commit()
                return result

            existing = connection.execute(
                """
                SELECT * FROM events
                WHERE tenant_id=? AND source=? AND source_event_id=?
                """,
                (
                    normalized["tenant_id"],
                    normalized["source"],
                    normalized["source_event_id"],
                ),
            ).fetchone()
            if existing:
                if existing["body_hash"] != body_hash:
                    result = self._quarantine(
                        connection, event, body_hash, "EVENT_ID_COLLISION"
                    )
                    connection.commit()
                    return result
                alerts = connection.execute(
                    "SELECT id, case_id FROM alerts WHERE event_id=? ORDER BY id",
                    (existing["id"],),
                ).fetchall()
                connection.commit()
                return EventIngestResult(
                    accepted=True,
                    duplicate=True,
                    quarantined=False,
                    event_id=existing["id"],
                    alert_ids=tuple(row["id"] for row in alerts),
                    case_ids=tuple(row["case_id"] for row in alerts),
                    reason="EXACT_REPLAY",
                    disposition=IngestDisposition.REPLAYED,
                )

            now = _rfc3339()
            event_id = str(uuid.uuid4())
            connection.execute(
                """
                INSERT INTO events(
                    id, tenant_id, source, source_event_id, event_type,
                    occurred_at, actor_id, asset_ref, severity, body_hash,
                    raw_json, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    normalized["tenant_id"],
                    normalized["source"],
                    normalized["source_event_id"],
                    normalized["event_type"],
                    normalized["occurred_at"],
                    normalized["actor_id"],
                    normalized["asset_ref"],
                    normalized["severity"],
                    body_hash,
                    raw.decode("utf-8"),
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO assets(tenant_id, asset_ref, source, last_seen)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(tenant_id, asset_ref)
                DO UPDATE SET source=excluded.source, last_seen=excluded.last_seen
                """,
                (
                    normalized["tenant_id"],
                    normalized["asset_ref"],
                    normalized["source"],
                    now,
                ),
            )

            alert_ids: list[str] = []
            case_ids: list[str] = []
            for rule_id, rule_severity, title in self._detections(normalized):
                case_id = str(uuid.uuid4())
                alert_id = str(uuid.uuid4())
                connection.execute(
                    """
                    INSERT INTO cases(
                        id, tenant_id, asset_ref, title, severity, state, created_at, updated_at
                    ) VALUES(?, ?, ?, ?, ?, 'NEW', ?, ?)
                    """,
                    (
                        case_id,
                        normalized["tenant_id"],
                        normalized["asset_ref"],
                        title,
                        rule_severity,
                        now,
                        now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO alerts(
                        id, tenant_id, event_id, case_id, rule_id, title, severity, created_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert_id,
                        normalized["tenant_id"],
                        event_id,
                        case_id,
                        rule_id,
                        title,
                        rule_severity,
                        now,
                    ),
                )
                self._append_evidence(
                    connection,
                    normalized["tenant_id"],
                    case_id,
                    "event.ingested",
                    {"eventId": event_id, "bodyHash": body_hash},
                )
                self._append_evidence(
                    connection,
                    normalized["tenant_id"],
                    case_id,
                    "alert.created",
                    {"alertId": alert_id, "ruleId": rule_id},
                )
                self._append_evidence(
                    connection,
                    normalized["tenant_id"],
                    case_id,
                    "case.created",
                    {"caseId": case_id, "state": "NEW"},
                )
                alert_ids.append(alert_id)
                case_ids.append(case_id)
            connection.commit()
            return EventIngestResult(
                accepted=True,
                duplicate=False,
                quarantined=False,
                event_id=event_id,
                alert_ids=tuple(alert_ids),
                case_ids=tuple(case_ids),
                disposition=IngestDisposition.ACCEPTED,
            )
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _row_to_envelope(self, row: sqlite3.Row) -> DefensiveControlEnvelopeV1:
        return DefensiveControlEnvelopeV1(
            id=row["id"],
            schema=row["schema_name"],
            tenant_id=row["tenant_id"],
            action_type=row["action_type"],
            target_refs=tuple(json.loads(row["target_refs_json"])),
            parameters=dict(json.loads(row["parameters_json"])),
            dry_run=bool(row["dry_run"]),
            policy_revision=row["policy_revision"],
            requested_by=row["requested_by"],
            idempotency_key=row["idempotency_key"],
            expires_at=row["expires_at"],
            canonical_request_hash=row["canonical_request_hash"],
            created_at=row["created_at"],
            case_id=row["case_id"],
        )

    def _envelope_protected(self, envelope: DefensiveControlEnvelopeV1) -> dict[str, Any]:
        return {
            "id": envelope.id,
            "schema": envelope.schema,
            "tenantId": envelope.tenant_id,
            "caseId": envelope.case_id,
            "actionType": envelope.action_type,
            "targetRefs": list(envelope.target_refs),
            "parameters": envelope.parameters,
            "dryRun": envelope.dry_run,
            "policyRevision": envelope.policy_revision,
            "requestedBy": envelope.requested_by,
            "idempotencyKey": envelope.idempotency_key,
            "expiresAt": envelope.expires_at,
            "createdAt": envelope.created_at,
        }

    def _validate_envelope_integrity(
        self, envelope: DefensiveControlEnvelopeV1
    ) -> None:
        if envelope.schema != self.ENVELOPE_SCHEMA:
            raise ConflictError("envelope schema diverged")
        if envelope.action_type != self.ALLOWED_ACTION:
            raise ConflictError("envelope action is not allowlisted")
        if envelope.policy_revision != self.POLICY_REVISION:
            raise ConflictError("envelope policy revision diverged")
        if not envelope.dry_run and envelope.case_id is None:
            raise ConflictError("live envelope is not bound to an incident case")
        if len(envelope.target_refs) != 1 or any(
            not target.startswith("asset:test-") for target in envelope.target_refs
        ):
            raise ConflictError("envelope target policy diverged")
        if set(envelope.parameters) - {"summary"}:
            raise ConflictError("envelope parameters contain executable or unknown data")
        _identifier(envelope.tenant_id, "envelope.tenant_id")
        _identifier(envelope.requested_by, "envelope.requested_by")
        _parse_rfc3339(envelope.expires_at, "envelope.expires_at")
        _parse_rfc3339(envelope.created_at, "envelope.created_at")
        expected = _sha256(_canonical_bytes(self._envelope_protected(envelope)))
        if not hmac.compare_digest(expected, envelope.canonical_request_hash):
            raise ConflictError("envelope canonical hash diverged")

    def _get_envelope(
        self, connection: sqlite3.Connection, envelope_id: str
    ) -> DefensiveControlEnvelopeV1:
        row = connection.execute(
            "SELECT * FROM envelopes WHERE id=?", (envelope_id,)
        ).fetchone()
        if not row:
            raise NotFoundError("envelope not found")
        try:
            envelope = self._row_to_envelope(row)
            self._validate_envelope_integrity(envelope)
            return envelope
        except (json.JSONDecodeError, TypeError, ValidationError) as exc:
            raise ConflictError("envelope row is malformed") from exc

    def _validate_live_case(
        self,
        connection: sqlite3.Connection,
        envelope: DefensiveControlEnvelopeV1,
    ) -> None:
        if envelope.dry_run:
            return
        if envelope.case_id is None:
            raise ConflictError("live envelope lacks a case binding")
        case = connection.execute(
            "SELECT * FROM cases WHERE id=? AND tenant_id=?",
            (envelope.case_id, envelope.tenant_id),
        ).fetchone()
        if not case or case["state"] == "CLOSED":
            raise AuthorizationError("live action case is missing, closed, or ineligible")
        if case["asset_ref"] != envelope.target_refs[0]:
            raise AuthorizationError("live action target diverged from its incident case")
        evidence = connection.execute(
            "SELECT * FROM evidence WHERE case_id=? AND tenant_id=? ORDER BY rowid",
            (envelope.case_id, envelope.tenant_id),
        ).fetchall()
        if not self._verify_evidence_rows(
            evidence, envelope.tenant_id, envelope.case_id
        ):
            raise ConflictError("live action case evidence is missing or invalid")

    def create_envelope(
        self,
        tenant_id: str,
        action_type: str,
        target_refs: Sequence[str],
        requested_by: AuthenticatedPrincipal,
        parameters: Mapping[str, Any] | None = None,
        dry_run: bool = True,
        ttl_seconds: int = 300,
        idempotency_key: str | None = None,
    ) -> DefensiveControlEnvelopeV1:
        tenant_id = _identifier(tenant_id, "tenant_id")
        requester_identity = self._require_principal(
            requested_by, tenant_id, {"requester"}
        )
        if action_type != self.ALLOWED_ACTION:
            raise ValidationError("only OPEN_TEST_TICKET is allowlisted")
        if not isinstance(target_refs, Sequence) or isinstance(target_refs, (str, bytes)):
            raise ValidationError("target_refs must be a non-empty sequence")
        targets = tuple(_identifier(value, "target_ref") for value in target_refs)
        if len(targets) != 1 or any(
            not value.startswith("asset:test-") for value in targets
        ):
            raise ValidationError("exactly one explicit asset:test-* target is permitted")
        values = dict(parameters or {})
        if set(values) - {"summary"}:
            raise ValidationError("only the inert summary parameter is permitted")
        if "summary" in values and (
            not isinstance(values["summary"], str) or len(values["summary"]) > 200
        ):
            raise ValidationError("summary must be a string of at most 200 characters")
        if not isinstance(dry_run, bool):
            raise ValidationError("dry_run must be a boolean")
        if not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= 3600:
            raise ValidationError("ttl_seconds must be between 1 and 3600")
        idempotency = _identifier(
            idempotency_key or str(uuid.uuid4()), "idempotency_key"
        )
        envelope_id = str(uuid.uuid4())
        created_at = _rfc3339()
        expires_at = _rfc3339(_utcnow() + timedelta(seconds=ttl_seconds))

        connection = self.store.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            for target in targets:
                asset = connection.execute(
                    "SELECT 1 FROM assets WHERE tenant_id=? AND asset_ref=?",
                    (tenant_id, target),
                ).fetchone()
                if not asset:
                    raise AuthorizationError("target is absent from this tenant's inventory")
            case_row = connection.execute(
                """
                SELECT id FROM cases
                WHERE tenant_id=? AND asset_ref=? AND state<>'CLOSED'
                ORDER BY created_at DESC LIMIT 1
                """,
                (tenant_id, targets[0]),
            ).fetchone()
            case_id = case_row["id"] if case_row else None
            if not dry_run and case_id is None:
                raise AuthorizationError(
                    "live actions require an eligible open incident case with evidence"
                )
            if not dry_run:
                evidence = connection.execute(
                    "SELECT * FROM evidence WHERE case_id=? AND tenant_id=? ORDER BY rowid",
                    (case_id, tenant_id),
                ).fetchall()
                if not self._verify_evidence_rows(evidence, tenant_id, case_id):
                    raise ConflictError("live action case evidence is missing or invalid")
            protected = {
                "id": envelope_id,
                "schema": self.ENVELOPE_SCHEMA,
                "tenantId": tenant_id,
                "caseId": case_id,
                "actionType": action_type,
                "targetRefs": list(targets),
                "parameters": values,
                "dryRun": dry_run,
                "policyRevision": self.POLICY_REVISION,
                "requestedBy": requester_identity,
                "idempotencyKey": idempotency,
                "expiresAt": expires_at,
                "createdAt": created_at,
            }
            request_hash = _sha256(_canonical_bytes(protected))
            connection.execute(
                """
                INSERT INTO envelopes(
                    id, schema_name, tenant_id, case_id, action_type,
                    target_refs_json, parameters_json, dry_run, policy_revision,
                    requested_by, idempotency_key, expires_at,
                    canonical_request_hash, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    envelope_id,
                    self.ENVELOPE_SCHEMA,
                    tenant_id,
                    case_id,
                    action_type,
                    _canonical_bytes(list(targets)).decode("utf-8"),
                    _canonical_bytes(values).decode("utf-8"),
                    int(dry_run),
                    self.POLICY_REVISION,
                    requester_identity,
                    idempotency,
                    expires_at,
                    request_hash,
                    created_at,
                ),
            )
            if case_id:
                self._append_evidence(
                    connection,
                    tenant_id,
                    case_id,
                    "response.envelope.created",
                    {
                        "envelopeId": envelope_id,
                        "requestHash": request_hash,
                        "dryRun": dry_run,
                    },
                )
            connection.commit()
            return self._get_envelope(connection, envelope_id)
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise ConflictError("idempotency key or envelope already exists") from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _validated_connector_result(
        self,
        envelope: DefensiveControlEnvelopeV1,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(result, Mapping):
            raise ConflictError("connector result is not an object")
        expected = {
            "connector": "DISPOSABLE_TEST_TRACKER",
            "state": EvidenceState.VERIFIED_LOCAL.value,
            "tenantId": envelope.tenant_id,
            "envelopeId": envelope.id,
            "actionType": envelope.action_type,
            "targetRefs": list(envelope.target_refs),
            "idempotencyKey": envelope.idempotency_key,
            "providerIdempotencyKey": FakeTicketConnector.provider_idempotency_key(
                envelope
            ),
            "canonicalRequestHash": envelope.canonical_request_hash,
        }
        for name, value in expected.items():
            if result.get(name) != value:
                raise ConflictError(f"connector result {name} binding diverged")
        remote_id = result.get("remoteId")
        expected_remote_id = "fake-ticket-" + hashlib.sha256(
            expected["providerIdempotencyKey"].encode("utf-8")
        ).hexdigest()[:16]
        if remote_id != expected_remote_id:
            raise ConflictError("connector result remote identifier binding diverged")
        return dict(result)

    def preview_envelope(self, envelope_id: str) -> ExecutionResult:
        with self.store.connect() as connection:
            envelope = self._get_envelope(connection, envelope_id)
        if _parse_rfc3339(envelope.expires_at, "expires_at") <= _utcnow():
            raise AuthorizationError("envelope is expired")
        result = self._ticket_connector.preview(envelope)
        return ExecutionResult(
            execution_id=None,
            envelope_id=envelope.id,
            status="DRY_RUN",
            remote_id=None,
            result=result,
            replayed=False,
        )

    def issue_approval(
        self,
        envelope_id: str,
        approver: AuthenticatedPrincipal,
        ttl_seconds: int = 300,
    ) -> ApprovalGrant:
        if not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= 3600:
            raise ValidationError("ttl_seconds must be between 1 and 3600")
        token = secrets.token_urlsafe(32)
        token_hash = _sha256(token.encode("utf-8"))
        approval_id = str(uuid.uuid4())
        connection = self.store.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            envelope = self._get_envelope(connection, envelope_id)
            self._validate_live_case(connection, envelope)
            approver_identity = self._require_principal(
                approver, envelope.tenant_id, {"approver"}
            )
            if envelope.dry_run:
                raise AuthorizationError("dry-run envelopes cannot be approved for execution")
            if approver_identity == envelope.requested_by:
                raise AuthorizationError("requester cannot approve their own action")
            envelope_expiry = _parse_rfc3339(envelope.expires_at, "expires_at")
            if envelope_expiry <= _utcnow():
                raise AuthorizationError("envelope is expired")
            expires = min(envelope_expiry, _utcnow() + timedelta(seconds=ttl_seconds))
            created_at = _rfc3339()
            connection.execute(
                """
                INSERT INTO approvals(
                    id, envelope_id, tenant_id, bound_hash, token_hash,
                    approver, expires_at, status, used_at, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, 'APPROVED', NULL, ?)
                """,
                (
                    approval_id,
                    envelope.id,
                    envelope.tenant_id,
                    envelope.canonical_request_hash,
                    token_hash,
                    approver_identity,
                    _rfc3339(expires),
                    created_at,
                ),
            )
            if envelope.case_id:
                self._append_evidence(
                    connection,
                    envelope.tenant_id,
                    envelope.case_id,
                    "response.approved",
                    {
                        "approvalId": approval_id,
                        "envelopeId": envelope.id,
                        "approver": approver_identity,
                        "boundHash": envelope.canonical_request_hash,
                    },
                )
            connection.commit()
            return ApprovalGrant(
                approval_id=approval_id,
                envelope_id=envelope.id,
                token=token,
                approver=approver_identity,
                expires_at=_rfc3339(expires),
                bound_hash=envelope.canonical_request_hash,
            )
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise ConflictError("an approval already exists for this envelope") from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _execution_from_row(self, row: sqlite3.Row, replayed: bool) -> ExecutionResult:
        return ExecutionResult(
            execution_id=row["id"],
            envelope_id=row["envelope_id"],
            status=row["status"],
            remote_id=row["remote_id"],
            result=dict(json.loads(row["result_json"])),
            replayed=replayed,
        )

    def _await_execution(self, envelope_id: str) -> ExecutionResult:
        for _attempt in range(500):
            with self.store.connect() as connection:
                row = connection.execute(
                    "SELECT * FROM executions WHERE envelope_id=?", (envelope_id,)
                ).fetchone()
            if not row:
                raise ConflictError("durable execution claim disappeared")
            if row["status"] != "CLAIMED":
                return self._execution_from_row(row, replayed=True)
            time.sleep(0.01)
        # Do not invent a terminal state that was never committed. The durable
        # row remains CLAIMED/QUEUED while the dispatch owner is still working.
        return self._execution_from_row(row, replayed=True)

    def execute_envelope(
        self,
        envelope_id: str,
        approval_token: str,
    ) -> ExecutionResult:
        if not isinstance(approval_token, str) or len(approval_token) < 16:
            raise AuthorizationError("approval token is invalid")
        token_hash = _sha256(approval_token.encode("utf-8"))
        connection = self.store.connect()
        dispatch_owner = False
        execution_id: str | None = None
        envelope: DefensiveControlEnvelopeV1
        try:
            connection.execute("BEGIN IMMEDIATE")
            envelope = self._get_envelope(connection, envelope_id)
            self._validate_live_case(connection, envelope)
            approval = connection.execute(
                "SELECT * FROM approvals WHERE envelope_id=? AND token_hash=?",
                (envelope.id, token_hash),
            ).fetchone()
            if not approval:
                raise AuthorizationError("approval is not bound to this envelope")
            existing = connection.execute(
                "SELECT * FROM executions WHERE envelope_id=?", (envelope_id,)
            ).fetchone()
            if existing:
                connection.commit()
                if existing["status"] == "CLAIMED":
                    execution_id = existing["id"]
                else:
                    return self._execution_from_row(existing, replayed=True)
            else:
                if envelope.dry_run:
                    raise AuthorizationError("dry-run envelope cannot execute")
                if _parse_rfc3339(envelope.expires_at, "expires_at") <= _utcnow():
                    raise AuthorizationError("envelope is expired")
                if approval["status"] != "APPROVED" or approval["used_at"] is not None:
                    raise AuthorizationError("approval has already been consumed")
                if not hmac.compare_digest(
                    approval["bound_hash"], envelope.canonical_request_hash
                ):
                    raise AuthorizationError("approval binding diverged")
                if _parse_rfc3339(
                    approval["expires_at"], "approval.expires_at"
                ) <= _utcnow():
                    raise AuthorizationError("approval is expired")
                for target in envelope.target_refs:
                    asset = connection.execute(
                        "SELECT 1 FROM assets WHERE tenant_id=? AND asset_ref=?",
                        (envelope.tenant_id, target),
                    ).fetchone()
                    if not asset:
                        raise AuthorizationError("target is no longer in tenant inventory")

                execution_id = str(uuid.uuid4())
                created_at = _rfc3339()
                connection.execute(
                    """
                    INSERT INTO executions(
                        id, envelope_id, tenant_id, status, remote_id,
                        result_json, created_at, completed_at
                    ) VALUES(?, ?, ?, 'CLAIMED', NULL, ?, ?, NULL)
                    """,
                    (
                        execution_id,
                        envelope.id,
                        envelope.tenant_id,
                        _canonical_bytes(
                            {
                                "state": EvidenceState.QUEUED.value,
                                "retry": False,
                                "idempotencyKey": envelope.idempotency_key,
                            }
                        ).decode("utf-8"),
                        created_at,
                    ),
                )
                connection.execute(
                    "UPDATE approvals SET status='CONSUMED', used_at=? WHERE id=?",
                    (created_at, approval["id"]),
                )
                connection.commit()
                dispatch_owner = True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

        if not dispatch_owner:
            return self._await_execution(envelope_id)

        try:
            connector_result = self._ticket_connector.perform(envelope)
            result_payload = self._validated_connector_result(envelope, connector_result)
            serialized_result = _canonical_bytes(result_payload).decode("utf-8")
            status = "SUCCEEDED"
            remote_id = str(result_payload.get("remoteId") or "") or None
        except Exception as exc:
            status = "BLOCKED_UNCERTAIN"
            remote_id = None
            result_payload = {
                "errorType": type(exc).__name__,
                "remoteOutcome": "UNCERTAIN",
                "retry": False,
            }
            serialized_result = _canonical_bytes(result_payload).decode("utf-8")

        finalize = self.store.connect()
        try:
            finalize.execute("BEGIN IMMEDIATE")
            claimed = finalize.execute(
                "SELECT * FROM executions WHERE id=? AND status='CLAIMED'",
                (execution_id,),
            ).fetchone()
            if not claimed:
                raise ConflictError("execution claim is not reconcilable")
            completed_at = _rfc3339()
            finalize.execute(
                """
                UPDATE executions
                SET status=?, remote_id=?, result_json=?, completed_at=?
                WHERE id=? AND status='CLAIMED'
                """,
                (status, remote_id, serialized_result, completed_at, execution_id),
            )
            if envelope.case_id:
                self._append_evidence(
                    finalize,
                    envelope.tenant_id,
                    envelope.case_id,
                    "response.executed",
                    {
                        "executionId": execution_id,
                        "envelopeId": envelope.id,
                        "status": status,
                        "remoteId": remote_id,
                        "retry": False,
                    },
                )
            finalize.commit()
            row = finalize.execute(
                "SELECT * FROM executions WHERE id=?", (execution_id,)
            ).fetchone()
            return self._execution_from_row(row, replayed=False)
        except Exception as exc:
            finalize.rollback()
            raise ConflictError(
                "connector outcome is uncertain; durable claim retained and automatic retry disabled"
            ) from exc
        finally:
            finalize.close()

    def reconcile_execution(
        self,
        envelope_id: str,
        principal: AuthenticatedPrincipal,
    ) -> ExecutionResult:
        """Authenticated provider read-back without redispatching the action."""

        with self.store.connect() as connection:
            envelope = self._get_envelope(connection, envelope_id)
            self._require_principal(principal, envelope.tenant_id, {"analyst"})
            row = connection.execute(
                "SELECT * FROM executions WHERE envelope_id=?", (envelope_id,)
            ).fetchone()
        if not row:
            raise NotFoundError("execution claim not found")
        if row["status"] not in {"CLAIMED", "BLOCKED_UNCERTAIN"}:
            return self._execution_from_row(row, replayed=True)

        try:
            provider_result = self._ticket_connector.lookup(envelope)
        except Exception as exc:
            return ExecutionResult(
                execution_id=row["id"],
                envelope_id=envelope.id,
                status="BLOCKED_UNCERTAIN",
                remote_id=row["remote_id"],
                result={
                    "errorType": type(exc).__name__,
                    "reason": "connector read-back failed",
                    "retry": False,
                },
                replayed=True,
            )
        if provider_result is None:
            return ExecutionResult(
                execution_id=row["id"],
                envelope_id=envelope.id,
                status="BLOCKED_UNCERTAIN",
                remote_id=row["remote_id"],
                result={
                    "reason": "provider has no observed result for the idempotency key",
                    "retry": False,
                },
                replayed=True,
            )
        result_payload = self._validated_connector_result(envelope, provider_result)
        serialized = _canonical_bytes(result_payload).decode("utf-8")
        remote_id = str(result_payload.get("remoteId") or "") or None

        finalize = self.store.connect()
        try:
            finalize.execute("BEGIN IMMEDIATE")
            current = finalize.execute(
                "SELECT * FROM executions WHERE id=?", (row["id"],)
            ).fetchone()
            if not current:
                raise ConflictError("durable execution claim disappeared")
            if current["status"] not in {"CLAIMED", "BLOCKED_UNCERTAIN"}:
                finalize.commit()
                return self._execution_from_row(current, replayed=True)
            completed_at = _rfc3339()
            finalize.execute(
                """
                UPDATE executions
                SET status='SUCCEEDED', remote_id=?, result_json=?, completed_at=?
                WHERE id=? AND status IN ('CLAIMED', 'BLOCKED_UNCERTAIN')
                """,
                (remote_id, serialized, completed_at, row["id"]),
            )
            if envelope.case_id:
                self._append_evidence(
                    finalize,
                    envelope.tenant_id,
                    envelope.case_id,
                    "response.reconciled",
                    {
                        "executionId": row["id"],
                        "envelopeId": envelope.id,
                        "status": "SUCCEEDED",
                        "remoteId": remote_id,
                        "redispatched": False,
                    },
                )
            finalize.commit()
            reconciled = finalize.execute(
                "SELECT * FROM executions WHERE id=?", (row["id"],)
            ).fetchone()
            return self._execution_from_row(reconciled, replayed=True)
        except Exception:
            finalize.rollback()
            raise
        finally:
            finalize.close()

    def transition_case(
        self,
        case_id: str,
        new_state: str,
        actor: AuthenticatedPrincipal,
    ) -> dict[str, Any]:
        if new_state not in self._CASE_TRANSITIONS:
            raise ValidationError("unknown case state")
        connection = self.store.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if not row:
                raise NotFoundError("case not found")
            actor_identity = self._require_principal(
                actor, row["tenant_id"], {"analyst"}
            )
            current = row["state"]
            if new_state not in self._CASE_TRANSITIONS.get(current, set()):
                raise ConflictError(f"case cannot transition from {current} to {new_state}")
            updated_at = _rfc3339()
            connection.execute(
                "UPDATE cases SET state=?, updated_at=? WHERE id=?",
                (new_state, updated_at, case_id),
            )
            self._append_evidence(
                connection,
                row["tenant_id"],
                case_id,
                "case.transitioned",
                {"from": current, "to": new_state, "actor": actor_identity},
            )
            connection.commit()
            return {
                "caseId": case_id,
                "from": current,
                "to": new_state,
                "actor": actor_identity,
                "updatedAt": updated_at,
            }
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _case_payload(
        self,
        connection: sqlite3.Connection,
        case_id: str,
        tenant_id: str,
    ) -> dict[str, Any]:
        case = connection.execute(
            "SELECT * FROM cases WHERE id=? AND tenant_id=?", (case_id, tenant_id)
        ).fetchone()
        if not case:
            raise NotFoundError("case not found")
        events = connection.execute(
            """
            SELECT DISTINCT events.* FROM events
            JOIN alerts ON alerts.event_id=events.id
            WHERE alerts.case_id=? AND alerts.tenant_id=? AND events.tenant_id=?
            ORDER BY events.created_at, events.id
            """,
            (case_id, tenant_id, tenant_id),
        ).fetchall()
        alerts = connection.execute(
            "SELECT * FROM alerts WHERE case_id=? AND tenant_id=? ORDER BY created_at, id",
            (case_id, tenant_id),
        ).fetchall()
        envelopes = connection.execute(
            "SELECT * FROM envelopes WHERE case_id=? AND tenant_id=? ORDER BY created_at, id",
            (case_id, tenant_id),
        ).fetchall()
        approvals = connection.execute(
            """
            SELECT approvals.id, approvals.envelope_id, approvals.tenant_id,
                   approvals.bound_hash, approvals.approver, approvals.expires_at,
                   approvals.status, approvals.used_at, approvals.created_at
            FROM approvals JOIN envelopes ON envelopes.id=approvals.envelope_id
            WHERE envelopes.case_id=? AND envelopes.tenant_id=?
              AND approvals.tenant_id=?
            ORDER BY approvals.created_at, approvals.id
            """,
            (case_id, tenant_id, tenant_id),
        ).fetchall()
        executions = connection.execute(
            """
            SELECT executions.* FROM executions
            JOIN envelopes ON envelopes.id=executions.envelope_id
            WHERE envelopes.case_id=? AND envelopes.tenant_id=?
              AND executions.tenant_id=?
            ORDER BY executions.created_at, executions.id
            """,
            (case_id, tenant_id, tenant_id),
        ).fetchall()
        evidence = connection.execute(
            "SELECT * FROM evidence WHERE case_id=? AND tenant_id=? ORDER BY rowid",
            (case_id, tenant_id),
        ).fetchall()
        return {
            "schema": "CaseEvidenceBundlePayloadV1",
            "case": dict(case),
            "events": [dict(row) for row in events],
            "alerts": [dict(row) for row in alerts],
            "envelopes": [dict(row) for row in envelopes],
            "approvals": [dict(row) for row in approvals],
            "executions": [dict(row) for row in executions],
            "evidence": [dict(row) for row in evidence],
        }

    def export_case(
        self,
        case_id: str,
        principal: AuthenticatedPrincipal,
    ) -> dict[str, Any]:
        connection = self.store.connect()
        try:
            connection.execute("BEGIN")
            case = connection.execute(
                "SELECT tenant_id FROM cases WHERE id=?", (case_id,)
            ).fetchone()
            if not case:
                raise NotFoundError("case not found")
            tenant_id = case["tenant_id"]
            self._require_principal(principal, tenant_id, {"auditor", "analyst"})
            payload = self._case_payload(connection, case_id, tenant_id)
            evidence_rows = payload["evidence"]
            if not self._verify_evidence_rows(evidence_rows, tenant_id, case_id):
                raise ConflictError("case evidence chain is empty or invalid")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        payload_bytes = _canonical_bytes(payload)
        digest = _sha256(payload_bytes)
        signature = hmac.new(
            self._evidence_signing_key, payload_bytes, hashlib.sha256
        ).hexdigest()
        return {
            "schema": "CaseEvidenceBundleV1",
            "payload": payload,
            "payloadDigest": digest,
            "signature": signature,
            "signatureAlgorithm": "HMAC-SHA256-LOCAL-TEST",
            "state": EvidenceState.VERIFIED_LOCAL.value,
        }

    def _verify_evidence_rows(
        self,
        rows: Sequence[Mapping[str, Any]],
        expected_tenant_id: str | None = None,
        expected_case_id: str | None = None,
    ) -> bool:
        if not rows:
            return False
        previous = ZERO_HASH
        for row in rows:
            try:
                if (
                    expected_tenant_id is not None
                    and row["tenant_id"] != expected_tenant_id
                ):
                    return False
                if expected_case_id is not None and row["case_id"] != expected_case_id:
                    return False
                if row["previous_hash"] != previous:
                    return False
                payload = json.loads(row["payload_json"])
                protected = {
                    "tenantId": row["tenant_id"],
                    "caseId": row["case_id"],
                    "kind": row["kind"],
                    "payload": payload,
                    "previousHash": row["previous_hash"],
                    "createdAt": row["created_at"],
                }
                expected = _sha256(_canonical_bytes(protected))
                if not hmac.compare_digest(expected, row["entry_hash"]):
                    return False
                previous = row["entry_hash"]
            except (
                KeyError,
                IndexError,
                TypeError,
                ValueError,
                OverflowError,
                RecursionError,
                ValidationError,
            ):
                return False
        return True

    def verify_case_export(self, bundle: Mapping[str, Any]) -> bool:
        if not isinstance(bundle, Mapping):
            return False
        try:
            if bundle.get("schema") != "CaseEvidenceBundleV1":
                return False
            payload = bundle["payload"]
            if not isinstance(payload, Mapping):
                return False
            payload_bytes = _canonical_bytes(payload)
            if not hmac.compare_digest(_sha256(payload_bytes), bundle["payloadDigest"]):
                return False
            expected_signature = hmac.new(
                self._evidence_signing_key, payload_bytes, hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(expected_signature, bundle["signature"]):
                return False
            case = payload["case"]
            if not isinstance(case, Mapping):
                return False
            tenant_id = case["tenant_id"]
            case_id = case["id"]
            for section in (
                "events",
                "alerts",
                "envelopes",
                "approvals",
                "executions",
                "evidence",
            ):
                rows = payload[section]
                if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
                    return False
                if any(
                    not isinstance(row, Mapping) or row.get("tenant_id") != tenant_id
                    for row in rows
                ):
                    return False
            if any(row.get("case_id") != case_id for row in payload["alerts"]):
                return False
            if any(row.get("case_id") != case_id for row in payload["envelopes"]):
                return False
            return self._verify_evidence_rows(
                payload.get("evidence", []), tenant_id, case_id
            )
        except (KeyError, TypeError, ValidationError):
            return False

    def verify_evidence_chain(self, case_id: str | None = None) -> bool:
        with self.store.connect() as connection:
            if not self.store._tenant_bindings_valid(connection):
                return False
            if case_id:
                case = connection.execute(
                    "SELECT tenant_id FROM cases WHERE id=?", (case_id,)
                ).fetchone()
                if not case:
                    return False
                rows = connection.execute(
                    "SELECT * FROM evidence WHERE case_id=? AND tenant_id=? ORDER BY rowid",
                    (case_id, case["tenant_id"]),
                ).fetchall()
                return self._verify_evidence_rows(rows, case["tenant_id"], case_id)
            cases = connection.execute(
                "SELECT id, tenant_id FROM cases ORDER BY id"
            ).fetchall()
            return all(
                self._verify_evidence_rows(
                    connection.execute(
                        "SELECT * FROM evidence WHERE case_id=? AND tenant_id=? ORDER BY rowid",
                        (row["id"], row["tenant_id"]),
                    ).fetchall(),
                    row["tenant_id"],
                    row["id"],
                )
                for row in cases
            )

    @staticmethod
    def _table_snapshot(
        connection: sqlite3.Connection, table: str
    ) -> dict[str, Any]:
        columns = [row["name"] for row in connection.execute(f"PRAGMA table_info({table})")]
        rows = [
            [row[column] for column in columns]
            for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid")
        ]
        return {
            "count": len(rows),
            "sha256": _sha256(_canonical_bytes({"columns": columns, "rows": rows})),
        }

    @staticmethod
    def _schema_snapshot(connection: sqlite3.Connection) -> dict[str, Any]:
        rows = [
            [row["type"], row["name"], row["tbl_name"], row["sql"]]
            for row in connection.execute(
                """
                SELECT type, name, tbl_name, sql FROM sqlite_master
                WHERE type IN ('table', 'index', 'trigger')
                  AND name NOT LIKE 'sqlite_%'
                ORDER BY type, name
                """
            )
        ]
        return {
            "count": len(rows),
            "sha256": _sha256(_canonical_bytes(rows)),
        }

    def run_backup_restore_drill(self) -> dict[str, Any]:
        started = time.monotonic()
        tables = (
            "metadata",
            "assets",
            "principals",
            "events",
            "quarantined_events",
            "cases",
            "alerts",
            "envelopes",
            "approvals",
            "executions",
            "evidence",
            "verification_receipts",
        )
        with tempfile.TemporaryDirectory(prefix="defensive-restore-") as directory:
            restored_path = Path(directory) / "restored.sqlite3"
            source = self.store.connect()
            target = sqlite3.connect(restored_path)
            try:
                source.execute("BEGIN")
                self.store._validate_schema(source)
                original_snapshots = {
                    table: self._table_snapshot(source, table) for table in tables
                }
                original_schema = self._schema_snapshot(source)
                source.backup(target)
                source.commit()
            finally:
                target.close()
                source.close()
            backup_digest = _sha256(restored_path.read_bytes())
            raw_restored = sqlite3.connect(restored_path)
            raw_restored.row_factory = sqlite3.Row
            try:
                integrity = raw_restored.execute("PRAGMA integrity_check").fetchone()[0]
                user_version = int(raw_restored.execute("PRAGMA user_version").fetchone()[0])
                self.store._validate_schema(raw_restored)
                restored_snapshots = {
                    table: self._table_snapshot(raw_restored, table) for table in tables
                }
                restored_schema = self._schema_snapshot(raw_restored)
            finally:
                raw_restored.close()
            if integrity != "ok" or user_version != SCHEMA_VERSION:
                raise ConflictError("untouched backup failed integrity or schema verification")
            if original_snapshots != restored_snapshots:
                raise ConflictError("untouched backup content digests diverged")
            if original_schema != restored_schema:
                raise ConflictError("untouched backup schema digest diverged")
            restored = ControlPlane(
                restored_path, self._event_signing_key, self._evidence_signing_key
            )
            chain_valid = restored.verify_evidence_chain()
            has_cases = restored_snapshots["cases"]["count"] > 0
            has_evidence = restored_snapshots["evidence"]["count"] > 0
            if not chain_valid or (has_cases and not has_evidence):
                raise ConflictError("disposable restore verification failed")
        return {
            "state": EvidenceState.VERIFIED_LOCAL.value,
            "scope": "disposable-local-sqlite",
            "productionRestore": False,
            "integrityCheck": "ok",
            "countsMatch": True,
            "contentDigestsMatch": True,
            "schemaDigestMatch": True,
            "evidenceChainValid": True,
            "backupDigest": backup_digest,
            "elapsedMs": round((time.monotonic() - started) * 1000, 3),
        }

    def record_local_verification(self, suite: str, evidence_digest: str) -> str:
        suite = _identifier(suite, "suite")
        if not re.fullmatch(r"[0-9a-f]{64}", evidence_digest):
            raise ValidationError("evidence_digest must be a lowercase SHA-256 digest")
        receipt_id = str(uuid.uuid4())
        with self.store.connect() as connection:
            connection.execute(
                "INSERT INTO verification_receipts(id, suite, evidence_digest, created_at) VALUES(?, ?, ?, ?)",
                (receipt_id, suite, evidence_digest, _rfc3339()),
            )
        return receipt_id

    def build_info(self) -> dict[str, Any]:
        revision = os.environ.get("CONTROL_PLANE_REVISION")
        return {
            "service": "defensive-control-plane",
            "version": PACKAGE_VERSION,
            "schemaVersion": SCHEMA_VERSION,
            "sourceRevision": revision,
            "state": EvidenceState.PARTIAL.value,
            "revisionAttestation": EvidenceState.PARTIAL.value,
            "deploymentVerified": False,
            "scope": "local",
        }

    def livez(self) -> dict[str, Any]:
        return {
            "status": "alive",
            "state": EvidenceState.VERIFIED_LOCAL.value,
            "scope": "local-process",
        }

    def readyz(self) -> dict[str, Any]:
        try:
            with self.store.connect() as connection:
                self.store._validate_schema(connection)
                integrity = connection.execute("PRAGMA quick_check").fetchone()[0]
                user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                required_triggers = {
                    row["name"]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
                tenant_bindings_valid = self.store._tenant_bindings_valid(connection)
                connection.execute("BEGIN IMMEDIATE")
                write_probe = connection.execute(
                    "UPDATE metadata SET value=value WHERE key='schema_version'"
                )
                writable = write_probe.rowcount == 1
                connection.rollback()
            chain_valid = self.verify_evidence_chain()
            ready = bool(
                integrity == "ok"
                and user_version == SCHEMA_VERSION
                and {
                    "evidence_no_update",
                    "evidence_no_delete",
                    "envelope_no_update",
                    "envelope_no_delete",
                    "alert_tenant_insert",
                    "alert_tenant_update",
                    "envelope_case_tenant_insert",
                    "approval_tenant_insert",
                    "approval_tenant_update",
                    "execution_tenant_insert",
                    "execution_tenant_update",
                    "evidence_tenant_insert",
                }.issubset(required_triggers)
                and tenant_bindings_valid
                and writable
                and chain_valid
            )
        except (
            sqlite3.Error,
            ValueError,
            OverflowError,
            RecursionError,
            TypeError,
            KeyError,
            ValidationError,
            ConflictError,
        ):
            ready = False
        return {
            "status": "ready" if ready else "not_ready",
            "state": (
                EvidenceState.VERIFIED_LOCAL.value
                if ready
                else EvidenceState.FAILED_CLOSED.value
            ),
            "scope": "local",
            "database": "ready" if ready else "unavailable",
            "schemaVersion": SCHEMA_VERSION,
            "evidenceChain": "valid" if ready else "unavailable_or_invalid",
            "productionReady": False,
            "externalConnectors": EvidenceState.UNAVAILABLE.value,
        }

    def lane_statuses(self) -> dict[str, Any]:
        with self.store.connect() as connection:
            receipt_count = int(
                connection.execute("SELECT COUNT(*) FROM verification_receipts").fetchone()[0]
            )
        # A caller-written digest is retained for audit, but never self-promotes a
        # lane. Only the external verification report may claim VERIFIED_LOCAL.
        local_state = EvidenceState.PARTIAL.value
        evidence_ids: list[str] = []
        return {
            "scope": "local-only",
            "productionOperational": False,
            "selfReportedReceiptCount": receipt_count,
            "selfReportedReceiptsState": EvidenceState.PARTIAL.value,
            "lanes": [
                {"name": "cybersecurity", "state": local_state, "evidenceIds": evidence_ids},
                {"name": "product", "state": EvidenceState.PARTIAL.value, "evidenceIds": evidence_ids},
                {"name": "engineering", "state": local_state, "evidenceIds": evidence_ids},
                {"name": "data-ai", "state": EvidenceState.UNAVAILABLE.value, "evidenceIds": []},
                {"name": "operations", "state": EvidenceState.PARTIAL.value, "evidenceIds": evidence_ids},
                {"name": "people", "state": EvidenceState.UNAVAILABLE.value, "evidenceIds": []},
                {"name": "governance", "state": EvidenceState.PARTIAL.value, "evidenceIds": evidence_ids},
            ],
            "connectors": [
                {"name": name, "state": EvidenceState.UNAVAILABLE.value, "observedAt": None}
                for name in ("identity", "endpoint", "siem", "email", "cloud", "ticketing")
            ],
        }
