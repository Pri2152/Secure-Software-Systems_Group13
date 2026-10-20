"""
SR-17: Audit log table.

Security controls:
- One append-only table for every workstream's
  security events (centralised audit log)
- Sequence numbers are per stream and unique per
  stream, so gaps and duplicates are detectable
- Server-side UTC timestamp and actor identity on
  every entry (except the anonymous ballot stream)
- Database triggers abort every UPDATE and DELETE on
  the audit table (defence in depth below the app);
  SQLite triggers are created with the table, MySQL
  triggers are in deploy/db/audit_triggers.sql
- Separate metadata from the voter/identity models:
  the table lives in the audit database (E's "audit"
  bind / EVP_AUDIT_DB_URL), never in the identity DB

Local academic prototype.
"""

import json

from sqlalchemy import DDL, Integer, String, Text, UniqueConstraint, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


AUDIT_TABLE = "audit_log"

HASH_COLUMN_LENGTH = 512

APPEND_ONLY_MESSAGE = "audit_log is append-only"
NO_UPDATE_TRIGGER = "audit_log_no_update"
NO_DELETE_TRIGGER = "audit_log_no_delete"


class AuditBase(DeclarativeBase):
    """Metadata for the audit database only."""


class AuditEntry(AuditBase):
    __tablename__ = AUDIT_TABLE
    __table_args__ = (
        UniqueConstraint("stream", "seq", name="uq_audit_stream_seq"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    stream: Mapped[str] = mapped_column(String(16), nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp_utc: Mapped[str] = mapped_column(String(32), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(128))
    source_ip: Mapped[str | None] = mapped_column(String(45))
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    details_json: Mapped[str] = mapped_column(Text, nullable=False)
    prev_hash: Mapped[str] = mapped_column(
        String(HASH_COLUMN_LENGTH), nullable=False
    )
    entry_hash: Mapped[str] = mapped_column(
        String(HASH_COLUMN_LENGTH), nullable=False
    )

    def to_public_dict(self) -> dict:
        """Fields an auditor may see (no chain internals)."""

        return {
            "stream": self.stream,
            "seq": self.seq,
            "timestamp_utc": self.timestamp_utc,
            "event_type": self.event_type,
            "actor_type": self.actor_type,
            "actor_id": self.actor_id,
            "source_ip": self.source_ip,
            "outcome": self.outcome,
            "details": json.loads(self.details_json),
        }


def _sqlite_block_trigger(name: str, operation: str) -> DDL:
    return DDL(
        f"CREATE TRIGGER IF NOT EXISTS {name} "
        f"BEFORE {operation} ON {AUDIT_TABLE} "
        f"BEGIN SELECT RAISE(ABORT, '{APPEND_ONLY_MESSAGE}'); END"
    ).execute_if(dialect="sqlite")


event.listen(
    AuditEntry.__table__,
    "after_create",
    _sqlite_block_trigger(NO_UPDATE_TRIGGER, "UPDATE"),
)
event.listen(
    AuditEntry.__table__,
    "after_create",
    _sqlite_block_trigger(NO_DELETE_TRIGGER, "DELETE"),
)


def ensure_triggers(engine) -> None:
    """
    (Re)create the SQLite triggers on an existing
    table. Idempotent; MySQL uses the deploy SQL file.
    """

    if engine.dialect.name != "sqlite":
        return

    with engine.begin() as connection:
        for name, operation in (
            (NO_UPDATE_TRIGGER, "UPDATE"),
            (NO_DELETE_TRIGGER, "DELETE"),
        ):
            connection.execute(_sqlite_block_trigger(name, operation))
