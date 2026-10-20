"""
SR-17: Audit log table.

Security controls:
- One append-only table for every workstream's
  security events (centralised audit log)
- Sequence numbers are per stream and unique per
  stream, so gaps and duplicates are detectable
- Server-side UTC timestamp and actor identity on
  every entry (except the anonymous ballot stream)
- Separate metadata from the voter/identity models:
  the table lives in the audit database (E's "audit"
  bind / EVP_AUDIT_DB_URL), never in the identity DB

Local academic prototype.
"""

import json

from sqlalchemy import Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


AUDIT_TABLE = "audit_log"

HASH_COLUMN_LENGTH = 512


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
