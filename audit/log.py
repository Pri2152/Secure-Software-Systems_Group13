"""
SR-17: Master audit logging routine.

Security controls:
- One master routine (AuditLog.record_event) through
  which every workstream writes security events
  (secure logger pattern)
- Every event is validated against the audit
  contract and its details pass the sensitive-data
  filter before anything is stored
- Server-side UTC time from an injectable clock;
  callers cannot supply the timestamp
- Insert-only access: this module never updates or
  deletes audit rows
- Reading is a separate component used only by the
  auditor endpoints

Local academic prototype.
"""

import json
import threading

from collections.abc import Callable
from datetime import datetime, timezone

from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from .events import STREAMS, validate_event
from .filters import sanitize_details
from .models import AuditBase, AuditEntry


MAX_READ_LIMIT = 200


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_timestamp(moment: datetime) -> str:
    """ISO 8601 UTC with microseconds, e.g. 2026-10-20T09:15:00.000000Z."""

    if not isinstance(moment, datetime) or moment.tzinfo is None:
        raise ValueError("Audit clock must return an aware datetime")

    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical_json(value) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


class AuditLog:
    """Writer and reader for the central audit table."""

    def __init__(
        self,
        engine: Engine,
        *,
        clock: Callable[[], datetime] | None = None,
    ):
        self.engine = engine
        self.clock = clock or utc_now
        self._sessions = sessionmaker(bind=engine, expire_on_commit=False)
        self._write_lock = threading.Lock()

    def create_schema(self) -> None:
        AuditBase.metadata.create_all(self.engine)

    def record_event(
        self,
        event_type: str,
        *,
        stream: str,
        actor_type: str,
        actor_id: str | None,
        outcome: str,
        details: dict | None = None,
        source_ip: str | None = None,
    ) -> None:
        """Validate, filter and append one audit event."""

        validate_event(
            event_type, stream, actor_type, actor_id, outcome, source_ip
        )

        details_json = canonical_json(sanitize_details(details))

        with self._write_lock, self._sessions.begin() as db_session:
            entry = AuditEntry(
                stream=stream,
                seq=self._last_seq(db_session, stream) + 1,
                timestamp_utc=format_timestamp(self.clock()),
                event_type=event_type,
                actor_type=actor_type,
                actor_id=actor_id,
                source_ip=source_ip,
                outcome=outcome,
                details_json=details_json,
            )

            db_session.add(entry)

    def list_events(self, stream: str, limit: int = 50) -> list[dict]:
        """Most recent entries of one stream, newest first."""

        if stream not in STREAMS:
            raise ValueError("Invalid audit stream")

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_READ_LIMIT
        ):
            raise ValueError("Invalid read limit")

        with self._sessions() as db_session:
            entries = db_session.scalars(
                select(AuditEntry)
                .where(AuditEntry.stream == stream)
                .order_by(AuditEntry.seq.desc())
                .limit(limit)
            ).all()

        return [entry.to_public_dict() for entry in entries]

    @staticmethod
    def _last_seq(db_session: Session, stream: str) -> int:
        return db_session.scalar(
            select(func.coalesce(func.max(AuditEntry.seq), 0)).where(
                AuditEntry.stream == stream
            )
        )
