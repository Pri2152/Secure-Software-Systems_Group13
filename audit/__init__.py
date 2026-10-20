"""
SR-17: Centralised, append-only, tamper-evident audit log (Workstream B).

Usage (handbook section 6.2):

    from audit import record_event

    record_event(
        "AUTHZ_DENIED",
        stream="identity",          # "identity" | "ballot" | "admin"
        actor_type="voter",         # "voter" | "staff" | "system" | "anonymous"
        actor_id=session.get("voter_id"),   # None on the ballot stream
        outcome="denied",           # "success" | "failure" | "denied"
        details={"permission": "records.read_own"},
        source_ip=None,             # None on the ballot stream
    )

Security controls:
- One master logging routine for every workstream
- Sensitive-data filter before storage (secure logger)
- Three separate streams; the ballot stream never
  records who acted or from where (SR-08)
- Fails closed: if no audit database is configured,
  record_event raises AuditNotConfigured instead of
  silently dropping security events

Configuration (environment):
- EVP_AUDIT_DB_URL   SQLAlchemy URL of the audit database

Local academic prototype.
"""

import os
import threading

from sqlalchemy import create_engine

from .events import (
    STREAM_ADMIN,
    STREAM_BALLOT,
    STREAM_IDENTITY,
    STREAMS,
)
from .log import AuditLog


ENV_AUDIT_DB_URL = "EVP_AUDIT_DB_URL"


class AuditNotConfigured(RuntimeError):
    """No audit database is configured; events are refused."""


_audit_log: AuditLog | None = None
_audit_lock = threading.Lock()


def build_audit_log_from_env(environ=None) -> AuditLog:
    environ = os.environ if environ is None else environ
    url = environ.get(ENV_AUDIT_DB_URL)

    if not url:
        raise AuditNotConfigured("No audit database is configured")

    audit_log = AuditLog(create_engine(url))
    audit_log.create_schema()

    return audit_log


def configure(audit_log: AuditLog | None) -> None:
    """Install the AuditLog used by record_event; None resets it."""

    global _audit_log

    if audit_log is not None and not isinstance(audit_log, AuditLog):
        raise TypeError("configure() needs an AuditLog")

    with _audit_lock:
        _audit_log = audit_log


def get_audit_log() -> AuditLog:
    global _audit_log

    with _audit_lock:
        if _audit_log is None:
            _audit_log = build_audit_log_from_env()

        return _audit_log


def record_event(
    event_type: str,
    *,
    stream: str,
    actor_type: str,
    actor_id: str | None,
    outcome: str,
    details: dict | None = None,
    source_ip: str | None = None,
) -> None:
    """Append one security event to the central audit log."""

    get_audit_log().record_event(
        event_type,
        stream=stream,
        actor_type=actor_type,
        actor_id=actor_id,
        outcome=outcome,
        details=details,
        source_ip=source_ip,
    )
