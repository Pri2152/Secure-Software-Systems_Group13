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
- Per-stream HMAC hash chains via crypto_agility
  (SR-14) make edits, deletions and reordering
  detectable (AuditLog.verify_chain)
- AuditLogHandler captures Workstream A's evp.* security
  log events as identity-stream audit events
  (install_audit_handler at application start-up)
- Signed checkpoints every 50 entries per stream go to
  a separate append-only archive (EVP_AUDIT_ARCHIVE)
- Fails closed: if no audit database is configured,
  record_event raises AuditNotConfigured instead of
  silently dropping security events

Configuration (environment):
- EVP_AUDIT_DB_URL   SQLAlchemy URL of the audit database
- EVP_AUDIT_ARCHIVE  checkpoint archive file (separate volume);
                     without it, checkpoints are disabled and a
                     warning is logged

Local academic prototype.
"""

import logging
import os
import threading

from sqlalchemy import create_engine

from .chain import ChainResult
from .checkpoints import (
    CHECKPOINT_INTERVAL,
    ENV_AUDIT_ARCHIVE,
    ArchiveNotConfigured,
    CheckpointArchive,
    CheckpointResult,
)
from .events import (
    STREAM_ADMIN,
    STREAM_BALLOT,
    STREAM_IDENTITY,
    STREAMS,
)
from .handler import AuditLogHandler, install_audit_handler
from .log import AuditLog


ENV_AUDIT_DB_URL = "EVP_AUDIT_DB_URL"

logger = logging.getLogger("evp.audit")


class AuditNotConfigured(RuntimeError):
    """No audit database is configured; events are refused."""


_audit_log: AuditLog | None = None
_audit_lock = threading.Lock()


def build_audit_log_from_env(environ=None) -> AuditLog:
    environ = os.environ if environ is None else environ
    url = environ.get(ENV_AUDIT_DB_URL)

    if not url:
        raise AuditNotConfigured("No audit database is configured")

    archive_path = environ.get(ENV_AUDIT_ARCHIVE)

    if not archive_path:
        logger.warning("audit_checkpoint_archive_not_configured")

    audit_log = AuditLog(
        create_engine(url),
        archive=CheckpointArchive(archive_path) if archive_path else None,
    )
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


def verify_chain(stream: str) -> ChainResult:
    return get_audit_log().verify_chain(stream)


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
