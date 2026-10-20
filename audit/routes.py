"""
SR-17: Auditor-only audit read and verify endpoints.

Security controls:
- Reading the log ("audit.read") and verifying it
  ("audit.verify") each need their own permission,
  enforced by the injected SR-04 decorator
  (Workstream E's require_permission): 401 without a
  login, 403 for any role without the permission
- Writing and reading are separate components: these
  routes only read; nothing here can change the log
- Strict query validation: unknown parameters,
  unknown streams and out-of-range limits get 400
- Responses carry event fields only, never hashes,
  MAC envelopes or key material; details were already
  filtered for secrets when stored
- Every successful read or verification is itself
  audited on the admin stream; if that record cannot
  be written, the request fails (no unlogged access)
- Generic error messages; failures go to the log

Local academic prototype.
"""

import logging

from collections.abc import Callable

from flask import Blueprint, jsonify, request, session

from .events import STREAM_ADMIN, STREAMS


DEFAULT_READ_LIMIT = 50
MAX_READ_LIMIT = 200
MAX_LIMIT_DIGITS = 3

EVENTS_PARAMETERS = frozenset({"stream", "limit"})
VERIFY_PARAMETERS = frozenset({"stream"})

logger = logging.getLogger("evp.audit")


def _bad_request():
    return jsonify({"error": "Invalid request"}), 400


def _unavailable():
    return jsonify({"error": "Audit service unavailable"}), 503


def _stream_parameter(allowed: frozenset):
    """The validated stream, or None if the query is invalid."""

    if not set(request.args) <= allowed:
        return None

    stream = request.args.get("stream")

    return stream if stream in STREAMS else None


def _limit_parameter():
    value = request.args.get("limit")

    if value is None:
        return DEFAULT_READ_LIMIT

    if (
        not value.isascii()
        or not value.isdigit()
        or len(value) > MAX_LIMIT_DIGITS
    ):
        return None

    limit = int(value)

    return limit if 1 <= limit <= MAX_READ_LIMIT else None


def create_audit_blueprint(
    require_permission: Callable,
    audit_reader,
    *,
    audit: Callable | None = None,
) -> Blueprint:
    """
    require_permission: SR-04 decorator factory, e.g.
        platform_security.rbac.require_permission
    audit_reader: an AuditLog (list_events, verify_chain,
        verify_checkpoints, archive)
    audit: where access to the log is recorded
        (default: audit_reader.record_event)
    """

    if not callable(require_permission):
        raise TypeError("require_permission must be callable")

    record_access = audit or audit_reader.record_event
    blueprint = Blueprint("audit", __name__)

    def audited(event_type: str, stream: str) -> None:
        record_access(
            event_type,
            stream=STREAM_ADMIN,
            actor_type="staff",
            actor_id=session.get("staff_id") or None,
            outcome="success",
            details={"stream": stream},
        )

    @blueprint.get("/audit/events")
    @require_permission("audit.read")
    def read_events():
        stream = _stream_parameter(EVENTS_PARAMETERS)
        limit = _limit_parameter()

        if stream is None or limit is None:
            return _bad_request()

        try:
            events = audit_reader.list_events(stream, limit)
            audited("AUDIT_LOG_READ", stream)
        except Exception:
            logger.exception("audit_read_failed")
            return _unavailable()

        return jsonify({"stream": stream, "events": events}), 200

    @blueprint.get("/audit/verify")
    @require_permission("audit.verify")
    def verify_log():
        stream = _stream_parameter(VERIFY_PARAMETERS)

        if stream is None:
            return _bad_request()

        try:
            result = audit_reader.verify_chain(stream).to_dict()

            if audit_reader.archive is not None:
                result["checkpoints"] = (
                    audit_reader.verify_checkpoints().to_dict()
                )

            audited("AUDIT_LOG_VERIFIED", stream)

        except Exception:
            logger.exception("audit_verify_failed")
            return _unavailable()

        return jsonify(result), 200

    return blueprint
