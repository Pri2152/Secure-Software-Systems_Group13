"""
SR-17: Bridge from Workstream A's security logs to the audit log.

Security controls:
- A logging.Handler on the "evp" logger namespace turns
  Workstream A's existing security log lines
  (evp.login, evp.authentication, evp.mission_access,
  evp.gateway_security) into identity-stream audit
  events, without editing Workstream A's code
- Only known message names are mapped (allow-list);
  only allow-listed "key=value" details with simple
  values are kept, so free text never reaches the log
- Actor and source come from trusted server-side
  state (Flask session and SR-07 gateway result),
  never from the log text
- An audit failure never breaks the login flow: the
  error is reported through logging's error handling
- Re-entrancy guard: events raised while auditing are
  not audited again

Local academic prototype.
"""

import ipaddress
import logging
import re
import threading

from collections.abc import Callable

from flask import g, has_request_context, request, session

from .events import STREAM_IDENTITY


EVP_LOGGER_NAME = "evp"
OWN_LOGGER_PREFIXES = ("evp.audit", "evp.crypto")

# message name -> (event type, outcome, actor type)
EVENT_MAP = {
    "authentication_success": ("AUTH_SUCCESS", "success", "voter"),
    "authentication_rejected": ("AUTH_FAILURE", "failure", "anonymous"),
    "authentication_invalid_source": (
        "AUTH_INVALID_SOURCE", "failure", "anonymous"
    ),
    "authentication_rate_limited": (
        "AUTH_RATE_LIMITED", "denied", "anonymous"
    ),
    "rate_limit_reached": ("RATE_LIMIT_REACHED", "denied", "system"),
    "mission_access_denied": (
        "MISSION_ACCESS_DENIED", "denied", "anonymous"
    ),
    "gateway_access_denied": (
        "GATEWAY_ACCESS_DENIED", "denied", "anonymous"
    ),
}

DETAIL_KEYS = frozenset({"reason", "scope"})
DETAIL_VALUE_PATTERN = re.compile(r"[a-z0-9_]{1,64}")


def flask_request_context() -> dict:
    """
    Voter ID and source IP from trusted server-side
    request state, when a Flask request is active.
    """

    if not has_request_context():
        return {}

    return {
        "voter_id": session.get("voter_id"),
        "source_ip": g.get("sr07_source_ip") or request.remote_addr,
    }


def _valid_ip(value):
    if not isinstance(value, str):
        return None

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return None

    return value


def parse_details(tokens) -> dict:
    details = {}

    for token in tokens:
        key, separator, value = token.partition("=")

        if (
            separator
            and key in DETAIL_KEYS
            and DETAIL_VALUE_PATTERN.fullmatch(value)
        ):
            details[key] = value

    return details


class AuditLogHandler(logging.Handler):
    """Turns known evp.* security log records into audit events."""

    def __init__(
        self,
        audit: Callable | None = None,
        context_provider: Callable[[], dict] = flask_request_context,
    ):
        super().__init__(level=logging.INFO)

        self._audit = audit
        self._context_provider = context_provider
        self._guard = threading.local()

    def emit(self, record: logging.LogRecord) -> None:
        if record.name.startswith(OWN_LOGGER_PREFIXES):
            return

        if getattr(self._guard, "active", False):
            return

        self._guard.active = True

        try:
            self._audit_record(record)
        except Exception:
            self.handleError(record)
        finally:
            self._guard.active = False

    def _audit_record(self, record: logging.LogRecord) -> None:
        tokens = record.getMessage().split()

        if not tokens or tokens[0] not in EVENT_MAP:
            return

        event_type, outcome, actor_type = EVENT_MAP[tokens[0]]
        context = self._context_provider() or {}

        actor_id = context.get("voter_id") if actor_type == "voter" else None

        if not isinstance(actor_id, str) or not actor_id:
            actor_id = None

        self._target()(
            event_type,
            stream=STREAM_IDENTITY,
            actor_type=actor_type,
            actor_id=actor_id,
            outcome=outcome,
            details={"source": record.name, **parse_details(tokens[1:])},
            source_ip=_valid_ip(context.get("source_ip")),
        )

    def _target(self) -> Callable:
        if self._audit is not None:
            return self._audit

        # Imported here: the package __init__ imports this module
        from . import record_event

        return record_event


def install_audit_handler(
    audit: Callable | None = None,
    context_provider: Callable[[], dict] = flask_request_context,
) -> AuditLogHandler:
    """
    Attach one AuditLogHandler to the "evp" logger.
    INFO records (e.g. authentication_success) must
    reach it, so the logger level is lowered to INFO
    when it is unset or higher.
    """

    logger = logging.getLogger(EVP_LOGGER_NAME)

    for existing in list(logger.handlers):
        if isinstance(existing, AuditLogHandler):
            logger.removeHandler(existing)

    if logger.level == logging.NOTSET or logger.level > logging.INFO:
        logger.setLevel(logging.INFO)

    handler = AuditLogHandler(audit, context_provider)
    logger.addHandler(handler)

    return handler


def remove_audit_handler(handler: AuditLogHandler) -> None:
    logging.getLogger(EVP_LOGGER_NAME).removeHandler(handler)
