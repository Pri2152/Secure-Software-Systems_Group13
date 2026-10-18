
"""
SR-04: Role-based, deny-by-default access control.

Security controls:
- Central role -> permission matrix (least privilege)
- Read-only matrix, so it cannot be changed at runtime
- Unknown roles or permissions are denied
- Role read from the server-side session only,
  never from request JSON, query or headers
- Denied requests are reported to the audit hook (SR-17)

Draft matrix: staff permissions await Workstream B
review (SR-06). Local academic prototype.
"""

import logging

from functools import wraps
from types import MappingProxyType

from flask import jsonify, session


logger = logging.getLogger("evp.rbac")


ROLE_PERMISSIONS = MappingProxyType({
    "voter": frozenset({
        "records.read_own",
        "records.update_own_address",
        "ballot.request_entitlement",
    }),
    "officer": frozenset({
        "roll.propose_bulk",
        "roll.approve_bulk",
        "candidates.read",
    }),
    "delegate": frozenset({
        "candidates.enter",
        "candidates.propose_finalise",
        "candidates.approve_finalise",
        "candidates.propose_exclusion",
        "candidates.approve_exclusion",
    }),
    "auditor": frozenset({
        "audit.read",
        "audit.verify",
        "tally.run",
        "bulletin.publish",
    }),
    "administrator": frozenset({
        "staff.manage",
        "results.publish",
        "config.read",
    }),
})


def has_permission(role, permission):
    """
    Return True only when a known role explicitly
    holds the permission. Anything else is denied.
    """

    if not isinstance(role, str):
        return False

    if not isinstance(permission, str):
        return False

    return permission in ROLE_PERMISSIONS.get(
        role, frozenset()
    )


def _report_denial(audit, permission):
    """
    Send an AUTHZ_DENIED event without letting an
    audit failure turn a denial into an allow.
    """

    # The stream follows the server-side login type,
    # not the claimed role, so a missing role on a
    # voter session is still a voter event.
    if session.get("authenticated") is True:
        stream = "identity"
        actor_type = "voter"
        actor_id = session.get("voter_id")
    else:
        stream = "admin"
        actor_type = "staff"
        actor_id = session.get("staff_id")

    try:
        audit(
            "AUTHZ_DENIED",
            stream=stream,
            actor_type=actor_type,
            actor_id=actor_id,
            outcome="denied",
            details={"permission": permission},
        )
    except Exception:
        logger.exception("authz_denied_audit_failed")


def require_permission(permission, *, audit=None):
    """
    Protect a Flask view with one named permission.

    401 when not authenticated, 403 when the
    session role lacks the permission.
    """

    if not isinstance(permission, str) or not permission:
        raise ValueError(
            "A permission name is required"
        )

    if audit is not None and not callable(audit):
        raise TypeError(
            "audit must be callable"
        )

    def decorator(view_function):

        @wraps(view_function)
        def wrapper(*args, **kwargs):

            if (
                session.get("authenticated") is not True
                and session.get("staff_authenticated")
                is not True
            ):
                return jsonify({
                    "error": "Authentication required"
                }), 401

            role = session.get("role")

            if not has_permission(role, permission):
                logger.warning(
                    "authz_denied permission=%s",
                    permission
                )

                if audit is not None:
                    _report_denial(audit, permission)

                return jsonify({
                    "error": "Forbidden"
                }), 403

            return view_function(*args, **kwargs)

        # Used by the SR-04 route inventory test.
        wrapper.required_permission = permission

        return wrapper

    return decorator
