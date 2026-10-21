"""
SR-02: Just-in-time privilege elevation.

Security controls:
- No standing privileges: a staff session can use a
  privileged permission only while it holds an
  elevation grant for exactly that permission
- Grants are requested per permission, only for
  permissions the role already holds under SR-04
  (Workstream E's has_permission), after step-up
  re-authentication (certificate and password again)
- Grants last at most ELEVATION_SECONDS (15 minutes),
  are stored server-side and checked against the
  database on every privileged request
- Grants are revoked on request, at login, at logout
  and at idle expiry
- require_elevated = staff session (idle timeout) +
  SR-04 require_permission + an active grant
- Grant, expiry, revoke and refusal are audited on
  the admin stream (SR-17)

Local academic prototype.
"""

import re

from collections.abc import Callable
from functools import wraps

from flask import jsonify, session
from sqlalchemy import select

from .models import PERMISSION_MAX_LENGTH, ElevationGrant
from .sessions import StaffSessions


ELEVATION_SECONDS = 15 * 60

PERMISSION_PATTERN = re.compile(r"[a-z][a-z_]*\.[a-z][a-z_]*")

REVOKE_REQUESTED = "requested"
REVOKE_SESSION_RESET = "session_reset"
REVOKE_REPLACED = "replaced"


def valid_permission_name(permission) -> bool:
    return (
        isinstance(permission, str)
        and len(permission) <= PERMISSION_MAX_LENGTH
        and PERMISSION_PATTERN.fullmatch(permission) is not None
    )


class ElevationService:
    """Creates, checks, expires and revokes elevation grants."""

    def __init__(
        self,
        *,
        db_session: Callable,
        sessions: StaffSessions,
        require_permission: Callable,
        has_permission: Callable[[str, str], bool],
        audit: Callable,
    ):
        self._db_session = db_session
        self.sessions = sessions
        self.require_permission = require_permission
        self.has_permission = has_permission
        self.audit = audit
        self.clock = sessions.clock

        sessions.add_reset_hook(
            lambda staff_id: self.revoke(staff_id, None, REVOKE_SESSION_RESET)
        )

    def role_allows(self, role, permission) -> bool:
        return valid_permission_name(permission) and self.has_permission(
            role, permission
        ) is True

    def grant(self, staff_id: str, permission: str) -> ElevationGrant:
        """New grant for ELEVATION_SECONDS; replaces an active one."""

        self.revoke(staff_id, permission, REVOKE_REPLACED)

        now = self.clock()
        grant = ElevationGrant(
            staff_id=staff_id,
            permission=permission,
            granted_at=now,
            expires_at=now + ELEVATION_SECONDS,
            revoked=False,
            expiry_recorded=False,
        )

        db_session = self._db_session()
        db_session.add(grant)
        db_session.commit()

        self._audit("STAFF_ELEVATION_GRANTED", "success", staff_id, {
            "permission": permission,
            "duration_seconds": ELEVATION_SECONDS,
        })

        return grant

    def active_grant(self, staff_id: str, permission: str):
        self.record_expired(staff_id)

        return self._db_session().scalar(
            select(ElevationGrant)
            .where(
                ElevationGrant.staff_id == staff_id,
                ElevationGrant.permission == permission,
                ElevationGrant.revoked.is_(False),
                ElevationGrant.granted_at <= self.clock(),
                ElevationGrant.expires_at > self.clock(),
            )
            .limit(1)
        )

    def active_permissions(self, staff_id: str) -> list[str]:
        self.record_expired(staff_id)

        now = self.clock()

        return sorted(set(self._db_session().scalars(
            select(ElevationGrant.permission).where(
                ElevationGrant.staff_id == staff_id,
                ElevationGrant.revoked.is_(False),
                ElevationGrant.expires_at > now,
            )
        )))

    def record_expired(self, staff_id: str) -> None:
        """Write each newly expired grant to the audit log once."""

        db_session = self._db_session()
        expired = db_session.scalars(
            select(ElevationGrant).where(
                ElevationGrant.staff_id == staff_id,
                ElevationGrant.revoked.is_(False),
                ElevationGrant.expiry_recorded.is_(False),
                ElevationGrant.expires_at <= self.clock(),
            )
        ).all()

        for grant in expired:
            grant.expiry_recorded = True
            self._audit("STAFF_ELEVATION_EXPIRED", "success", staff_id, {
                "permission": grant.permission,
            })

        if expired:
            db_session.commit()

    def revoke(self, staff_id: str, permission: str | None,
               reason: str = REVOKE_REQUESTED) -> int:
        """Revoke active grants (one permission, or all if None)."""

        db_session = self._db_session()
        query = select(ElevationGrant).where(
            ElevationGrant.staff_id == staff_id,
            ElevationGrant.revoked.is_(False),
            ElevationGrant.expires_at > self.clock(),
        )

        if permission is not None:
            query = query.where(ElevationGrant.permission == permission)

        grants = db_session.scalars(query).all()

        for grant in grants:
            grant.revoked = True
            grant.revoked_at = self.clock()
            self._audit("STAFF_ELEVATION_REVOKED", "success", staff_id, {
                "permission": grant.permission,
                "reason": reason,
            })

        if grants:
            db_session.commit()

        return len(grants)

    def refusal(self, permission: str):
        """
        For routes whose permission depends on the request
        (e.g. the operation type): None when the session's
        role holds the permission and an active grant
        exists, otherwise the 403 response to return.
        """

        staff_id = session.get("staff_id")

        if not self.role_allows(session.get("role"), permission):
            return jsonify({"error": "Forbidden"}), 403

        if self.active_grant(staff_id, permission) is None:
            self._audit(
                "STAFF_ELEVATION_REQUIRED", "denied", staff_id,
                {"permission": permission},
            )
            return jsonify({"error": "Elevation required"}), 403

        return None

    def require_elevated(self, permission: str):
        """
        Decorator for privileged routes: staff session,
        SR-04 permission and an active elevation grant.
        """

        if not valid_permission_name(permission):
            raise ValueError("A valid permission name is required")

        def decorator(view_function):

            @wraps(view_function)
            def check_grant(*args, **kwargs):
                staff_id = session.get("staff_id")

                if self.active_grant(staff_id, permission) is None:
                    self._audit(
                        "STAFF_ELEVATION_REQUIRED", "denied", staff_id,
                        {"permission": permission},
                    )
                    return jsonify({"error": "Elevation required"}), 403

                return view_function(*args, **kwargs)

            protected = self.sessions.require_staff_session(
                self.require_permission(permission)(check_grant)
            )
            protected.required_permission = permission
            protected.requires_elevation = True

            return protected

        return decorator

    def _audit(self, event_type, outcome, staff_id, details) -> None:
        self.audit(
            event_type,
            stream="admin",
            actor_type="staff",
            actor_id=staff_id,
            outcome=outcome,
            details=details,
        )
