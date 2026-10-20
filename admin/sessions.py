"""
SR-02 (with SR-16): Staff sessions.

Security controls:
- After login the session is cleared and its ID
  regenerated (session fixation), like Workstream A
- The session holds exactly the keys Workstream E's
  SR-04 RBAC reads (staff_authenticated, staff_id,
  role) plus last_activity; never any voter keys
- 10-minute inactivity timeout, as for voters (SR-16)
- A voter session, or a session with both voter and
  staff flags, can never use staff endpoints
- Every request re-checks that the staff account still
  exists and is active; otherwise the session is ended
  at once (STAFF_SESSION_REVOKED), so deactivating an
  account also cuts off sessions that are already open
- Starting or ending a session (login, logout, idle
  expiry, revocation) runs the registered reset hooks, so a new
  session never inherits privileges (e.g. elevations);
  ending a session is audited on the admin stream

Local academic prototype.
"""

import math
import time

from collections.abc import Callable
from functools import wraps

from flask import current_app, jsonify, session

from .accounts import STAFF_ROLES


INACTIVITY_LIMIT_SECONDS = 600

STAFF_FLAG = "staff_authenticated"
VOTER_FLAG = "authenticated"


def _regenerate_session_id() -> None:
    interface = current_app.session_interface

    # Flask-Session (server-side sessions, as in app.py)
    if hasattr(interface, "regenerate"):
        interface.regenerate(session)


def _valid_timestamp(value, now: float) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value <= now
    )


class StaffSessions:
    """Creates, checks and ends staff sessions."""

    def __init__(
        self,
        *,
        audit: Callable,
        clock: Callable[[], float] = time.time,
        account_is_active: Callable[[str], bool] | None = None,
    ):
        """
        account_is_active(staff_id) -> bool is checked on
        every request; None skips the check (tests only).
        """

        self.audit = audit
        self.clock = clock
        self.account_is_active = account_is_active
        self._reset_hooks: list[Callable[[str], None]] = []

    def add_reset_hook(self, hook: Callable[[str], None]) -> None:
        """Run hook(staff_id) whenever a staff session starts or ends."""

        self._reset_hooks.append(hook)

    def _reset(self, staff_id: str) -> None:
        for hook in self._reset_hooks:
            hook(staff_id)

    def establish(self, account) -> None:
        self._reset(account.staff_id)

        session.clear()
        session[STAFF_FLAG] = True
        session["staff_id"] = account.staff_id
        session["role"] = account.role
        session["last_activity"] = self.clock()
        session.permanent = True

        _regenerate_session_id()

    def current_staff_id(self) -> str | None:
        """The staff ID of a valid, active session, else None."""

        if session.get(STAFF_FLAG) is not True:
            return None

        if VOTER_FLAG in session or "voter_id" in session:
            return None

        staff_id = session.get("staff_id")

        if not isinstance(staff_id, str) or not staff_id:
            return None

        if session.get("role") not in STAFF_ROLES:
            return None

        return staff_id

    def end(self, event_type: str) -> None:
        staff_id = session.get("staff_id")

        if isinstance(staff_id, str) and staff_id:
            self._reset(staff_id)

            self.audit(
                event_type,
                stream="admin",
                actor_type="staff",
                actor_id=staff_id,
                outcome="success",
            )

        session.clear()

    def require_staff_session(self, view_function):
        """401 unless a valid, recently active staff session exists."""

        @wraps(view_function)
        def wrapper(*args, **kwargs):
            staff_id = self.current_staff_id()

            if staff_id is None:
                session.clear()
                return jsonify({"error": "Authentication required"}), 401

            if (
                self.account_is_active is not None
                and self.account_is_active(staff_id) is not True
            ):
                self.end("STAFF_SESSION_REVOKED")
                return jsonify({"error": "Authentication required"}), 401

            now = self.clock()
            last_activity = session.get("last_activity")

            if not _valid_timestamp(last_activity, now):
                session.clear()
                return jsonify({"error": "Session expired"}), 401

            if now - last_activity >= INACTIVITY_LIMIT_SECONDS:
                self.end("STAFF_SESSION_EXPIRED")
                return jsonify({
                    "error": "Session expired due to inactivity"
                }), 401

            session["last_activity"] = now
            session.permanent = True

            return view_function(*args, **kwargs)

        wrapper.requires_staff_session = True

        return wrapper
