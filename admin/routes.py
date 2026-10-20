"""
SR-02: Staff authentication endpoints.

Security controls:
- Thin routes: input validation here, factor checks
  in StaffAuthenticator
- Strict JSON input: exactly {"staff_id", "password"},
  type and length checked; unknown fields refused
- Identity comes only from the trusted gateway and the
  server-side session, never from request data
- One generic 401 message for every authentication
  failure; 429 when the SR-01 rate limit applies
- CSRF protection from Flask-WTF (app-wide), with a
  token endpoint like Workstream A's /login/csrf
- Successful login replaces any existing (voter or
  staff) session with a fresh staff session
- Elevation needs a staff session, a permission the
  role holds (403 otherwise) and step-up
  re-authentication with the certificate and password
  (401 / 429 as for login)
- Staff account management is a privileged operation:
  it needs an active "staff.manage" elevation, applies
  the person-linked / one-certificate rules and is
  audited with the acting administrator

Local academic prototype.
"""

from flask import Blueprint, jsonify, request, session
from flask_wtf.csrf import generate_csrf

from .accounts import (
    StaffAccountError,
    create_staff_account,
    find_staff_account,
)
from .elevation import ElevationService, valid_permission_name
from .gateway import read_gateway_identity
from .login import (
    STATUS_RATE_LIMITED,
    STEP_UP_EVENT_PREFIX,
    StaffAuthenticator,
)
from .sessions import StaffSessions


LOGIN_FIELDS = frozenset({"staff_id", "password"})
ELEVATE_FIELDS = frozenset({"permission", "password"})
REVOKE_FIELDS = frozenset({"permission"})
ACCOUNT_FIELDS = frozenset(
    {"staff_id", "full_name", "role", "password", "cert_fingerprint"}
)
STAFF_MANAGE = "staff.manage"
MAX_STAFF_ID_INPUT = 64
MAX_PASSWORD_INPUT = 1024


def _error(message: str, status: int):
    return jsonify({"error": message}), status


def invalid_credentials():
    return _error("Invalid authentication credentials", 401)


def read_json_fields(allowed: frozenset, required: frozenset):
    """The JSON object, or None if fields are missing or unknown."""

    if not request.is_json:
        return None

    data = request.get_json(silent=True)

    if (
        not isinstance(data, dict)
        or not set(data) <= allowed
        or not required <= set(data)
    ):
        return None

    return data


def valid_password_input(password) -> bool:
    return isinstance(password, str) and 1 <= len(password) <= MAX_PASSWORD_INPUT


def _audit_admin_action(elevation, event_type, outcome, details) -> None:
    elevation.audit(
        event_type,
        stream="admin",
        actor_type="staff",
        actor_id=session.get("staff_id"),
        outcome=outcome,
        details=details,
    )


def create_staff_blueprint(
    *,
    authenticator: StaffAuthenticator,
    sessions: StaffSessions,
    elevation: ElevationService,
    db_session=None,
) -> Blueprint:
    """
    db_session: callable returning the SQLAlchemy session
    for staff accounts (default: the authenticator's).
    """

    blueprint = Blueprint("staff", __name__)
    require_staff_session = sessions.require_staff_session
    require_elevated = elevation.require_elevated
    db_session = db_session or authenticator.db_session

    @blueprint.get("/staff/csrf")
    def staff_csrf():
        return jsonify({"csrf_token": generate_csrf()}), 200

    @blueprint.post("/staff/login")
    def staff_login():
        data = read_json_fields(LOGIN_FIELDS, LOGIN_FIELDS)

        if (
            data is None
            or not isinstance(data["staff_id"], str)
            or not 1 <= len(data["staff_id"]) <= MAX_STAFF_ID_INPUT
            or not valid_password_input(data["password"])
        ):
            return _error("Invalid request", 400)

        result = authenticator.authenticate(
            data["staff_id"],
            data["password"],
            read_gateway_identity(request),
        )

        if result.status == STATUS_RATE_LIMITED:
            return _error("Too many authentication attempts", 429)

        if not result.success:
            return invalid_credentials()

        sessions.establish(result.account)

        return jsonify({
            "message": "Authentication successful",
            "role": result.account.role,
        }), 200

    @blueprint.get("/staff/session")
    @require_staff_session
    def staff_session_status():
        staff_id = sessions.current_staff_id()

        return jsonify({
            "staff_id": staff_id,
            "elevations": elevation.active_permissions(staff_id),
            "csrf_token": generate_csrf(),
        }), 200

    @blueprint.post("/staff/elevate")
    @require_staff_session
    def staff_elevate():
        data = read_json_fields(ELEVATE_FIELDS, ELEVATE_FIELDS)

        if (
            data is None
            or not valid_permission_name(data["permission"])
            or not valid_password_input(data["password"])
        ):
            return _error("Invalid request", 400)

        staff_id = session["staff_id"]
        permission = data["permission"]

        if not elevation.role_allows(session["role"], permission):
            elevation.audit(
                "STAFF_ELEVATION_DENIED",
                stream="admin",
                actor_type="staff",
                actor_id=staff_id,
                outcome="denied",
                details={"permission": permission},
            )
            return _error("Forbidden", 403)

        result = authenticator.authenticate(
            staff_id,
            data["password"],
            read_gateway_identity(request),
            event_prefix=STEP_UP_EVENT_PREFIX,
        )

        if result.status == STATUS_RATE_LIMITED:
            return _error("Too many authentication attempts", 429)

        if not result.success or result.account.staff_id != staff_id:
            return invalid_credentials()

        grant = elevation.grant(staff_id, permission)

        return jsonify({
            "permission": permission,
            "expires_at": grant.expires_at,
            "expires_in_seconds": grant.expires_at - grant.granted_at,
        }), 200

    @blueprint.post("/staff/elevate/revoke")
    @require_staff_session
    def staff_revoke_elevation():
        data = read_json_fields(REVOKE_FIELDS, frozenset())

        if data is None:
            return _error("Invalid request", 400)

        permission = data.get("permission")

        if permission is not None and not valid_permission_name(permission):
            return _error("Invalid request", 400)

        revoked = elevation.revoke(session["staff_id"], permission)

        return jsonify({"revoked": revoked}), 200

    @blueprint.post("/staff/accounts")
    @require_elevated(STAFF_MANAGE)
    def staff_create_account():
        data = read_json_fields(ACCOUNT_FIELDS, ACCOUNT_FIELDS)

        if data is None:
            return _error("Invalid request", 400)

        try:
            account = create_staff_account(db_session(), **data)
            db_session().commit()
        except StaffAccountError as error:
            db_session().rollback()
            _audit_admin_action(
                elevation, "STAFF_ACCOUNT_CREATE_REJECTED", "failure",
                {"reason": str(error)},
            )
            return _error(str(error), 400)

        _audit_admin_action(
            elevation, "STAFF_ACCOUNT_CREATED", "success",
            {"staff_id": account.staff_id, "role": account.role},
        )

        return jsonify({
            "staff_id": account.staff_id,
            "role": account.role,
        }), 201

    @blueprint.post("/staff/accounts/<staff_id>/deactivate")
    @require_elevated(STAFF_MANAGE)
    def staff_deactivate_account(staff_id):
        account = find_staff_account(db_session(), staff_id)

        if account is None:
            return _error("Not found", 404)

        if account.staff_id == session.get("staff_id"):
            return _error("Staff cannot deactivate their own account", 409)

        account.is_active = False
        db_session().commit()
        elevation.revoke(account.staff_id, None, "account_deactivated")

        _audit_admin_action(
            elevation, "STAFF_ACCOUNT_DEACTIVATED", "success",
            {"staff_id": account.staff_id},
        )

        return jsonify({"staff_id": account.staff_id, "active": False}), 200

    @blueprint.post("/staff/logout")
    @require_staff_session
    def staff_logout():
        sessions.end("STAFF_LOGOUT")

        return jsonify({"message": "Logged out successfully"}), 200

    return blueprint
