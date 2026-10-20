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

Local academic prototype.
"""

from flask import Blueprint, jsonify, request, session
from flask_wtf.csrf import generate_csrf

from .gateway import read_gateway_identity
from .login import STATUS_RATE_LIMITED, StaffAuthenticator


LOGIN_FIELDS = frozenset({"staff_id", "password"})
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


def establish_staff_session(account) -> None:
    """Fresh session holding only the keys SR-04 RBAC reads."""

    session.clear()
    session["staff_authenticated"] = True
    session["staff_id"] = account.staff_id
    session["role"] = account.role


def create_staff_blueprint(*, authenticator: StaffAuthenticator) -> Blueprint:
    blueprint = Blueprint("staff", __name__)

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

        establish_staff_session(result.account)

        return jsonify({
            "message": "Authentication successful",
            "role": result.account.role,
        }), 200

    return blueprint
