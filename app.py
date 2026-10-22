
"""
Electronic Voting Platform - Workstream A.

SR-01: Password authentication, MFA and rate limiting
SR-05: Object-level authorisation
SR-07: Diplomatic-mission access restrictions
SR-16: Secure sessions, CSRF and logout

Local academic prototype. Not production-ready.
"""

import ipaddress
import math
import os
import secrets
import time

from datetime import timedelta
from functools import wraps

from cachelib import SimpleCache
from flask import Flask, g, jsonify, request, session
from flask_session import Session
from flask_wtf.csrf import CSRFProtect, generate_csrf

from gateway_security import evaluate_gateway_request
from platform_security.health import health_blueprint
from record_routes import create_record_blueprint
from records import db
from verification.headers import register_security_headers
from voting_routes import create_voting_blueprint


app = Flask(__name__)

INACTIVITY_LIMIT_SECONDS = 600

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY")
    or secrets.token_hex(32),

    SESSION_TYPE="cachelib",
    SESSION_CACHELIB=SimpleCache(),
    SESSION_PERMANENT=True,

    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
    SESSION_REFRESH_EACH_REQUEST=True,

    PERMANENT_SESSION_LIFETIME=timedelta(minutes=10),

    WTF_CSRF_ENABLED=True,
    MAX_CONTENT_LENGTH=4096,

    LOGIN_COORDINATOR=None,
    VOTING_ELECTION_ID=os.environ.get("EVP_ELECTION_ID") or "election-2026",

    SR07_GATEWAY_ENFORCED=(
        os.environ.get("SR07_GATEWAY_ENFORCED") == "1"
    ),
    MISSION_ACCESS_POLICY=None,

    SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
    SQLALCHEMY_BINDS={
        name: os.environ[variable]
        for name, variable in (
            ("ballot", "EVP_BALLOT_DB_URL"),
            ("audit", "EVP_AUDIT_DB_URL"),
        )
        if os.environ.get(variable)
    },
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

Session(app)
csrf = CSRFProtect(app)

db.init_app(app)


@app.before_request
def enforce_mission_access():

    if app.config.get("SR07_GATEWAY_ENFORCED") is not True:
        return None

    policy = app.config.get("MISSION_ACCESS_POLICY")

    if policy is None:
        app.logger.error(
            "SR-07 gateway policy is not configured"
        )
        return jsonify({
            "error": "Access policy unavailable"
        }), 503

    try:
        decision = evaluate_gateway_request(
            request,
            policy
        )
    except Exception:
        app.logger.exception(
            "SR-07 gateway evaluation failed"
        )
        return jsonify({
            "error": "Access policy unavailable"
        }), 503

    if not decision.allowed:
        return jsonify({
            "error": "Access denied"
        }), 403

    # The gateway adapter checks the peer and
    # mission policy before this point.
    # Nginx must overwrite X-EVP-Source-IP.
    try:
        trusted_source_ip = str(
            ipaddress.ip_address(
                request.headers.get(
                    "X-EVP-Source-IP", ""
                ).strip()
            )
        )
    except (ValueError, AttributeError):
        return jsonify({
            "error": "Access denied"
        }), 403

    # Retain the validated original source for
    # SR-01 rate limiting and audit purposes.
    g.sr07_source_ip = trusted_source_ip
    g.mission_access_reason = decision.reason

    return None


def current_timestamp():
    return time.time()


def establish_authenticated_session(
    verified_voter_id,
    session_obj=None
):
    if (
        not isinstance(verified_voter_id, str)
        or not verified_voter_id.strip()
    ):
        raise ValueError(
            "A verified voter ID is required"
        )

    active_session = (
        session if session_obj is None else session_obj
    )

    active_session.clear()
    active_session["authenticated"] = True
    active_session["voter_id"] = verified_voter_id
    active_session["role"] = "voter"
    active_session["last_activity"] = current_timestamp()
    active_session.permanent = True

    app.session_interface.regenerate(active_session)


def require_active_session(view_function):

    @wraps(view_function)
    def wrapper(*args, **kwargs):

        if session.get("authenticated") is not True:
            return jsonify({
                "error": "Authentication required"
            }), 401

        now = current_timestamp()
        last_activity = session.get("last_activity")

        valid_timestamp = (
            isinstance(last_activity, (int, float))
            and not isinstance(last_activity, bool)
            and math.isfinite(last_activity)
            and last_activity <= now
        )

        if not valid_timestamp:
            session.clear()
            return jsonify({
                "error": "Session expired"
            }), 401

        if now - last_activity >= INACTIVITY_LIMIT_SECONDS:
            session.clear()
            return jsonify({
                "error": "Session expired due to inactivity"
            }), 401

        session["last_activity"] = now
        session.permanent = True

        return view_function(*args, **kwargs)

    wrapper.requires_active_session = True
    return wrapper


@app.get("/")
def home():
    return "Electronic Voting Platform - Workstream A"


@app.get("/login/csrf")
def login_csrf():
    return jsonify({
        "csrf_token": generate_csrf()
    }), 200


@app.post("/login")
def login():

    if session.get("authenticated") is True:
        return jsonify({
            "error": "Already authenticated"
        }), 409

    coordinator = app.config.get(
        "LOGIN_COORDINATOR"
    )

    if coordinator is None:
        return jsonify({
            "error": "Login service is not configured"
        }), 503

    if not request.is_json:
        return jsonify({
            "error": "JSON request required"
        }), 415

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "Invalid request"
        }), 400

    account_id = data.get("account_id")
    password = data.get("password")
    totp_code = data.get("totp_code")

    if (
        not isinstance(account_id, str)
        or not 1 <= len(account_id.strip()) <= 128
        or not isinstance(password, str)
        or not 1 <= len(password) <= 1024
        or not isinstance(totp_code, str)
        or len(totp_code) != 6
        or not totp_code.isascii()
        or not totp_code.isdigit()
    ):
        return jsonify({
            "error": "Invalid request"
        }), 400

    # In gateway mode, use the original source IP
    # validated during the SR-07 access check.
    # Otherwise preserve standalone test behaviour.
    if app.config.get("SR07_GATEWAY_ENFORCED") is True:
        source_id = g.get("sr07_source_ip")
    else:
        source_id = request.remote_addr

    if not source_id:
        return jsonify({
            "error": "Invalid request source"
        }), 400

    result = coordinator.authenticate(
        account_id=account_id,
        password=password,
        totp_code=totp_code,
        source_id=source_id,
        on_authenticated=establish_authenticated_session,
    )

    if result.success:
        return jsonify({
            "message": "Authentication successful"
        }), 200

    if result.status == "rate_limited":
        return jsonify({
            "error": "Too many authentication attempts"
        }), 429

    if result.status == "invalid_request":
        return jsonify({
            "error": "Invalid request"
        }), 400

    return jsonify({
        "error": "Invalid authentication credentials"
    }), 401


@app.get("/session-status")
@require_active_session
def session_status():
    return jsonify({
        "message": "Session active",
        "authenticated": True,
        "csrf_token": generate_csrf()
    }), 200


@app.post("/logout")
@require_active_session
def logout():
    session.clear()

    return jsonify({
        "message": "Logged out successfully"
    }), 200


@app.post("/test-action")
def test_action():
    return "Test action completed"


app.register_blueprint(
    create_record_blueprint(
        require_active_session
    )
)

app.register_blueprint(health_blueprint)  # SR-19 GET /healthz
app.register_blueprint(create_voting_blueprint(require_active_session))
register_security_headers(app)  # SR-15 security headers on every response


if __name__ == "__main__":
    app.run(debug=False)
