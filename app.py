
"""
Electronic Voting Platform - Workstream A.

SR-01: Password authentication, MFA and rate limiting
SR-05: Object-level authorisation
SR-16: Secure sessions, CSRF and logout

Local academic prototype. Not production-ready.
"""

import os
import secrets
import time
import math

from functools import wraps
from datetime import timedelta

from cachelib import SimpleCache
from flask import Flask, jsonify, request, session
from flask_session import Session
from flask_wtf.csrf import CSRFProtect, generate_csrf

from records import db
from record_routes import create_record_blueprint


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

    # Isolated, non-persistent prototype database.
    SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

Session(app)
csrf = CSRFProtect(app)

# SR-05: Initialise database support.
db.init_app(app)


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

    # Obtain source address from the server's
    # connection metadata, not client JSON.
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


# Temporary endpoint for existing CSRF tests.
@app.post("/test-action")
def test_action():
    return "Test action completed"


# SR-05: Register protected record endpoints.
app.register_blueprint(
    create_record_blueprint(
        require_active_session
    )
)


if __name__ == "__main__":
    app.run(debug=False)
