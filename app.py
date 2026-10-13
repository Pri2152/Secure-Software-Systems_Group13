
import os
import secrets
import time
import math
from functools import wraps
from datetime import timedelta

from cachelib import SimpleCache
from flask import Flask, jsonify, session
from flask_session import Session
from flask_wtf.csrf import CSRFProtect, generate_csrf


# Create the Flask application
app = Flask(__name__)

# SR-16: Ten-minute inactivity limit
INACTIVITY_LIMIT_SECONDS = 600

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY")
    or secrets.token_hex(32),

    # Server-side session storage (local prototype)
    SESSION_TYPE="cachelib",
    SESSION_CACHELIB=SimpleCache(),
    SESSION_PERMANENT=True,

    # Secure session cookies
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
    SESSION_REFRESH_EACH_REQUEST=True,

    # Session lifetime
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=10),

    # CSRF protection
    WTF_CSRF_ENABLED=True,
)

# Initialise security extensions
Session(app)
csrf = CSRFProtect(app)


def current_timestamp():
    """Return the current time in seconds."""
    return time.time()


# SR-16: Establish a new session after verified authentication
def establish_authenticated_session(
    verified_voter_id,
    session_obj=None
):
    """
    Called only after SR-01 has verified the voter's
    credentials and MFA.

    Clear pre-login data and regenerate the session ID.
    """

    if (
        not isinstance(verified_voter_id, str)
        or not verified_voter_id.strip()
    ):
        raise ValueError("A verified voter ID is required")

    active_session = (
        session if session_obj is None else session_obj
    )

    # Remove pre-authentication session data
    active_session.clear()

    # Establish the authenticated session
    active_session["authenticated"] = True
    active_session["voter_id"] = verified_voter_id
    active_session["last_activity"] = current_timestamp()
    active_session.permanent = True

    # Rotate session ID and invalidate the previous ID
    app.session_interface.regenerate(active_session)


# SR-16: Protect authenticated endpoints
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

        inactive_seconds = now - last_activity

        if inactive_seconds >= INACTIVITY_LIMIT_SECONDS:
            session.clear()
            return jsonify({
                "error": "Session expired due to inactivity"
            }), 401

        # Refresh activity
        session["last_activity"] = now
        session.permanent = True

        return view_function(*args, **kwargs)

    return wrapper


# Public homepage
@app.get("/")
def home():
    return "Electronic Voting Platform - Workstream A"


# Protected session status
@app.get("/session-status")
@require_active_session
def session_status():

    return jsonify({
        "message": "Session active",
        "authenticated": True,
        "csrf_token": generate_csrf()
    }), 200


# SR-16: Secure logout
@app.post("/logout")
@require_active_session
def logout():

    session.clear()

    return jsonify({
        "message": "Logged out successfully"
    }), 200


# Temporary CSRF testing endpoint
@app.post("/test-action")
def test_action():
    return "Test action completed"


# Run application locally
if __name__ == "__main__":
    app.run(debug=False)
