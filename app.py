
import os
import secrets
import time
import math
from functools import wraps
from datetime import timedelta

from cachelib import SimpleCache
from flask import Flask, jsonify, session
from flask_session import Session
from flask_wtf.csrf import CSRFProtect


# Create Flask application
app = Flask(__name__)

# SR-16: Maximum inactivity period
INACTIVITY_LIMIT_SECONDS = 600

# Security configuration
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY")
    or secrets.token_hex(32),

    # Server-side session storage
    SESSION_TYPE="cachelib",
    SESSION_CACHELIB=SimpleCache(),
    SESSION_PERMANENT=True,

    # Session cookie security
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
    SESSION_REFRESH_EACH_REQUEST=True,

    # Session lifetime: 10 minutes
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=10),

    # Enable CSRF protection
    WTF_CSRF_ENABLED=True,
)

# Initialise Flask-Session
Session(app)

# Initialise CSRF protection
csrf = CSRFProtect(app)


def current_timestamp():
    """Return the current time in seconds."""
    return time.time()


# SR-16: Protect authenticated routes
def require_active_session(view_function):

    @wraps(view_function)
    def wrapper(*args, **kwargs):

        # Check whether the user is authenticated
        if session.get("authenticated") is not True:
            return jsonify({
                "error": "Authentication required"
            }), 401

        now = current_timestamp()
        last_activity = session.get("last_activity")

        # Reject missing or invalid activity timestamps
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

        # Check the 10-minute inactivity timeout
        inactive_seconds = now - last_activity

        if inactive_seconds >= INACTIVITY_LIMIT_SECONDS:
            session.clear()
            return jsonify({
                "error": "Session expired due to inactivity"
            }), 401

        # Refresh activity timestamp
        session["last_activity"] = now
        session.permanent = True

        return view_function(*args, **kwargs)

    return wrapper


# Public homepage
@app.get("/")
def home():
    return "Electronic Voting Platform - Workstream A"


# Protected session status endpoint
@app.get("/session-status")
@require_active_session
def session_status():
    return jsonify({
        "message": "Session active",
        "authenticated": True
    }), 200


# Temporary endpoint for CSRF testing
@app.post("/test-action")
def test_action():
    return "Test action completed"


# Start local development server
if __name__ == "__main__":
    app.run(debug=False)
