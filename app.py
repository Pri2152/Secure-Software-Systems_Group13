
import os
from datetime import timedelta

from flask import Flask
from flask_wtf.csrf import CSRFProtect

# Create the Flask application
app = Flask(__name__)

# SR-16: Initial secure session configuration
app.config.update(
    SECRET_KEY=os.environ.get(
        "SECRET_KEY", "local-development-only"
    ),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=10),
    WTF_CSRF_ENABLED=True,
)

# Enable CSRF protection for unsafe requests
csrf = CSRFProtect(app)


# Application homepage
@app.get("/")
def home():
    return "Electronic Voting Platform - Workstream A"


# Temporary endpoint for testing CSRF protection
@app.post("/test-action")
def test_action():
    return "Test action completed"


# Run the application locally
if __name__ == "__main__":
    app.run(debug=False)
