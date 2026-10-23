"""
Sign-in page for the voter web client.

Serves one small HTML page and its CSS and JavaScript. The page uses the
existing JSON login (GET /login/csrf, POST /login); this file adds no new
way to log in and handles no credentials itself.
"""

from flask import Blueprint, render_template


def create_signin_blueprint():
    bp = Blueprint(
        "signin", __name__, url_prefix="/signin",
        static_folder="static/signin", static_url_path="/assets",
    )

    @bp.get("")
    def page():
        return render_template("signin/login.html")

    @bp.after_request
    def private_response(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; form-action 'none'; base-uri 'none'; "
            "frame-ancestors 'none'"
        )
        return response

    return bp
