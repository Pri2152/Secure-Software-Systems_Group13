"""
SR-11 / SR-15: the public verification page (Workstream D).

Serves one small HTML page with its CSS and JavaScript at /verify. The
page holds no data. It asks for the tally token, then calls the
existing /publish, /bulletin and /bulletin/checks routes, so it adds no
new way to read the count.
"""

from flask import Blueprint


def create_verify_blueprint():
    bp = Blueprint(
        "verify_page", __name__, url_prefix="/verify",
        static_folder="web", static_url_path="/assets",
    )

    @bp.get("")
    def page():
        return bp.send_static_file("verify.html")

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
