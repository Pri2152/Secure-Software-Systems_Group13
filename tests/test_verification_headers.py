"""SR-15: Every response carries the security headers."""

from flask import Flask, jsonify

import app as application

from verification.headers import SECURITY_HEADERS, register_security_headers


def make_app():
    flask_app = Flask(__name__)

    @flask_app.get("/plain")
    def plain():
        return jsonify(ok=True)

    @flask_app.get("/custom")
    def custom():
        response = jsonify(ok=True)
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        return response

    return register_security_headers(flask_app)


def test_every_response_gets_all_headers():
    response = make_app().test_client().get("/plain")

    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value


def test_error_responses_get_headers_too():
    response = make_app().test_client().get("/missing")

    assert response.status_code == 404
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_route_set_policy_is_not_weakened():
    response = make_app().test_client().get("/custom")

    assert response.headers["Content-Security-Policy"] == "default-src 'none'"


def test_policy_blocks_framing_and_inline_script():
    policy = SECURITY_HEADERS["Content-Security-Policy"]

    assert "frame-ancestors 'none'" in policy
    assert "unsafe-inline" not in policy
    assert "unsafe-eval" not in policy


def test_platform_app_sends_the_headers():
    response = application.app.test_client().get(
        "/healthz", base_url="https://localhost"
    )

    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Cache-Control"] == "no-store"


def test_voting_page_keeps_its_stricter_policy():
    response = application.app.test_client().get(
        "/vote", base_url="https://localhost"
    )

    assert "default-src 'none'" in response.headers["Content-Security-Policy"]
