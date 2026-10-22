"""The sign-in page is plain, safe HTML that uses the existing /login."""

import re
from pathlib import Path

import pytest

import app as application


ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def client():
    return application.app.test_client()


def test_page_loads(client):
    reply = client.get("/signin")

    assert reply.status_code == 200
    assert b"Sign in to vote" in reply.data


def test_page_has_no_inline_script_or_style(client):
    html = client.get("/signin").get_data(as_text=True)

    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert "style=" not in html
    assert "onclick" not in html.lower()


def test_page_is_not_cached_and_has_a_strict_csp(client):
    reply = client.get("/signin")
    policy = reply.headers["Content-Security-Policy"]

    assert reply.headers["Cache-Control"] == "no-store"
    assert "default-src 'none'" in policy
    assert "script-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy


def test_assets_are_served(client):
    assert client.get("/signin/assets/login.js").status_code == 200
    assert client.get("/signin/assets/login.css").status_code == 200


def test_password_field_is_a_password_input(client):
    html = client.get("/signin").get_data(as_text=True)

    assert 'id="password" name="password" type="password"' in html


def test_script_uses_existing_login_and_never_writes_html():
    script = (ROOT / "static" / "signin" / "login.js").read_text()

    assert '"/login/csrf"' in script and '"/login"' in script
    assert "innerHTML" not in script
    assert "localStorage" not in script and "sessionStorage" not in script
    assert "console.log" not in script


def test_query_string_values_are_never_shown(client):
    reply = client.get("/signin?x=<script>alert(1)</script>")

    assert b"alert(1)" not in reply.data
