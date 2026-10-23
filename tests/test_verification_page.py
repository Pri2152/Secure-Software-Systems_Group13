"""SR-11 / SR-15: the verification page is plain, strict and holds no data."""

import re

import pytest

import crypto_agility
from records import db
from verification import wsgi


TOKEN = "t" * 40


@pytest.fixture
def client(tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text(TOKEN)
    settings = {
        "EVP_ELECTION_ID": "election-2026",
        "EVP_DIVISIONS": "Melbourne",
        "EVP_TALLY_TOKEN_FILE": str(token_file),
        "EVP_BALLOT_DB_URL": f"sqlite:///{tmp_path / 'ballot.db'}",
        "EVP_AUDIT_DB_URL": f"sqlite:///{tmp_path / 'audit.db'}",
    }
    app = wsgi.create_app(
        settings, crypto=crypto_agility.build_service(dev_keys=True)
    )

    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()

    crypto_agility.configure(None)


def test_page_loads_without_a_token(client):
    response = client.get("/verify")

    assert response.status_code == 200
    assert b"Verify the count" in response.data


def test_page_has_a_strict_policy_and_is_not_cached(client):
    response = client.get("/verify")
    policy = response.headers["Content-Security-Policy"]

    assert "default-src 'none'" in policy
    assert "script-src 'self'" in policy
    assert "unsafe-inline" not in policy
    assert response.headers["Cache-Control"] == "no-store"


def test_page_has_no_inline_script_or_style_or_remote_files(client):
    html = client.get("/verify").get_data(as_text=True)

    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert "style=" not in html
    assert "http://" not in html and "https://" not in html
    assert "onclick" not in html


def test_script_never_writes_server_text_as_html(client):
    script = client.get("/verify/assets/verify.js").get_data(as_text=True)

    assert "innerHTML" not in script
    assert "eval(" not in script
    assert "localStorage" not in script and "sessionStorage" not in script


def test_assets_are_served(client):
    for name in ("verify.js", "verify.css"):
        assert client.get(f"/verify/assets/{name}").status_code == 200
