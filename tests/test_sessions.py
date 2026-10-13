
from datetime import timedelta

import pytest

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True

    with app.test_client() as test_client:
        yield test_client


def test_secure_cookie_configuration():
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SECURE"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


def test_session_lifetime_configuration():
    assert app.config["PERMANENT_SESSION_LIFETIME"] == timedelta(
        minutes=10
    )


def test_post_without_csrf_token_is_rejected(client):
    response = client.post("/test-action")

    assert response.status_code == 400
