
from datetime import timedelta

import pytest
import app as application


HTTPS_URL = "https://localhost"


@pytest.fixture
def client():
    application.app.config["TESTING"] = True

    with application.app.test_client() as test_client:
        yield test_client


def create_test_session(client, last_activity):
    """
    Simulate an authenticated session for testing.
    This does not create a public login endpoint.
    """
    with client.session_transaction(
        base_url=HTTPS_URL
    ) as test_session:
        test_session.clear()
        test_session["authenticated"] = True
        test_session["last_activity"] = last_activity
        test_session.permanent = True


def csrf_headers(token):
    """Create headers for a CSRF-protected request."""
    return {
        "X-CSRFToken": token,
        "Referer": HTTPS_URL + "/session-status"
    }


# Test 1: Secure cookie configuration
def test_secure_cookie_configuration():
    assert application.app.config[
        "SESSION_COOKIE_HTTPONLY"
    ] is True

    assert application.app.config[
        "SESSION_COOKIE_SECURE"
    ] is True

    assert application.app.config[
        "SESSION_COOKIE_SAMESITE"
    ] == "Lax"


# Test 2: Session lifetime
def test_session_lifetime_configuration():
    assert application.app.config[
        "PERMANENT_SESSION_LIFETIME"
    ] == timedelta(minutes=10)


# Test 3: Missing CSRF token
def test_post_without_csrf_token_is_rejected(client):
    response = client.post(
        "/test-action",
        base_url=HTTPS_URL
    )

    assert response.status_code == 400


# Test 4: Server-side session backend
def test_server_side_session_backend():
    backend = type(
        application.app.session_interface
    ).__name__

    assert backend == "CacheLibSessionInterface"


# Test 5: Unauthenticated access
def test_unauthenticated_access_denied(client):
    response = client.get(
        "/session-status",
        base_url=HTTPS_URL
    )

    assert response.status_code == 401


# Test 6: Active session refresh
def test_active_session_refresh(client, monkeypatch):
    clock = [1000.0]

    monkeypatch.setattr(
        application,
        "current_timestamp",
        lambda: clock[0]
    )

    create_test_session(client, last_activity=700.0)

    first_response = client.get(
        "/session-status",
        base_url=HTTPS_URL
    )

    assert first_response.status_code == 200

    clock[0] = 1599.0

    second_response = client.get(
        "/session-status",
        base_url=HTTPS_URL
    )

    assert second_response.status_code == 200


# Test 7: Session expires after inactivity
def test_session_expires_after_inactivity(
    client, monkeypatch
):
    monkeypatch.setattr(
        application,
        "current_timestamp",
        lambda: 1000.0
    )

    create_test_session(client, last_activity=399.0)

    response = client.get(
        "/session-status",
        base_url=HTTPS_URL
    )

    assert response.status_code == 401
    assert "expired" in response.get_json()["error"].lower()

    with client.session_transaction(
        base_url=HTTPS_URL
    ) as test_session:
        assert test_session.get("authenticated") is not True


# Test 8: Exactly 10 minutes
def test_session_expires_at_ten_minutes(
    client, monkeypatch
):
    monkeypatch.setattr(
        application,
        "current_timestamp",
        lambda: 1000.0
    )

    create_test_session(client, last_activity=400.0)

    response = client.get(
        "/session-status",
        base_url=HTTPS_URL
    )

    assert response.status_code == 401


# Test 9: Cookie security attributes
def test_session_cookie_attributes(client, monkeypatch):
    monkeypatch.setattr(
        application,
        "current_timestamp",
        lambda: 1000.0
    )

    create_test_session(client, last_activity=900.0)

    response = client.get(
        "/session-status",
        base_url=HTTPS_URL
    )

    assert response.status_code == 200

    cookie_header = "; ".join(
        response.headers.getlist("Set-Cookie")
    )

    assert "Secure" in cookie_header
    assert "HttpOnly" in cookie_header
    assert "SameSite=Lax" in cookie_header


# Test 10: Valid CSRF token accepted
def test_valid_csrf_token(client):
    create_test_session(
        client,
        last_activity=application.current_timestamp()
    )

    status_response = client.get(
        "/session-status",
        base_url=HTTPS_URL
    )

    assert status_response.status_code == 200

    token = status_response.get_json()["csrf_token"]

    response = client.post(
        "/test-action",
        base_url=HTTPS_URL,
        headers=csrf_headers(token)
    )

    assert response.status_code == 200


# Test 11: Secure logout
def test_secure_logout(client):
    create_test_session(
        client,
        last_activity=application.current_timestamp()
    )

    status_response = client.get(
        "/session-status",
        base_url=HTTPS_URL
    )

    assert status_response.status_code == 200

    token = status_response.get_json()["csrf_token"]

    logout_response = client.post(
        "/logout",
        base_url=HTTPS_URL,
        headers=csrf_headers(token)
    )

    assert logout_response.status_code == 200

    # Authenticated access must no longer work
    response = client.get(
        "/session-status",
        base_url=HTTPS_URL
    )

    assert response.status_code == 401


# Test 12: Logout without CSRF token rejected
def test_logout_without_csrf_token(client):
    create_test_session(
        client,
        last_activity=application.current_timestamp()
    )

    response = client.post(
        "/logout",
        base_url=HTTPS_URL
    )

    assert response.status_code == 400


# Test 13: Old CSRF token invalid after logout
def test_old_csrf_token_invalid_after_logout(client):
    create_test_session(
        client,
        last_activity=application.current_timestamp()
    )

    status_response = client.get(
        "/session-status",
        base_url=HTTPS_URL
    )

    assert status_response.status_code == 200

    token = status_response.get_json()["csrf_token"]

    logout_response = client.post(
        "/logout",
        base_url=HTTPS_URL,
        headers=csrf_headers(token)
    )

    assert logout_response.status_code == 200

    # Reusing the previous CSRF token must fail
    response = client.post(
        "/test-action",
        base_url=HTTPS_URL,
        headers=csrf_headers(token)
    )

    assert response.status_code == 400
