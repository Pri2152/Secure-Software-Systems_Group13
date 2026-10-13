
import pytest
import app as application


HTTPS_URL = "https://localhost"


@pytest.fixture
def client():
    application.app.config["TESTING"] = True

    with application.app.test_client() as test_client:
        yield test_client


# Test 14: Regenerate session ID after authentication
def test_session_id_regenerated(client, monkeypatch):

    monkeypatch.setattr(
        application,
        "current_timestamp",
        lambda: 1000.0
    )

    # Create an anonymous pre-login session
    with client.session_transaction(
        base_url=HTTPS_URL
    ) as test_session:
        test_session["pre_login"] = True
        test_session["csrf_token"] = "old_test_token"
        old_session_id = test_session.sid

    # Simulate SR-01 completing authentication
    with client.session_transaction(
        base_url=HTTPS_URL
    ) as test_session:

        application.establish_authenticated_session(
            "voter-test-001",
            session_obj=test_session
        )

        new_session_id = test_session.sid

    # Session identifier must change
    assert old_session_id != new_session_id

    # Verify authenticated session contents
    with client.session_transaction(
        base_url=HTTPS_URL
    ) as test_session:

        assert test_session["authenticated"] is True
        assert test_session["voter_id"] == "voter-test-001"
        assert test_session["last_activity"] == 1000.0

        # Pre-login data must be removed
        assert "pre_login" not in test_session
        assert "csrf_token" not in test_session


# Test 15: Previous session ID cannot be reused
def test_old_session_id_rejected(client, monkeypatch):

    monkeypatch.setattr(
        application,
        "current_timestamp",
        lambda: 1000.0
    )

    with client.session_transaction(
        base_url=HTTPS_URL
    ) as test_session:
        test_session["pre_login"] = True
        old_session_id = test_session.sid

    with client.session_transaction(
        base_url=HTTPS_URL
    ) as test_session:

        application.establish_authenticated_session(
            "voter-test-002",
            session_obj=test_session
        )

        new_session_id = test_session.sid

    assert old_session_id != new_session_id

    # New session should allow authenticated access
    active_response = client.get(
        "/session-status",
        base_url=HTTPS_URL
    )

    assert active_response.status_code == 200

    # Simulate another client using the old session ID
    with application.app.test_client() as old_client:

        old_client.set_cookie(
            "session",
            old_session_id,
            domain="localhost",
            path="/"
        )

        old_response = old_client.get(
            "/session-status",
            base_url=HTTPS_URL
        )

        assert old_response.status_code == 401


# Test 16: Reject invalid voter identifiers
@pytest.mark.parametrize(
    "invalid_id",
    [None, "", "   ", 123]
)
def test_invalid_voter_id_rejected(client, invalid_id):

    with client.session_transaction(
        base_url=HTTPS_URL
    ) as test_session:

        test_session["pre_login"] = True

        with pytest.raises(ValueError):
            application.establish_authenticated_session(
                invalid_id,
                session_obj=test_session
            )

        assert test_session.get("authenticated") is not True

