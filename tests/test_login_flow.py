
"""
SR-01: Integrated authentication workflow tests.

Uses synthetic voters and fixed TOTP timestamps.
"""

import pytest
import pyotp

from flask import session

import app as application

from auth import hash_password
from rate_limit import LoginRateLimiter
from login_flow import (
    VoterRecord,
    LoginCoordinator,
)


TEST_SECRET = "JBSWY3DPEHPK3PXP"
TEST_PASSWORD = "CorrectPassword123!"


@pytest.fixture
def environment():
    now = [1700000000.0]

    voter = VoterRecord(
        voter_id="voter-001",
        password_hash=hash_password(TEST_PASSWORD),
        totp_secret=TEST_SECRET,
    )

    voters = {"voter-001": voter}

    limiter = LoginRateLimiter(
        clock=lambda: now[0]
    )

    coordinator = LoginCoordinator(
        lookup_voter=lambda account: voters.get(account),
        rate_limiter=limiter,
        clock=lambda: now[0],
    )

    return {
        "clock": now,
        "coordinator": coordinator,
        "voters": voters,
    }


def valid_code(environment):
    timestamp = int(environment["clock"][0])
    return pyotp.TOTP(TEST_SECRET).at(timestamp)


def attempt(
    environment,
    password=TEST_PASSWORD,
    code=None,
    account="voter-001",
    source="203.0.113.10",
    callback=None,
):
    if code is None:
        code = valid_code(environment)

    if callback is None:
        callback = lambda voter_id: None

    return environment["coordinator"].authenticate(
        account_id=account,
        password=password,
        totp_code=code,
        source_id=source,
        on_authenticated=callback,
    )


# Test 1: Both factors are required
def test_correct_password_and_totp(environment):
    authenticated = []

    result = attempt(
        environment,
        callback=authenticated.append,
    )

    assert result.success is True
    assert result.status == "authenticated"
    assert authenticated == ["voter-001"]


# Test 2: Incorrect password cannot authenticate
def test_wrong_password_rejected(environment):
    authenticated = []

    result = attempt(
        environment,
        password="WrongPassword!",
        callback=authenticated.append,
    )

    assert result.success is False
    assert authenticated == []


# Test 3: Incorrect MFA cannot authenticate
def test_wrong_mfa_rejected(environment):
    authenticated = []

    correct = valid_code(environment)

    wrong = str(
        (int(correct) + 1) % 1000000
    ).zfill(6)

    result = attempt(
        environment,
        code=wrong,
        callback=authenticated.append,
    )

    assert result.success is False
    assert authenticated == []


# Test 4: Unknown voter rejected
def test_unknown_voter_rejected(environment):
    result = attempt(
        environment,
        account="nonexistent-voter",
    )

    assert result.success is False
    assert result.status == "invalid_credentials"


# Test 5: TOTP replay prevented
def test_totp_replay_rejected(environment):
    first = attempt(environment)
    second = attempt(environment)

    assert first.success is True
    assert second.success is False


# Test 6: New TOTP time step permits login
def test_new_totp_step_accepted(environment):
    first = attempt(environment)

    environment["clock"][0] += 30

    second = attempt(environment)

    assert first.success is True
    assert second.success is True


# Test 7: Account locked after five failures
def test_account_lockout(environment):
    for _ in range(5):
        result = attempt(
            environment,
            password="WrongPassword!",
        )
        assert result.success is False

    # Even valid credentials are now blocked
    blocked = attempt(
        environment,
        source="198.51.100.25",
    )

    assert blocked.success is False
    assert blocked.status == "rate_limited"


# Test 8: Source-level lockout
def test_source_lockout(environment):
    source = "203.0.113.50"

    for index in range(5):
        result = attempt(
            environment,
            account=f"unknown-{index}",
            source=source,
        )
        assert result.success is False

    blocked = attempt(
        environment,
        account="voter-001",
        source=source,
    )

    assert blocked.success is False
    assert blocked.status == "rate_limited"


# Test 9: Successful login establishes SR-16 session
def test_integration_with_secure_session(environment):
    application.app.config["TESTING"] = True

    with application.app.test_request_context(
        "/", base_url="https://localhost"
    ):
        assert session.get("authenticated") is not True

        result = attempt(
            environment,
            callback=(
                application.establish_authenticated_session
            ),
        )

        assert result.success is True
        assert session["authenticated"] is True
        assert session["voter_id"] == "voter-001"
        assert "last_activity" in session
