
"""
SR-01: Authentication input-validation tests.

All credentials and voter records are synthetic.
"""

import pytest
import pyotp

from auth import hash_password
from login_flow import (
    VoterRecord,
    LoginCoordinator,
)
from rate_limit import LoginRateLimiter


TEST_SECRET = "JBSWY3DPEHPK3PXP"
TEST_PASSWORD = "CorrectPassword123!"
FIXED_TIME = 1700000000


@pytest.fixture
def environment():
    voter = VoterRecord(
        voter_id="voter-001",
        password_hash=hash_password(TEST_PASSWORD),
        totp_secret=TEST_SECRET,
    )

    coordinator = LoginCoordinator(
        lookup_voter=lambda account: (
            voter if account == "voter-001" else None
        ),
        rate_limiter=LoginRateLimiter(
            clock=lambda: 1000.0
        ),
        clock=lambda: FIXED_TIME,
    )

    code = pyotp.TOTP(TEST_SECRET).at(FIXED_TIME)

    return coordinator, code


# Reject invalid account identifiers
@pytest.mark.parametrize(
    "invalid_account",
    [None, "", "   ", 123]
)
def test_invalid_account_rejected(
    environment, invalid_account
):
    coordinator, code = environment
    authenticated = []

    result = coordinator.authenticate(
        account_id=invalid_account,
        password=TEST_PASSWORD,
        totp_code=code,
        source_id="203.0.113.10",
        on_authenticated=authenticated.append,
    )

    assert result.success is False
    assert result.status == "invalid_credentials"
    assert authenticated == []


# Reject invalid source identifiers
@pytest.mark.parametrize(
    "invalid_source",
    [None, "", "   ", 123]
)
def test_invalid_source_rejected(
    environment, invalid_source
):
    coordinator, code = environment
    authenticated = []

    result = coordinator.authenticate(
        account_id="voter-001",
        password=TEST_PASSWORD,
        totp_code=code,
        source_id=invalid_source,
        on_authenticated=authenticated.append,
    )

    assert result.success is False
    assert result.status == "invalid_request"
    assert authenticated == []


# Reject malformed passwords
@pytest.mark.parametrize(
    "invalid_password",
    [None, 123]
)
def test_invalid_password_rejected(
    environment, invalid_password
):
    coordinator, code = environment
    authenticated = []

    result = coordinator.authenticate(
        account_id="voter-001",
        password=invalid_password,
        totp_code=code,
        source_id="203.0.113.10",
        on_authenticated=authenticated.append,
    )

    assert result.success is False
    assert result.status == "invalid_credentials"
    assert authenticated == []


# Reject malformed MFA codes
@pytest.mark.parametrize(
    "invalid_code",
    [None, 123]
)
def test_invalid_mfa_rejected(
    environment, invalid_code
):
    coordinator, _ = environment
    authenticated = []

    result = coordinator.authenticate(
        account_id="voter-001",
        password=TEST_PASSWORD,
        totp_code=invalid_code,
        source_id="203.0.113.10",
        on_authenticated=authenticated.append,
    )

    assert result.success is False
    assert result.status == "invalid_credentials"
    assert authenticated == []
