
"""
SR-01: Rate limiting security tests.
"""

import logging
import pytest

from rate_limit import LoginRateLimiter


@pytest.fixture
def limiter_and_clock():
    now = [1000.0]

    limiter = LoginRateLimiter(
        clock=lambda: now[0]
    )

    return limiter, now


# Test 1: Four failures are below the limit
def test_four_failures_do_not_block(limiter_and_clock):
    limiter, _ = limiter_and_clock

    for _ in range(4):
        assert limiter.record_failure(
            "voter1", "203.0.113.10"
        ) is False

    assert limiter.is_blocked(
        "voter1", "203.0.113.10"
    ) is False


# Test 2: Fifth account failure blocks login
def test_fifth_failure_blocks_account_across_sources(
    limiter_and_clock
):
    limiter, _ = limiter_and_clock

    for i in range(5):
        limiter.record_failure(
            "VOTER1",
            f"203.0.113.{i + 1}"
        )

    assert limiter.is_blocked(
        "voter1", "198.51.100.1"
    ) is True


# Test 3: Fifth source failure blocks login
def test_fifth_failure_blocks_source_across_accounts(
    limiter_and_clock
):
    limiter, _ = limiter_and_clock

    for i in range(5):
        limiter.record_failure(
            f"voter{i}", "203.0.113.10"
        )

    assert limiter.is_blocked(
        "another_voter", "203.0.113.10"
    ) is True


# Test 4: Lockout expires after 15 minutes
def test_window_expires_exactly_at_fifteen_minutes(
    limiter_and_clock
):
    limiter, now = limiter_and_clock

    for _ in range(5):
        limiter.record_failure(
            "voter1", "203.0.113.10"
        )

    now[0] = 1899.0

    assert limiter.is_blocked(
        "voter1", "203.0.113.10"
    ) is True

    now[0] = 1900.0

    assert limiter.is_blocked(
        "voter1", "203.0.113.10"
    ) is False


# Test 5: Unrelated accounts remain unaffected
def test_unrelated_account_and_source_unaffected(
    limiter_and_clock
):
    limiter, _ = limiter_and_clock

    for _ in range(5):
        limiter.record_failure(
            "voter1", "203.0.113.10"
        )

    assert limiter.is_blocked(
        "voter2", "203.0.113.11"
    ) is False


# Test 6: Blocked requests do not extend lockout
def test_blocked_attempts_do_not_extend_window(
    limiter_and_clock
):
    limiter, now = limiter_and_clock

    for _ in range(5):
        limiter.record_failure(
            "voter1", "203.0.113.10"
        )

    now[0] = 1500.0

    assert limiter.record_failure(
        "voter1", "203.0.113.10"
    ) is True

    now[0] = 1900.0

    assert limiter.is_blocked(
        "voter1", "203.0.113.10"
    ) is False


# Test 7: Security event logging
def test_rate_limit_event_logged(
    limiter_and_clock, caplog
):
    limiter, _ = limiter_and_clock

    with caplog.at_level(
        logging.WARNING,
        logger="evp.authentication"
    ):
        for _ in range(5):
            limiter.record_failure(
                "voter1", "203.0.113.10"
            )

    assert "rate_limit_reached scope=account" in caplog.text
    assert "rate_limit_reached scope=source" in caplog.text

    # Avoid exposing raw account identifiers in logs
    assert "voter1" not in caplog.text


# Test 8: Reject missing identifiers
@pytest.mark.parametrize(
    "account,source",
    [
        (None, "203.0.113.1"),
        ("", "203.0.113.1"),
        ("voter1", None),
        ("voter1", ""),
    ]
)
def test_bad_identifiers_rejected(
    limiter_and_clock, account, source
):
    limiter, _ = limiter_and_clock

    with pytest.raises(ValueError):
        limiter.record_failure(account, source)
