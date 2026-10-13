
"""
SR-01: Integrated voter authentication prototype.

Combines:
- Argon2id password verification
- TOTP MFA verification
- Account and source rate limiting
- TOTP replay prevention
- Successful authentication callback

Uses synthetic voter records during testing.
"""

import logging
import secrets
import time
from dataclasses import dataclass
from threading import Lock

from auth import (
    hash_password,
    verify_password,
    verify_totp_code,
)
from rate_limit import LoginRateLimiter


logger = logging.getLogger("evp.login")


@dataclass(frozen=True)
class VoterRecord:
    voter_id: str
    password_hash: str
    totp_secret: str


@dataclass(frozen=True)
class AuthenticationResult:
    success: bool
    status: str


class TOTPReplayGuard:
    """
    Prevent acceptance of more than one TOTP code
    per voter during the same or an earlier time step.

    In-memory prototype only.
    """

    def __init__(self):
        self.last_used_step = {}
        self.lock = Lock()

    def verify_and_consume(
        self, voter_id, secret, code, timestamp
    ):
        if not verify_totp_code(
            secret, code, at_time=timestamp
        ):
            return False

        current_step = int(timestamp // 30)

        with self.lock:
            previous_step = self.last_used_step.get(
                voter_id
            )

            if (
                previous_step is not None
                and current_step <= previous_step
            ):
                return False

            self.last_used_step[voter_id] = current_step
            return True


class LoginCoordinator:
    """
    Coordinates password and MFA authentication.

    Does not create a public login endpoint.
    """

    def __init__(
        self,
        lookup_voter,
        rate_limiter=None,
        clock=None,
        replay_guard=None,
    ):
        self.lookup_voter = lookup_voter
        self.rate_limiter = (
            rate_limiter
            if rate_limiter is not None
            else LoginRateLimiter()
        )
        self.clock = clock or time.time
        self.replay_guard = (
            replay_guard
            if replay_guard is not None
            else TOTPReplayGuard()
        )

        # Dummy hash to reduce timing differences
        # when an account does not exist.
        self.dummy_hash = hash_password(
            secrets.token_urlsafe(32)
        )

    def authenticate(
        self,
        account_id,
        password,
        totp_code,
        source_id,
        on_authenticated,
    ):
        """
        Authenticate using password and TOTP.

        on_authenticated must be a trusted server-side
        callback that creates the authenticated session.

        source_id must be obtained from a trusted
        server-side source, not user-controlled input.
        """

        if not callable(on_authenticated):
            raise TypeError(
                "An authentication callback is required"
            )

        account_key = account_id.strip().casefold()

        # Check account and source limits first
        if self.rate_limiter.is_blocked(
            account_key, source_id
        ):
            logger.warning("authentication_rate_limited")

            return AuthenticationResult(
                False, "rate_limited"
            )

        voter = self.lookup_voter(account_key)

        # Use a dummy hash for unknown accounts
        stored_hash = (
            voter.password_hash
            if isinstance(voter, VoterRecord)
            else self.dummy_hash
        )

        password_valid = verify_password(
            stored_hash, password
        )

        if (
            not isinstance(voter, VoterRecord)
            or not password_valid
        ):
            self.rate_limiter.record_failure(
                account_key, source_id
            )
            logger.info("authentication_rejected")

            return AuthenticationResult(
                False, "invalid_credentials"
            )

        # Verify and consume the one-time MFA code
        mfa_valid = self.replay_guard.verify_and_consume(
            voter.voter_id,
            voter.totp_secret,
            totp_code,
            self.clock(),
        )

        if not mfa_valid:
            self.rate_limiter.record_failure(
                account_key, source_id
            )
            logger.info("authentication_rejected")

            return AuthenticationResult(
                False, "invalid_credentials"
            )

        # Both factors have passed.
        # Only now establish the authenticated session.
        on_authenticated(voter.voter_id)

        logger.info("authentication_success")

        return AuthenticationResult(
            True, "authenticated"
        )
