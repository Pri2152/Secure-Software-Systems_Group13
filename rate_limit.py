
"""
SR-01: Authentication rate limiting.

Single-process prototype:
- Maximum 5 failed attempts in 15 minutes
- Separate limits by account and source
- Security event logging

Replace in-memory storage with a shared backend
such as Redis before multi-process deployment.
"""

import logging
import time
from collections import deque
from threading import Lock


class LoginRateLimiter:

    def __init__(
        self,
        max_failures=5,
        window_seconds=900,
        clock=None
    ):
        if not isinstance(max_failures, int) or max_failures < 1:
            raise ValueError("max_failures must be positive")

        if (
            not isinstance(window_seconds, (int, float))
            or window_seconds <= 0
        ):
            raise ValueError("window_seconds must be positive")

        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.clock = clock or time.monotonic

        self.attempts = {}
        self.lock = Lock()
        self.logger = logging.getLogger("evp.authentication")

    @staticmethod
    def _keys(account_id, source_id):
        if (
            not isinstance(account_id, str)
            or not account_id.strip()
        ):
            raise ValueError(
                "account_id must be a non-empty string"
            )

        if (
            not isinstance(source_id, str)
            or not source_id.strip()
        ):
            raise ValueError(
                "source_id must be a non-empty string"
            )

        return (
            ("account", account_id.strip().casefold()),
            ("source", source_id.strip())
        )

    def _count(self, key, now):
        failures = self.attempts.get(key)

        if failures is None:
            return 0

        while (
            failures
            and now - failures[0] >= self.window_seconds
        ):
            failures.popleft()

        if not failures:
            del self.attempts[key]
            return 0

        return len(failures)

    def is_blocked(self, account_id, source_id):
        """Check account and source limits."""

        account_key, source_key = self._keys(
            account_id, source_id
        )

        with self.lock:
            now = self.clock()

            return (
                self._count(account_key, now)
                >= self.max_failures
                or self._count(source_key, now)
                >= self.max_failures
            )

    def record_failure(self, account_id, source_id):
        """
        Record one failed authentication attempt.

        Returns True when the login is blocked.
        """

        account_key, source_key = self._keys(
            account_id, source_id
        )

        with self.lock:
            now = self.clock()

            account_count = self._count(account_key, now)
            source_count = self._count(source_key, now)

            # Do not extend an existing lockout
            if (
                account_count >= self.max_failures
                or source_count >= self.max_failures
            ):
                return True

            self.attempts.setdefault(
                account_key, deque()
            ).append(now)

            self.attempts.setdefault(
                source_key, deque()
            ).append(now)

            # Log threshold events without raw identifiers
            if account_count + 1 == self.max_failures:
                self.logger.warning(
                    "rate_limit_reached scope=account"
                )

            if source_count + 1 == self.max_failures:
                self.logger.warning(
                    "rate_limit_reached scope=source"
                )

            return (
                account_count + 1 >= self.max_failures
                or source_count + 1 >= self.max_failures
            )
