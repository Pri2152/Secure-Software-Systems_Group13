"""
SR-02: Phishing-resistant staff authentication.

Security controls:
- Two factors, both required: a client certificate
  verified by the Nginx mTLS gateway whose SHA-256
  fingerprint matches the account (possession; cannot
  be typed into a phishing site), and the account's
  Argon2id password (knowledge)
- Fingerprints compared in constant time
- Every failure has the same result for the client;
  the specific reason goes only to the audit log
- A dummy Argon2id check runs for unknown accounts so
  response time does not reveal which IDs exist
- Workstream A's SR-01 LoginRateLimiter is reused:
  5 failures in 15 minutes per account and per source
- Outdated Argon2 parameters are upgraded on login
  (SR-14 rehash helper)
- Every success, failure and lockout is audited on the
  admin stream (SR-17) without the password

Local academic prototype.
"""

import hmac
import secrets

from collections.abc import Callable
from dataclasses import dataclass
from functools import cache

from crypto_agility.passwords import hash_password, verify_and_upgrade

from .accounts import find_staff_account, normalize_staff_id
from .gateway import GatewayIdentity
from .models import StaffAccount


STATUS_AUTHENTICATED = "authenticated"
STATUS_INVALID = "invalid_credentials"
STATUS_RATE_LIMITED = "rate_limited"

AUDIT_STREAM = "admin"
AUDIT_ACTOR = "staff"

LOGIN_EVENT_PREFIX = "STAFF_LOGIN"
STEP_UP_EVENT_PREFIX = "STAFF_STEP_UP"


@dataclass(frozen=True)
class StaffLoginResult:
    success: bool
    status: str
    account: StaffAccount | None = None


@cache
def _dummy_hash() -> str:
    return hash_password(secrets.token_urlsafe(32))


def certificate_matches(
    account: StaffAccount | None, identity: GatewayIdentity
) -> bool:
    if account is None or not identity.cert_verified:
        return False

    if not isinstance(identity.cert_fingerprint, str):
        return False

    return hmac.compare_digest(
        account.cert_fingerprint.encode("ascii"),
        identity.cert_fingerprint.casefold().encode("ascii", "replace"),
    )


class StaffAuthenticator:
    """Checks both staff factors and records the outcome."""

    def __init__(
        self,
        *,
        db_session: Callable,
        rate_limiter,
        audit: Callable,
    ):
        self._db_session = db_session
        self.rate_limiter = rate_limiter
        self.audit = audit

    def authenticate(
        self,
        staff_id,
        password,
        identity: GatewayIdentity | None,
        *,
        event_prefix: str = LOGIN_EVENT_PREFIX,
    ) -> StaffLoginResult:
        """
        Check both factors. event_prefix names the audit
        events (STAFF_LOGIN_* or STAFF_STEP_UP_*).
        """

        def audit(suffix, outcome, actor_id, details):
            self.audit(
                f"{event_prefix}_{suffix}",
                stream=AUDIT_STREAM,
                actor_type=AUDIT_ACTOR,
                actor_id=actor_id,
                outcome=outcome,
                details=details,
                source_ip=identity.source_ip if identity else None,
            )

        if identity is None:
            audit("FAILURE", "failure", None, {"reason": "untrusted_gateway"})
            return StaffLoginResult(False, STATUS_INVALID)

        normalized_id = normalize_staff_id(staff_id)

        if normalized_id is None:
            audit("FAILURE", "failure", None, {"reason": "invalid_staff_id"})
            return StaffLoginResult(False, STATUS_INVALID)

        if self.rate_limiter.is_blocked(normalized_id, identity.source_ip):
            audit("RATE_LIMITED", "denied", None, {})
            return StaffLoginResult(False, STATUS_RATE_LIMITED)

        account = find_staff_account(self._db_session(), normalized_id)

        password_ok, new_hash = verify_and_upgrade(
            account.password_hash if account else _dummy_hash(),
            password,
        )

        reason = self._failure_reason(account, identity, password_ok)

        if reason is not None:
            self.rate_limiter.record_failure(
                normalized_id, identity.source_ip
            )
            audit(
                "FAILURE", "failure",
                account.staff_id if account else None,
                {"reason": reason},
            )
            return StaffLoginResult(False, STATUS_INVALID)

        if new_hash is not None:
            account.password_hash = new_hash
            self._db_session().commit()

        audit("SUCCESS", "success", account.staff_id, {"role": account.role})

        return StaffLoginResult(True, STATUS_AUTHENTICATED, account)

    @staticmethod
    def _failure_reason(account, identity, password_ok) -> str | None:
        if account is None:
            return "unknown_account"

        if not account.is_active:
            return "inactive_account"

        if not identity.cert_verified:
            return "missing_certificate"

        if not certificate_matches(account, identity):
            return "certificate_mismatch"

        if not password_ok:
            return "wrong_password"

        return None
