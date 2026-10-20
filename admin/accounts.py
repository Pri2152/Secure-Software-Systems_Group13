"""
SR-02: Staff account creation rules (no shared accounts).

Security controls:
- Staff IDs must be person-linked: generic or shared
  names (admin, officer, test, root, staff, ... and
  numbered variants such as officer-01 or admin2)
  are refused
- Role must be one of the SR-04 staff roles
  (Workstream E's RBAC matrix); "voter" is refused
- Certificate fingerprint must be a SHA-256 hex value
  and may belong to only one account (checked here
  and enforced by a UNIQUE constraint)
- Minimum password length; the password is stored
  only as an Argon2id hash
- Errors are generic and never echo the password

Local academic prototype.
"""

import re

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from crypto_agility.passwords import hash_password

from .models import (
    FULL_NAME_MAX_LENGTH,
    STAFF_ID_MAX_LENGTH,
    StaffAccount,
)


STAFF_ROLES = frozenset({"officer", "delegate", "administrator", "auditor"})

GENERIC_NAMES = frozenset({
    "admin",
    "administrator",
    "officer",
    "delegate",
    "auditor",
    "test",
    "tester",
    "shared",
    "root",
    "user",
    "staff",
    "system",
    "guest",
    "demo",
    "service",
    "operator",
    "superuser",
    "sysadmin",
})

STAFF_ID_MIN_LENGTH = 3
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024
MIN_PERSON_TOKEN_LENGTH = 2

STAFF_ID_PATTERN = re.compile(r"[a-z][a-z0-9]*(?:[-_.][a-z0-9]+)*")
NAME_SEPARATORS = re.compile(r"[-_.]")
FINGERPRINT_PATTERN = re.compile(r"[0-9a-f]{64}")


class StaffAccountError(ValueError):
    """A staff account request breaks the account rules."""


def normalize_staff_id(staff_id) -> str | None:
    """Lower-case, validated staff ID, or None if malformed."""

    if not isinstance(staff_id, str):
        return None

    candidate = staff_id.strip().casefold()

    if (
        not STAFF_ID_MIN_LENGTH <= len(candidate) <= STAFF_ID_MAX_LENGTH
        or not STAFF_ID_PATTERN.fullmatch(candidate)
    ):
        return None

    return candidate


def is_generic_name(staff_id: str) -> bool:
    """
    True when the ID names no person: every part, with
    digits removed, is a generic word (officer-01,
    admin2, test_user) or nothing is left.
    """

    parts = [
        re.sub(r"[0-9]", "", part)
        for part in NAME_SEPARATORS.split(staff_id.casefold())
    ]
    person_parts = [
        part
        for part in parts
        if len(part) >= MIN_PERSON_TOKEN_LENGTH
        and part not in GENERIC_NAMES
    ]

    return not person_parts


def normalize_fingerprint(fingerprint) -> str | None:
    if not isinstance(fingerprint, str):
        return None

    candidate = fingerprint.strip().replace(":", "").casefold()

    return candidate if FINGERPRINT_PATTERN.fullmatch(candidate) else None


def _validate_full_name(full_name) -> str:
    if not isinstance(full_name, str):
        raise StaffAccountError("A full name is required")

    cleaned = " ".join(full_name.split())

    if not cleaned or len(cleaned) > FULL_NAME_MAX_LENGTH:
        raise StaffAccountError("A full name is required")

    if cleaned.casefold() in GENERIC_NAMES:
        raise StaffAccountError("Full name must identify a person")

    return cleaned


def _validate_password(password) -> str:
    if (
        not isinstance(password, str)
        or not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH
    ):
        raise StaffAccountError(
            f"Password must be {MIN_PASSWORD_LENGTH} to "
            f"{MAX_PASSWORD_LENGTH} characters"
        )

    return password


def create_staff_account(
    db_session,
    *,
    staff_id,
    full_name,
    role,
    password,
    cert_fingerprint,
) -> StaffAccount:
    """Create one person-linked staff account."""

    normalized_id = normalize_staff_id(staff_id)

    if normalized_id is None:
        raise StaffAccountError("Invalid staff ID")

    if is_generic_name(normalized_id):
        raise StaffAccountError("Staff ID must identify a person")

    if role not in STAFF_ROLES:
        raise StaffAccountError("Invalid staff role")

    fingerprint = normalize_fingerprint(cert_fingerprint)

    if fingerprint is None:
        raise StaffAccountError("Invalid certificate fingerprint")

    name = _validate_full_name(full_name)
    _validate_password(password)

    existing = db_session.scalar(
        select(StaffAccount.id).where(
            (StaffAccount.staff_id == normalized_id)
            | (StaffAccount.cert_fingerprint == fingerprint)
        )
    )

    if existing is not None:
        raise StaffAccountError(
            "Staff ID or certificate is already registered"
        )

    account = StaffAccount(
        staff_id=normalized_id,
        full_name=name,
        role=role,
        password_hash=hash_password(password),
        cert_fingerprint=fingerprint,
        is_active=True,
    )

    db_session.add(account)

    try:
        db_session.flush()
    except IntegrityError:
        db_session.rollback()
        raise StaffAccountError(
            "Staff ID or certificate is already registered"
        ) from None

    return account


def find_staff_account(db_session, staff_id) -> StaffAccount | None:
    normalized_id = normalize_staff_id(staff_id)

    if normalized_id is None:
        return None

    return db_session.scalar(
        select(StaffAccount).where(StaffAccount.staff_id == normalized_id)
    )


def staff_account_is_active(db_session, staff_id) -> bool:
    """True only for an existing, active account."""

    account = find_staff_account(db_session, staff_id)

    return account is not None and account.is_active is True
