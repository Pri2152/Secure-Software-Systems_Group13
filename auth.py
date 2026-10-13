
"""
SR-01: Secure voter authentication.

Provides:
- Argon2id password hashing
- Password verification
- TOTP secret generation
- TOTP code verification

Full authentication requires additional controls.
"""

import binascii

import pyotp
from argon2 import PasswordHasher
from argon2.low_level import Type
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)


# Configure Argon2id password hashing
password_hasher = PasswordHasher(type=Type.ID)


def hash_password(password):
    """
    Generate an Argon2id password hash.
    """

    if not isinstance(password, str) or not password:
        raise ValueError("A non-empty password is required")

    return password_hasher.hash(password)


def verify_password(stored_hash, entered_password):
    """
    Verify a password against a stored Argon2id hash.
    """

    if not isinstance(stored_hash, str):
        return False

    if not isinstance(entered_password, str):
        return False

    try:
        return password_hasher.verify(
            stored_hash,
            entered_password
        )

    except (
        VerifyMismatchError,
        VerificationError,
        InvalidHashError
    ):
        return False


# SR-01: Generate an MFA secret
def generate_totp_secret():
    """
    Generate a unique Base32 TOTP secret.

    The secret must be stored securely and must
    never be committed to GitHub.
    """

    return pyotp.random_base32()


# SR-01: Verify a six-digit TOTP code
def verify_totp_code(secret, code, at_time=None):
    """
    Verify a TOTP code using a 30-second interval.

    Returns True if valid, otherwise False.

    This function does not yet enforce one-time
    consumption of a successfully used code.
    """

    if not isinstance(secret, str) or not secret:
        return False

    if not isinstance(code, str):
        return False

    if (
        len(code) != 6
        or not code.isascii()
        or not code.isdigit()
    ):
        return False

    try:
        totp = pyotp.TOTP(
            secret,
            digits=6,
            interval=30
        )

        return bool(
            totp.verify(
                code,
                for_time=at_time,
                valid_window=0
            )
        )

    except (
        ValueError,
        TypeError,
        binascii.Error
    ):
        return False
