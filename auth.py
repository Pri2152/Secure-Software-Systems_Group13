
"""
SR-01: Voter password authentication.
Uses Argon2id for password hashing and verification.
"""

from argon2 import PasswordHasher
from argon2.low_level import Type
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)

# Configure Argon2id
password_hasher = PasswordHasher(type=Type.ID)


def hash_password(password):
    """
    Generate a secure Argon2id password hash.
    """

    if not isinstance(password, str) or not password:
        raise ValueError("A non-empty password is required")

    return password_hasher.hash(password)


def verify_password(stored_hash, entered_password):
    """
    Return True when the password matches.
    Otherwise, return False.
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
