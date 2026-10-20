"""
SR-14 (supports SR-02): Agile Argon2id password hashing.

Security controls:
- Argon2id parameter sets are named algorithms in the
  registry ("password" family), so the cost settings
  are chosen by the crypto policy
- Stored hashes are self-describing ($argon2id$v=19$
  m=...,t=...,p=...), so hashes made with older
  parameters still verify
- Rehash-on-login migration: after a successful
  verification, a hash with outdated parameters is
  replaced by a new one (check_needs_rehash)
- Any malformed input or hash returns "not verified"
  instead of raising (fail closed)

argon2id-v1 matches the argon2-cffi defaults used by
Workstream A's auth.py, so voter hashes count as
current. auth.py itself is not changed.

Local academic prototype.
"""

from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)
from argon2.low_level import Type

from .algorithms import PASSWORD, Algorithm


ARGON2_HASH_BYTES = 32
ARGON2_SALT_BYTES = 16

PASSWORD_FAILURES = (
    VerifyMismatchError,
    VerificationError,
    InvalidHashError,
)


@dataclass(frozen=True)
class Argon2Parameters:
    time_cost: int
    memory_cost_kib: int
    parallelism: int


class Argon2idAlgorithm(Algorithm):
    """One named Argon2id parameter set."""

    def __init__(self, name: str, parameters: Argon2Parameters):
        super().__init__(name, PASSWORD)

        self.parameters = parameters
        self._hasher = PasswordHasher(
            time_cost=parameters.time_cost,
            memory_cost=parameters.memory_cost_kib,
            parallelism=parameters.parallelism,
            hash_len=ARGON2_HASH_BYTES,
            salt_len=ARGON2_SALT_BYTES,
            type=Type.ID,
        )

    def hash(self, password: str) -> str:
        if not isinstance(password, str) or not password:
            raise ValueError("A non-empty password is required")

        return self._hasher.hash(password)

    def verify(self, stored_hash: str, password: str) -> bool:
        if not isinstance(stored_hash, str):
            return False

        if not isinstance(password, str) or not password:
            return False

        try:
            return self._hasher.verify(stored_hash, password)
        except PASSWORD_FAILURES:
            return False

    def needs_rehash(self, stored_hash: str) -> bool:
        try:
            return self._hasher.check_needs_rehash(stored_hash)
        except (InvalidHashError, ValueError):
            return True


# RFC 9106 second recommended option (argon2-cffi defaults)
ARGON2ID_V1 = Argon2idAlgorithm(
    "argon2id-v1",
    Argon2Parameters(time_cost=3, memory_cost_kib=65536, parallelism=4),
)


def hash_password(
    password: str, algorithm: Argon2idAlgorithm = ARGON2ID_V1
) -> str:
    """Hash a password with the given (default: current) parameter set."""

    return algorithm.hash(password)


def verify_and_upgrade(
    stored_hash: str,
    password: str,
    algorithm: Argon2idAlgorithm = ARGON2ID_V1,
) -> tuple[bool, str | None]:
    """
    Verify a password. Returns (ok, new_hash): new_hash
    is set only when the password is correct and the
    stored hash uses outdated parameters, so the caller
    can save it (rehash-on-login).
    """

    if not algorithm.verify(stored_hash, password):
        return False, None

    if algorithm.needs_rehash(stored_hash):
        return True, algorithm.hash(password)

    return True, None
