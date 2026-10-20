"""
SR-14: Named cryptographic algorithm implementations.

Security controls:
- Every algorithm has a stable name and belongs to
  exactly one family, so outputs can record which
  algorithm produced them
- Only well-reviewed primitives from the standard
  library and the `cryptography` package are used
- Reserved algorithms have a name but no
  implementation; any use raises AlgorithmUnavailable

This is the only place in the platform that calls
cryptographic libraries directly.

Local academic prototype.
"""

import hashlib
import hmac
import os

from collections.abc import Callable
from dataclasses import dataclass

from .errors import AlgorithmUnavailable


# Algorithm families
HASH = "hash"
MAC = "mac"
SIGN = "sign"
AEAD = "aead"
SEAL = "seal"
PASSWORD = "password"

FAMILIES = frozenset({HASH, MAC, SIGN, AEAD, SEAL, PASSWORD})

SYMMETRIC_KEY_BYTES = 32


@dataclass(frozen=True, repr=False)
class KeyMaterial:
    """
    Secret or asymmetric key material for one key
    version. Its repr never shows the key.
    """

    secret: bytes | None = None
    private_key: object = None
    public_key: object = None

    def __repr__(self) -> str:
        return "<KeyMaterial redacted>"


class Algorithm:
    """A named algorithm in one family."""

    available = True

    def __init__(self, name: str, family: str):
        if family not in FAMILIES:
            raise ValueError("Unknown algorithm family")

        if not isinstance(name, str) or not name:
            raise ValueError("Algorithm name must be a non-empty string")

        self.name = name
        self.family = family

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.family}:{self.name}>"


class ReservedAlgorithm(Algorithm):
    """
    A registry slot for an algorithm that is planned
    but not implemented. It can never be used.
    """

    available = False

    def __getattr__(self, attribute):
        if attribute.startswith("__"):
            raise AttributeError(attribute)

        raise AlgorithmUnavailable(
            "Algorithm is reserved and not available"
        )


class HashAlgorithm(Algorithm):
    """A one-way hash function."""

    def __init__(self, name: str, hash_constructor: Callable):
        super().__init__(name, HASH)
        self._hash_constructor = hash_constructor

    def digest(self, data: bytes) -> bytes:
        return self._hash_constructor(data).digest()


class HmacAlgorithm(Algorithm):
    """A keyed message authentication code (HMAC)."""

    def __init__(
        self,
        name: str,
        hash_constructor: Callable,
        key_size: int = SYMMETRIC_KEY_BYTES,
    ):
        super().__init__(name, MAC)
        self._hash_constructor = hash_constructor
        self.key_size = key_size

    def generate_key(self) -> KeyMaterial:
        return KeyMaterial(secret=os.urandom(self.key_size))

    def check_key(self, material: KeyMaterial) -> None:
        if (
            not isinstance(material.secret, bytes)
            or len(material.secret) != self.key_size
        ):
            raise ValueError("Invalid MAC key")

    def compute(self, key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, self._hash_constructor).digest()

    def verify(self, key: bytes, data: bytes, tag: bytes) -> bool:
        return hmac.compare_digest(self.compute(key, data), tag)


SHA256 = HashAlgorithm("sha256", hashlib.sha256)
SHA3_256 = HashAlgorithm("sha3-256", hashlib.sha3_256)

HMAC_SHA256 = HmacAlgorithm("hmac-sha256", hashlib.sha256)
HMAC_SHA3_256 = HmacAlgorithm("hmac-sha3-256", hashlib.sha3_256)
