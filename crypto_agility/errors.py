"""
SR-14: Crypto-agility error types.

Security controls:
- One base class (CryptoError) so callers can fail
  closed on any cryptographic problem
- Distinct subclasses for unknown, unavailable and
  disallowed algorithms, missing keys, malformed
  envelopes and failed decryption
- Messages never contain key material, plaintext
  or envelope contents

Local academic prototype.
"""


class CryptoError(Exception):
    """Base class for every crypto_agility failure."""


class UnknownAlgorithm(CryptoError):
    """The algorithm name is not in the registry."""


class AlgorithmNotAllowed(CryptoError):
    """The algorithm is known but the policy does not allow it."""


class AlgorithmUnavailable(CryptoError):
    """The algorithm is reserved but has no implementation."""


class InvalidPolicy(CryptoError):
    """A crypto policy is malformed."""


class KeyNotFound(CryptoError):
    """No usable key exists for the requested purpose and algorithm."""


class InvalidEnvelope(CryptoError):
    """A cryptographic envelope is malformed."""


class DecryptionError(CryptoError):
    """Decryption failed: tampered data, wrong key or bad envelope."""


class CryptoNotConfigured(CryptoError):
    """No keys or policy were configured, so crypto is refused."""
