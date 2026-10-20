"""
SR-14: Central crypto-agility service.

Security controls:
- Single entry point for platform cryptography; the
  algorithm for each new output comes from the crypto
  policy through the secure factory
- Self-describing outputs: hashes carry an
  "<alg>:" prefix and every envelope records
  {"alg", "kid", "v"}
- Verification uses the algorithm named in the
  envelope only while the policy still allows it,
  and the key ID must belong to the same purpose and
  algorithm (key-confusion protection)
- Strict envelope validation: exact field set,
  types, format version, base64 and size caps
- verify_* methods return False on any problem and
  never raise; constant-time comparisons only

Local academic prototype.
"""

import base64
import binascii
import hmac

from .algorithms import HASH, MAC
from .errors import CryptoError, InvalidEnvelope
from .keys import KeyStore, check_purpose
from .policy import CryptoPolicy
from .registry import AlgorithmRegistry, CryptoFactory


ENVELOPE_VERSION = 1
HEADER_FIELDS = frozenset({"alg", "kid", "v"})

MAX_ALG_LENGTH = 64
MAX_KID_LENGTH = 128
MAX_HASH_VALUE_LENGTH = 256
MAX_TAG_B64_LENGTH = 4096

VERIFY_FAILURES = (CryptoError, ValueError, TypeError)


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(value, max_length: int) -> bytes:
    if not isinstance(value, str) or len(value) > max_length:
        raise InvalidEnvelope("Envelope field is invalid")

    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error):
        raise InvalidEnvelope("Envelope field is invalid") from None


def _require_bytes(data) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    return data


def parse_envelope(envelope, binary_fields: dict[str, int]) -> dict:
    """
    Validate an envelope and decode its binary
    fields. binary_fields maps field name to the
    maximum base64 length. Unknown fields are refused.
    """

    if not isinstance(envelope, dict):
        raise InvalidEnvelope("Envelope must be an object")

    if set(envelope) != HEADER_FIELDS | set(binary_fields):
        raise InvalidEnvelope("Envelope fields are invalid")

    alg, kid, version = envelope["alg"], envelope["kid"], envelope["v"]

    if not isinstance(alg, str) or len(alg) > MAX_ALG_LENGTH:
        raise InvalidEnvelope("Envelope algorithm is invalid")

    if not isinstance(kid, str) or len(kid) > MAX_KID_LENGTH:
        raise InvalidEnvelope("Envelope key ID is invalid")

    if type(version) is not int or version != ENVELOPE_VERSION:
        raise InvalidEnvelope("Envelope version is not supported")

    parsed = {"alg": alg, "kid": kid}

    for name, max_length in binary_fields.items():
        parsed[name] = _b64decode(envelope[name], max_length)

    return parsed


class CryptoService:
    """Hashing, MACs and (later) signatures and encryption by purpose."""

    def __init__(
        self,
        registry: AlgorithmRegistry,
        policy: CryptoPolicy,
        keystore: KeyStore,
    ):
        self.registry = registry
        self.factory = CryptoFactory(registry, policy)
        self.keys = keystore

    @property
    def policy(self) -> CryptoPolicy:
        return self.factory.policy

    def with_policy(self, policy: CryptoPolicy) -> "CryptoService":
        """Same registry and keys under a new policy (migration)."""

        return CryptoService(self.registry, policy, self.keys)

    # Hashing

    def hash(self, data: bytes) -> str:
        """Self-describing digest, e.g. "sha256:<hex>"."""

        _require_bytes(data)
        algorithm = self.factory.for_new(HASH)

        return f"{algorithm.name}:{algorithm.digest(data).hex()}"

    def verify_hash(self, data: bytes, value: str) -> bool:
        if (
            not isinstance(data, bytes)
            or not isinstance(value, str)
            or len(value) > MAX_HASH_VALUE_LENGTH
        ):
            return False

        name, separator, digest_hex = value.partition(":")

        if not separator:
            return False

        try:
            algorithm = self.factory.for_verify(HASH, name)
        except CryptoError:
            return False

        return hmac.compare_digest(
            algorithm.digest(data).hex().encode("ascii"),
            digest_hex.encode("utf-8"),
        )

    # Message authentication codes

    def mac(self, purpose: str, data: bytes) -> dict:
        """HMAC envelope {"alg", "kid", "v", "sig"}."""

        check_purpose(purpose)
        _require_bytes(data)

        algorithm = self.factory.for_new(MAC)
        key = self.keys.current(purpose, algorithm)

        return self._envelope(
            algorithm.name,
            key.kid,
            sig=algorithm.compute(key.material.secret, data),
        )

    def verify_mac(self, purpose: str, data: bytes, envelope) -> bool:
        try:
            check_purpose(purpose)
            _require_bytes(data)

            fields = parse_envelope(envelope, {"sig": MAX_TAG_B64_LENGTH})
            algorithm = self.factory.for_verify(MAC, fields["alg"])
            key = self.keys.get(fields["kid"], purpose, algorithm)

            return algorithm.verify(
                key.material.secret, data, fields["sig"]
            )

        except VERIFY_FAILURES:
            return False

    @staticmethod
    def _envelope(alg: str, kid: str, **binary_fields: bytes) -> dict:
        envelope = {"alg": alg, "kid": kid, "v": ENVELOPE_VERSION}

        for name, value in binary_fields.items():
            envelope[name] = _b64encode(value)

        return envelope
