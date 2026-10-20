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
- Authenticated encryption (AES-256-GCM) with a random
  nonce per message; the key ID is bound into the
  associated data; decrypt/open raise DecryptionError
  on any tampering, wrong key or bad envelope
- Sealing (RSA-OAEP + AES-256-GCM) lets voter clients
  encrypt with only the public "election" key; only
  the compartment holding the private key can open
- Password hashing uses the policy's Argon2id
  parameter set, with rehash-on-login migration

Local academic prototype.
"""

import base64
import binascii
import hmac

from .algorithms import (
    AEAD,
    HASH,
    MAC,
    PASSWORD,
    SEAL,
    SIGN,
    public_key_pem,
)
from .errors import (
    CryptoError,
    DecryptionError,
    InvalidEnvelope,
    KeyNotFound,
)
from .keys import KeyStore, check_purpose
from .passwords import verify_and_upgrade
from .policy import CryptoPolicy
from .registry import AlgorithmRegistry, CryptoFactory


ENVELOPE_VERSION = 1
HEADER_FIELDS = frozenset({"alg", "kid", "v"})

MAX_ALG_LENGTH = 64
MAX_KID_LENGTH = 128
MAX_HASH_VALUE_LENGTH = 256
MAX_TAG_B64_LENGTH = 4096
MAX_PLAINTEXT_BYTES = 1024 * 1024
MAX_CIPHERTEXT_B64_LENGTH = 2 * 1024 * 1024

# The public seal key is published under this purpose
ELECTION_PURPOSE = "election"

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


def _require_plaintext(plaintext) -> bytes:
    _require_bytes(plaintext)

    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise ValueError("Plaintext is too large")

    return plaintext


def _bound_aad(kid: str, aad: bytes) -> bytes:
    """Associated data that also authenticates the key ID."""

    return kid.encode("ascii") + b"\x00" + _require_bytes(aad)


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
    """Hashing, MACs, signatures and encryption by purpose."""

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

    # Digital signatures

    def sign(self, purpose: str, data: bytes) -> dict:
        """Signature envelope {"alg", "kid", "v", "sig"}."""

        check_purpose(purpose)
        _require_bytes(data)

        algorithm = self.factory.for_new(SIGN)
        key = self.keys.current(purpose, algorithm)

        if key.material.private_key is None:
            raise KeyNotFound("No private signing key for this purpose")

        return self._envelope(
            algorithm.name,
            key.kid,
            sig=algorithm.sign(key.material.private_key, data),
        )

    def verify(self, purpose: str, data: bytes, envelope) -> bool:
        """
        Verify with the algorithm and key named in the
        envelope. False (never raises) on any problem.
        """

        try:
            check_purpose(purpose)
            _require_bytes(data)

            fields = parse_envelope(envelope, {"sig": MAX_TAG_B64_LENGTH})
            algorithm = self.factory.for_verify(SIGN, fields["alg"])
            key = self.keys.get(fields["kid"], purpose, algorithm)

            return algorithm.verify(
                key.material.public_key, data, fields["sig"]
            )

        except VERIFY_FAILURES:
            return False

    def public_key_pem(self, purpose: str) -> bytes:
        """
        PEM public key: the sealing key for "election",
        otherwise the current signing key.
        """

        check_purpose(purpose)

        family = SEAL if purpose == ELECTION_PURPOSE else SIGN
        algorithm = self.factory.for_new(family)

        return public_key_pem(
            self.keys.current(purpose, algorithm).material.public_key
        )

    # Authenticated encryption

    def encrypt(
        self, purpose: str, plaintext: bytes, aad: bytes = b""
    ) -> dict:
        """AEAD envelope {"alg", "kid", "v", "nonce", "ct"}."""

        check_purpose(purpose)
        _require_plaintext(plaintext)

        algorithm = self.factory.for_new(AEAD)
        key = self.keys.current(purpose, algorithm)

        nonce, ciphertext = algorithm.encrypt(
            key.material.secret, plaintext, _bound_aad(key.kid, aad)
        )

        return self._envelope(
            algorithm.name, key.kid, nonce=nonce, ct=ciphertext
        )

    def decrypt(self, purpose: str, envelope, aad: bytes = b"") -> bytes:
        """Plaintext, or DecryptionError on any failure."""

        try:
            check_purpose(purpose)

            fields = parse_envelope(envelope, {
                "nonce": MAX_TAG_B64_LENGTH,
                "ct": MAX_CIPHERTEXT_B64_LENGTH,
            })
            algorithm = self.factory.for_verify(AEAD, fields["alg"])
            key = self.keys.get(fields["kid"], purpose, algorithm)

            return algorithm.decrypt(
                key.material.secret,
                fields["nonce"],
                fields["ct"],
                _bound_aad(fields["kid"], aad),
            )

        except VERIFY_FAILURES:
            raise DecryptionError("Decryption failed") from None

    # Public-key sealing

    def seal(self, purpose: str, plaintext: bytes) -> dict:
        """
        Envelope {"alg", "kid", "v", "wrapped_key",
        "nonce", "ct"}; needs only the public key.
        """

        check_purpose(purpose)
        _require_plaintext(plaintext)

        algorithm = self.factory.for_new(SEAL)
        key = self.keys.current(purpose, algorithm)

        wrapped_key, nonce, ciphertext = algorithm.seal(
            key.material.public_key, plaintext, key.kid.encode("ascii")
        )

        return self._envelope(
            algorithm.name,
            key.kid,
            wrapped_key=wrapped_key,
            nonce=nonce,
            ct=ciphertext,
        )

    def open(self, purpose: str, envelope) -> bytes:
        """Private-key side only. DecryptionError on any failure."""

        try:
            check_purpose(purpose)

            fields = parse_envelope(envelope, {
                "wrapped_key": MAX_TAG_B64_LENGTH,
                "nonce": MAX_TAG_B64_LENGTH,
                "ct": MAX_CIPHERTEXT_B64_LENGTH,
            })
            algorithm = self.factory.for_verify(SEAL, fields["alg"])
            key = self.keys.get(fields["kid"], purpose, algorithm)

            if key.material.private_key is None:
                raise KeyNotFound("No private key for this purpose")

            return algorithm.open(
                key.material.private_key,
                fields["wrapped_key"],
                fields["nonce"],
                fields["ct"],
                fields["kid"].encode("ascii"),
            )

        except VERIFY_FAILURES:
            raise DecryptionError("Decryption failed") from None

    # Password hashing (Argon2id parameter sets)

    def hash_password(self, password: str) -> str:
        return self.factory.for_new(PASSWORD).hash(password)

    def verify_and_upgrade_password(
        self, stored_hash: str, password: str
    ) -> tuple[bool, str | None]:
        """(ok, new_hash_or_None): rehash-on-login helper."""

        return verify_and_upgrade(
            stored_hash, password, self.factory.for_new(PASSWORD)
        )

    @staticmethod
    def _envelope(alg: str, kid: str, **binary_fields: bytes) -> dict:
        envelope = {"alg": alg, "kid": kid, "v": ENVELOPE_VERSION}

        for name, value in binary_fields.items():
            envelope[name] = _b64encode(value)

        return envelope
