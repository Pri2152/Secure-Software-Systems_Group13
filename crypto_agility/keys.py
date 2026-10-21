"""
SR-14: Versioned key store.

Security controls:
- Every key has a key ID "<purpose>.<alg>.v<n>" that
  travels in each envelope, so the right key version
  is found after rotation
- Each key ID is bound to (purpose, family, algorithm);
  a lookup that names a different purpose or
  algorithm is refused (key-confusion protection)
- Several versions per purpose and algorithm; only
  the current one produces new outputs, older ones
  still verify and decrypt
- Ephemeral mode generates keys with os.urandom /
  `cryptography` on demand, for development and tests
  only; deployments load keys from secrets
- Directory mode loads keys from a secrets directory
  (Docker secrets) described by manifest.json; the
  manifest is validated strictly, file names cannot
  leave the directory, sizes are capped, and any
  problem stops start-up (CryptoNotConfigured)
- Public-only entries let verify-only compartments
  check signatures without holding private keys
- Key material is never shown in repr or errors

Manifest format (manifest.json in the key directory):

    {"keys": [
      {"kid": "audit.hmac-sha256.v1", "purpose": "audit",
       "family": "mac", "alg": "hmac-sha256",
       "file": "audit_hmac_v1", "current": true},
      {"kid": "pii.aes-256-gcm.v1", "purpose": "pii",
       "family": "aead", "alg": "aes-256-gcm",
       "file": "pii_key_v1", "encoding": "hex",
       "current": true},
      {"kid": "results.ed25519.v1", "purpose": "results",
       "family": "sign", "alg": "ed25519",
       "file": "results_sign_v1.pem", "current": true}
    ]}

Symmetric key files hold base64 (default) or hex
("encoding": "hex"); asymmetric key files hold an
unencrypted PEM private key or a PEM public key.

Local academic prototype.
"""

import base64
import binascii
import json
import re
import threading

from dataclasses import dataclass, field
from pathlib import Path

from .algorithms import (
    AEAD,
    MAC,
    SEAL,
    SIGN,
    Algorithm,
    KeyMaterial,
    load_pem_key_material,
)
from .errors import CryptoError, CryptoNotConfigured, KeyNotFound


PURPOSE_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,31}")
KID_PATTERN = re.compile(
    r"(?P<purpose>[a-z][a-z0-9_-]{0,31})"
    r"\.(?P<alg>[a-z0-9][a-z0-9+-]{0,63})"
    r"\.v(?P<version>[1-9][0-9]{0,5})"
)


MANIFEST_NAME = "manifest.json"
MAX_MANIFEST_BYTES = 256 * 1024
MAX_KEY_FILE_BYTES = 64 * 1024

MANIFEST_REQUIRED_FIELDS = frozenset(
    {"kid", "purpose", "family", "alg", "file", "current"}
)
MANIFEST_OPTIONAL_FIELDS = frozenset({"encoding"})

SYMMETRIC_FAMILIES = frozenset({MAC, AEAD})
ASYMMETRIC_FAMILIES = frozenset({SIGN, SEAL})

SECRET_ENCODINGS = frozenset({"base64", "hex"})
PEM_ENCODING = "pem"

KEY_FILE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def check_purpose(purpose) -> str:
    if not isinstance(purpose, str) or not PURPOSE_PATTERN.fullmatch(
        purpose
    ):
        raise ValueError("Invalid key purpose")

    return purpose


def make_kid(purpose: str, alg: str, version: int) -> str:
    kid = f"{check_purpose(purpose)}.{alg}.v{version}"

    if not KID_PATTERN.fullmatch(kid):
        raise ValueError("Invalid key ID")

    return kid


def parse_kid(kid) -> tuple[str, str, int]:
    """Split a key ID into (purpose, alg, version)."""

    match = (
        KID_PATTERN.fullmatch(kid) if isinstance(kid, str) else None
    )

    if match is None:
        raise KeyNotFound("Key ID is malformed")

    return (
        match["purpose"],
        match["alg"],
        int(match["version"]),
    )


@dataclass(frozen=True)
class KeyEntry:
    """One key version and the use it is bound to."""

    kid: str
    purpose: str
    family: str
    alg: str
    version: int
    material: KeyMaterial = field(repr=False)


class KeyStore:
    """Holds every key version known to this compartment."""

    def __init__(self, *, generate_missing: bool = False):
        self._entries: dict[str, KeyEntry] = {}
        self._current: dict[tuple[str, str, str], str] = {}
        self._generate_missing = generate_missing
        self._lock = threading.RLock()

    @classmethod
    def ephemeral(cls) -> "KeyStore":
        """In-memory keys generated on first use (dev/tests only)."""

        return cls(generate_missing=True)

    @classmethod
    def from_directory(cls, path, registry) -> "KeyStore":
        """
        Load every key listed in <path>/manifest.json.
        Fails closed with CryptoNotConfigured.
        """

        directory = Path(path)

        if not directory.is_dir():
            raise CryptoNotConfigured("Key directory is not available")

        directory = directory.resolve()
        manifest = _read_manifest(directory)
        store = cls()
        current_slots = set()

        for index, item in enumerate(manifest):
            try:
                entry = _load_manifest_entry(
                    store, directory, registry, item
                )
            except (CryptoError, ValueError, TypeError, OSError):
                raise CryptoNotConfigured(
                    f"Key manifest entry {index} is invalid"
                ) from None

            if item["current"]:
                if cls._slot(entry) in current_slots:
                    raise CryptoNotConfigured(
                        f"Key manifest entry {index} is a second "
                        "current key"
                    )

                current_slots.add(cls._slot(entry))

        return store

    def add(
        self,
        purpose: str,
        algorithm: Algorithm,
        material: KeyMaterial,
        version: int,
        *,
        current: bool = False,
    ) -> KeyEntry:
        """Register one key version for a purpose and algorithm."""

        algorithm.check_key(material)

        kid = make_kid(purpose, algorithm.name, version)
        entry = KeyEntry(
            kid=kid,
            purpose=purpose,
            family=algorithm.family,
            alg=algorithm.name,
            version=version,
            material=material,
        )

        with self._lock:
            if kid in self._entries:
                raise ValueError("Key ID is already registered")

            self._entries[kid] = entry

            if current:
                self._current[self._slot(entry)] = kid

        return entry

    def current(self, purpose: str, algorithm: Algorithm) -> KeyEntry:
        """The key that produces new outputs."""

        check_purpose(purpose)

        with self._lock:
            kid = self._current.get(
                (purpose, algorithm.family, algorithm.name)
            )

            if kid is not None:
                return self._entries[kid]

            if self._generate_missing:
                return self.rotate(purpose, algorithm)

        raise KeyNotFound("No current key for this purpose")

    def get(self, kid, purpose: str, algorithm: Algorithm) -> KeyEntry:
        """
        Look up a key named in an envelope. The key must
        be bound to this purpose, family and algorithm.
        """

        parse_kid(kid)

        with self._lock:
            entry = self._entries.get(kid)

        if (
            entry is None
            or entry.purpose != purpose
            or entry.family != algorithm.family
            or entry.alg != algorithm.name
        ):
            raise KeyNotFound("Key is not valid for this use")

        return entry

    def rotate(
        self,
        purpose: str,
        algorithm: Algorithm,
        material: KeyMaterial | None = None,
    ) -> KeyEntry:
        """
        Add the next key version and make it current.
        Older versions stay available for verification.
        """

        if material is None:
            if not self._generate_missing:
                raise CryptoError(
                    "Key generation is disabled; supply key material"
                )

            material = algorithm.generate_key()

        with self._lock:
            version = 1 + max(
                (
                    entry.version
                    for entry in self._entries.values()
                    if entry.purpose == purpose
                    and entry.alg == algorithm.name
                ),
                default=0,
            )

            return self.add(
                purpose, algorithm, material, version, current=True
            )

    def kids(self, purpose: str, algorithm: Algorithm) -> list[str]:
        """Every key ID for a purpose and algorithm, oldest first."""

        with self._lock:
            entries = [
                entry
                for entry in self._entries.values()
                if entry.purpose == purpose
                and entry.alg == algorithm.name
            ]

        return [
            entry.kid
            for entry in sorted(entries, key=lambda e: e.version)
        ]

    @staticmethod
    def _slot(entry: KeyEntry) -> tuple[str, str, str]:
        return (entry.purpose, entry.family, entry.alg)


def _read_manifest(directory: Path) -> list:
    try:
        manifest_path = directory / MANIFEST_NAME

        if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            raise CryptoNotConfigured("Key manifest is too large")

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    except (OSError, UnicodeDecodeError, ValueError):
        raise CryptoNotConfigured("Key manifest cannot be read") from None

    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"keys"}
        or not isinstance(manifest["keys"], list)
    ):
        raise CryptoNotConfigured("Key manifest is malformed")

    return manifest["keys"]


def _load_manifest_entry(
    store: KeyStore, directory: Path, registry, item
) -> KeyEntry:
    if not isinstance(item, dict):
        raise ValueError("Manifest entry must be an object")

    fields = set(item)

    if not MANIFEST_REQUIRED_FIELDS <= fields or not fields <= (
        MANIFEST_REQUIRED_FIELDS | MANIFEST_OPTIONAL_FIELDS
    ):
        raise ValueError("Manifest entry fields are invalid")

    if not isinstance(item["current"], bool):
        raise ValueError("Manifest 'current' must be true or false")

    purpose, alg, version = parse_kid(item["kid"])

    if item["purpose"] != purpose or item["alg"] != alg:
        raise ValueError("Key ID does not match purpose and algorithm")

    algorithm = registry.get(item["family"], alg)

    if not algorithm.available:
        raise ValueError("Reserved algorithms cannot hold keys")

    raw = _read_key_file(directory, item["file"])
    material = _decode_key_material(
        algorithm.family, raw, item.get("encoding")
    )

    return store.add(
        purpose, algorithm, material, version, current=item["current"]
    )


def _read_key_file(directory: Path, name) -> bytes:
    """Read a key file that must sit directly inside the directory."""

    if not isinstance(name, str) or not KEY_FILE_PATTERN.fullmatch(name):
        raise ValueError("Invalid key file name")

    path = (directory / name).resolve()

    if path.parent != directory or not path.is_file():
        raise ValueError("Key file is not inside the key directory")

    if path.stat().st_size > MAX_KEY_FILE_BYTES:
        raise ValueError("Key file is too large")

    return path.read_bytes()


def _decode_key_material(family: str, raw: bytes, encoding) -> KeyMaterial:
    if family in SYMMETRIC_FAMILIES:
        encoding = encoding or "base64"

        if encoding not in SECRET_ENCODINGS:
            raise ValueError("Unsupported key encoding")

        try:
            text = raw.decode("ascii").strip()

            secret = (
                bytes.fromhex(text)
                if encoding == "hex"
                else base64.b64decode(text, validate=True)
            )

        except (UnicodeDecodeError, binascii.Error):
            raise ValueError("Key file is not valid") from None

        return KeyMaterial(secret=secret)

    if family in ASYMMETRIC_FAMILIES:
        if encoding not in (None, PEM_ENCODING):
            raise ValueError("Asymmetric keys must be PEM")

        return load_pem_key_material(raw)

    raise ValueError("This algorithm family has no keys")
