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
- Key material is never shown in repr or errors

Local academic prototype.
"""

import re
import threading

from dataclasses import dataclass, field

from .algorithms import Algorithm, KeyMaterial
from .errors import CryptoError, KeyNotFound


PURPOSE_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,31}")
KID_PATTERN = re.compile(
    r"(?P<purpose>[a-z][a-z0-9_-]{0,31})"
    r"\.(?P<alg>[a-z0-9][a-z0-9+-]{0,63})"
    r"\.v(?P<version>[1-9][0-9]{0,5})"
)


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
