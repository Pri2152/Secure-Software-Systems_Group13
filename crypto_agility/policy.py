"""
SR-14: Configurable crypto policy.

Security controls:
- Algorithms are chosen by configuration, not code:
  one default per family for new outputs and an
  allow-list per family for verifying old outputs
- Immutable (frozen) policy objects, so the policy
  cannot be changed at runtime by accident
- Strict validation: unknown families or fields,
  wrong types, a default outside its allow-list, or
  any unknown or unavailable (reserved) algorithm is
  rejected (fail closed)
- Retiring an algorithm = removing it from the
  allow-list; its outputs then stop verifying

Local academic prototype.
"""

import json

from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Mapping

from .algorithms import FAMILIES, HASH, MAC
from .errors import (
    AlgorithmNotAllowed,
    AlgorithmUnavailable,
    InvalidPolicy,
)

if TYPE_CHECKING:
    from .registry import AlgorithmRegistry


MAX_POLICY_FILE_BYTES = 64 * 1024
MAX_ALGORITHM_NAME_LENGTH = 64

POLICY_FIELDS = frozenset({"defaults", "allowed"})


def _check_family(family) -> None:
    if family not in FAMILIES:
        raise InvalidPolicy("Unknown algorithm family in policy")


def _check_name(name) -> None:
    if (
        not isinstance(name, str)
        or not name
        or len(name) > MAX_ALGORITHM_NAME_LENGTH
    ):
        raise InvalidPolicy("Invalid algorithm name in policy")


@dataclass(frozen=True)
class CryptoPolicy:
    """Default and allowed algorithms per family."""

    defaults: Mapping[str, str] = field(default_factory=dict)
    allowed: Mapping[str, frozenset[str]] = field(default_factory=dict)

    def __post_init__(self):
        if not isinstance(self.defaults, Mapping):
            raise InvalidPolicy("Policy defaults must be a mapping")

        if not isinstance(self.allowed, Mapping):
            raise InvalidPolicy("Policy allowed sets must be a mapping")

        allowed = {}

        for family, names in self.allowed.items():
            _check_family(family)

            if isinstance(names, (str, bytes)) or not hasattr(
                names, "__iter__"
            ):
                raise InvalidPolicy("Allowed algorithms must be a list")

            names = frozenset(names)

            for name in names:
                _check_name(name)

            allowed[family] = names

        for family, name in self.defaults.items():
            _check_family(family)
            _check_name(name)

            if name not in allowed.get(family, frozenset()):
                raise AlgorithmNotAllowed(
                    "Policy default is not in its allow-list"
                )

        object.__setattr__(
            self, "defaults", MappingProxyType(dict(self.defaults))
        )
        object.__setattr__(self, "allowed", MappingProxyType(allowed))

    def default_for(self, family: str) -> str:
        name = self.defaults.get(family)

        if name is None:
            raise AlgorithmNotAllowed(
                "Policy has no default for this family"
            )

        return name

    def is_allowed(self, family: str, name: str) -> bool:
        return name in self.allowed.get(family, frozenset())

    def validate(self, registry: "AlgorithmRegistry") -> None:
        """
        Every default and allowed name must be a known,
        available algorithm of the right family.
        """

        for family, names in self.allowed.items():
            for name in names:
                algorithm = registry.get(family, name)

                if not algorithm.available:
                    raise AlgorithmUnavailable(
                        "Policy allows a reserved algorithm"
                    )

    def with_default(self, family: str, name: str) -> "CryptoPolicy":
        """A copy with a new default (added to the allow-list)."""

        allowed = dict(self.allowed)
        allowed[family] = allowed.get(family, frozenset()) | {name}

        return CryptoPolicy(
            defaults={**self.defaults, family: name},
            allowed=allowed,
        )

    def with_allowed(self, family: str, names) -> "CryptoPolicy":
        """A copy with a replaced allow-list for one family."""

        return CryptoPolicy(
            defaults=self.defaults,
            allowed={**self.allowed, family: frozenset(names)},
        )

    def to_dict(self) -> dict:
        return {
            "defaults": dict(self.defaults),
            "allowed": {
                family: sorted(names)
                for family, names in self.allowed.items()
            },
        }

    @classmethod
    def from_dict(cls, data) -> "CryptoPolicy":
        if not isinstance(data, dict) or set(data) != POLICY_FIELDS:
            raise InvalidPolicy(
                "Policy must contain exactly 'defaults' and 'allowed'"
            )

        allowed = data["allowed"]

        if not isinstance(allowed, dict) or any(
            not isinstance(names, list) for names in allowed.values()
        ):
            raise InvalidPolicy("Allowed algorithms must be lists")

        return cls(defaults=data["defaults"], allowed=allowed)

    @classmethod
    def from_json_file(cls, path) -> "CryptoPolicy":
        path = Path(path)

        try:
            if path.stat().st_size > MAX_POLICY_FILE_BYTES:
                raise InvalidPolicy("Policy file is too large")

            data = json.loads(path.read_text(encoding="utf-8"))

        except (OSError, UnicodeDecodeError, ValueError):
            raise InvalidPolicy("Policy file cannot be read") from None

        return cls.from_dict(data)


DEFAULT_POLICY = CryptoPolicy(
    defaults={
        HASH: "sha256",
        MAC: "hmac-sha256",
    },
    allowed={
        HASH: {"sha256", "sha3-256"},
        MAC: {"hmac-sha256", "hmac-sha3-256"},
    },
)
