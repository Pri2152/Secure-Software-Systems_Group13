"""
SR-14: Algorithm registry and secure factory.

Security controls:
- Registry of named algorithms per family; unknown
  names are refused (fail closed)
- Secure factory pattern: callers ask for "the
  signer" or "the hasher" and the factory chooses the
  implementation from the crypto policy, so the
  security-relevant choice is made in one place
- New outputs always use the policy default
- Verification uses the algorithm named in the
  output only while the policy still allows it;
  reserved (unavailable) algorithms are never used

Local academic prototype.
"""

from . import algorithms
from .algorithms import Algorithm
from .errors import (
    AlgorithmNotAllowed,
    AlgorithmUnavailable,
    UnknownAlgorithm,
)
from .policy import CryptoPolicy


class AlgorithmRegistry:
    """Named algorithms; each name is unique across families."""

    def __init__(self, entries=()):
        self._algorithms: dict[str, Algorithm] = {}

        for algorithm in entries:
            self.register(algorithm)

    def register(self, algorithm: Algorithm) -> None:
        if not isinstance(algorithm, Algorithm):
            raise TypeError("Only Algorithm instances can be registered")

        if algorithm.name in self._algorithms:
            raise ValueError("Algorithm name is already registered")

        self._algorithms[algorithm.name] = algorithm

    def get(self, family: str, name: str) -> Algorithm:
        """
        Return the algorithm only if it exists in the
        given family. Anything else is UnknownAlgorithm.
        """

        algorithm = (
            self._algorithms.get(name)
            if isinstance(name, str)
            else None
        )

        if algorithm is None or algorithm.family != family:
            raise UnknownAlgorithm("Algorithm is not registered")

        return algorithm

    def names(self, family: str) -> frozenset[str]:
        return frozenset(
            name
            for name, algorithm in self._algorithms.items()
            if algorithm.family == family
        )


def default_registry() -> AlgorithmRegistry:
    """The platform's registered algorithms."""

    return AlgorithmRegistry([
        algorithms.SHA256,
        algorithms.SHA3_256,
        algorithms.HMAC_SHA256,
        algorithms.HMAC_SHA3_256,
        algorithms.ED25519,
        algorithms.ECDSA_P256_SHA256,
        algorithms.AES_256_GCM,
        algorithms.CHACHA20_POLY1305,
        algorithms.RSA_OAEP_AES_256_GCM,
    ])


class CryptoFactory:
    """
    Secure factory: hands out algorithm
    implementations according to the policy.
    """

    def __init__(self, registry: AlgorithmRegistry, policy: CryptoPolicy):
        policy.validate(registry)

        self.registry = registry
        self.policy = policy

    def for_new(self, family: str) -> Algorithm:
        """The configured default for producing new outputs."""

        return self._usable(family, self.policy.default_for(family))

    def for_verify(self, family: str, name: str) -> Algorithm:
        """
        The algorithm named in an existing output,
        refused unless the policy still allows it.
        """

        algorithm = self._usable(family, name)

        if not self.policy.is_allowed(family, algorithm.name):
            raise AlgorithmNotAllowed("Algorithm is not allowed by policy")

        return algorithm

    def _usable(self, family: str, name: str) -> Algorithm:
        algorithm = self.registry.get(family, name)

        if not algorithm.available:
            raise AlgorithmUnavailable(
                "Algorithm is reserved and not available"
            )

        return algorithm
