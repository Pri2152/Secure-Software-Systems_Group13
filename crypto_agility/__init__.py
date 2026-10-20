"""
SR-14: Central crypto-agility service (Workstream B).

Security controls:
- Algorithm registry and secure factory: the crypto
  policy, not the calling code, picks each algorithm
- Configuration-driven defaults and allow-lists, so
  algorithms are replaced without code changes

Local academic prototype.
"""

from .errors import (
    AlgorithmNotAllowed,
    AlgorithmUnavailable,
    CryptoError,
    CryptoNotConfigured,
    DecryptionError,
    InvalidEnvelope,
    InvalidPolicy,
    KeyNotFound,
    UnknownAlgorithm,
)
from .policy import DEFAULT_POLICY, CryptoPolicy
from .registry import AlgorithmRegistry, CryptoFactory, default_registry
