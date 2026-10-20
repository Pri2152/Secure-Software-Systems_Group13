"""
SR-14: Central crypto-agility service (Workstream B).

Usage (handbook section 6.1):

    from crypto_agility import crypto

    value = crypto.hash(data)               # "sha256:<hex>"
    envelope = crypto.mac("audit", data)    # {"alg", "kid", "v", "sig"}

Security controls:
- Algorithm registry and secure factory: the crypto
  policy, not the calling code, picks each algorithm
- Configuration-driven defaults and allow-lists, so
  algorithms are replaced without code changes
- Self-describing, versioned outputs that still
  verify after the default algorithm changes
- Fails closed: with no key configuration in the
  environment, the first crypto call raises
  CryptoNotConfigured instead of using weak defaults

Configuration (environment):
- EVP_CRYPTO_DEV_KEYS=1  generate throwaway keys in
  memory (development and tests only)
- EVP_CRYPTO_POLICY      path to a policy JSON file

Local academic prototype.
"""

import logging
import os
import threading

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
from .keys import KeyStore
from .policy import DEFAULT_POLICY, CryptoPolicy
from .registry import AlgorithmRegistry, CryptoFactory, default_registry
from .service import CryptoService


ENV_DEV_KEYS = "EVP_CRYPTO_DEV_KEYS"
ENV_POLICY = "EVP_CRYPTO_POLICY"

logger = logging.getLogger("evp.crypto")

_service: CryptoService | None = None
_service_lock = threading.Lock()


def build_service(
    *,
    dev_keys: bool = False,
    policy: CryptoPolicy | None = None,
    policy_path: str | None = None,
    registry: AlgorithmRegistry | None = None,
) -> CryptoService:
    """
    Build a service from explicit settings. Without a
    key source this raises CryptoNotConfigured.
    """

    registry = registry or default_registry()

    if policy is None:
        policy = (
            CryptoPolicy.from_json_file(policy_path)
            if policy_path
            else DEFAULT_POLICY
        )

    if dev_keys:
        logger.warning("crypto_dev_keys_in_use")
        keystore = KeyStore.ephemeral()
    else:
        raise CryptoNotConfigured("No cryptographic keys are configured")

    return CryptoService(registry, policy, keystore)


def build_service_from_env(environ=None) -> CryptoService:
    environ = os.environ if environ is None else environ

    return build_service(
        dev_keys=environ.get(ENV_DEV_KEYS) == "1",
        policy_path=environ.get(ENV_POLICY) or None,
    )


def configure(service: CryptoService | None) -> None:
    """Install the service behind `crypto`; None resets it."""

    global _service

    if service is not None and not isinstance(service, CryptoService):
        raise TypeError("configure() needs a CryptoService")

    with _service_lock:
        _service = service


def get_service() -> CryptoService:
    """The configured service, built from the environment on first use."""

    global _service

    with _service_lock:
        if _service is None:
            _service = build_service_from_env()

        return _service


class _ConfiguredCrypto:
    """
    Module-level facade. Configuration is resolved at
    the first call, so importing never needs keys.
    """

    def hash(self, data: bytes) -> str:
        return get_service().hash(data)

    def verify_hash(self, data: bytes, value: str) -> bool:
        return get_service().verify_hash(data, value)

    def mac(self, purpose: str, data: bytes) -> dict:
        return get_service().mac(purpose, data)

    def verify_mac(self, purpose: str, data: bytes, envelope) -> bool:
        return get_service().verify_mac(purpose, data, envelope)


crypto = _ConfiguredCrypto()
