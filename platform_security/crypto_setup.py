"""
SR-13: Start-up wiring of field encryption to the SR-14 service.

Security controls:
- Registers Workstream B's crypto_agility service as the
  EncryptedText provider for the voter-access compartment
- Fails closed at start-up: if the keys are not configured
  or there is no usable PII key, the compartment refuses to
  start instead of running without encryption
- Proves the PII key works with an encrypt/decrypt round
  trip before any request is served
- Called from the compartment's start-up code, never on
  import, so tests and CI need no keys
- Error messages name the setting, never key material

Configuration is crypto_agility's own (EVP_KEY_DIR, or
EVP_CRYPTO_DEV_KEYS=1 for development only).

Local academic prototype.
"""

import crypto_agility

from .field_crypto import CryptoProviderNotConfigured, set_crypto_provider


PII_PURPOSE = "pii"
STARTUP_CHECK = b"evp-pii-startup-check"


def install_pii_provider(environ=None):
    """
    Build crypto_agility from the environment, check the
    PII key, and register it for EncryptedText columns.
    Raises CryptoProviderNotConfigured (fail closed).
    """

    try:
        service = crypto_agility.build_service_from_env(environ)
        envelope = service.encrypt(PII_PURPOSE, STARTUP_CHECK)

        if service.decrypt(PII_PURPOSE, envelope) != STARTUP_CHECK:
            raise crypto_agility.CryptoError("PII key check failed")

    except crypto_agility.CryptoError:
        raise CryptoProviderNotConfigured(
            "The PII encryption key is not available: set EVP_KEY_DIR "
            "to a key folder whose manifest has a current 'pii' key"
        ) from None

    crypto_agility.configure(service)
    set_crypto_provider(crypto_agility.crypto)

    return service
