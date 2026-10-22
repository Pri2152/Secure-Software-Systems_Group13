"""
SR-13: Application-level field encryption for PII columns.

Security controls:
- EncryptedText columns are encrypted on write and
  decrypted on read, so the database only ever holds
  a JSON ciphertext envelope, never plaintext
- No crypto library is imported here: encryption is
  delegated to a provider with Workstream B's SR-14
  crypto_agility interface (encrypt / decrypt by
  purpose), so algorithms and key versions stay agile
- Fails closed: with no provider configured, every
  write and read raises instead of falling back to
  plaintext
- Only text values are accepted, and the provider's
  results are type-checked before use
- Error messages never include the stored value or
  the plaintext

Local academic prototype.
"""

import json
import threading

from sqlalchemy.types import Text, TypeDecorator


class CryptoProviderNotConfigured(RuntimeError):
    """Raised when an encrypted field is used with no provider."""


class FieldCryptoError(ValueError):
    """Raised when a value or envelope cannot be processed safely."""


_provider = None
_provider_lock = threading.Lock()


def set_crypto_provider(provider):
    """
    Install the crypto provider used by every
    EncryptedText column. None removes it.

    A provider must offer
    encrypt(purpose, plaintext_bytes) -> dict envelope and
    decrypt(purpose, envelope_dict) -> bytes.
    """

    global _provider

    if provider is not None:
        for method in ("encrypt", "decrypt"):
            if not callable(getattr(provider, method, None)):
                raise TypeError(
                    f"Crypto provider must define {method}()"
                )

    with _provider_lock:
        _provider = provider


def get_crypto_provider():
    """
    Return the installed provider, or raise
    CryptoProviderNotConfigured (fail closed).
    """

    with _provider_lock:
        provider = _provider

    if provider is None:
        raise CryptoProviderNotConfigured(
            "No crypto provider is configured for encrypted fields"
        )

    return provider


class EncryptedText(TypeDecorator):
    """
    Text column stored as a JSON encryption envelope.

    The purpose (default "pii") selects the provider's
    key family, so different kinds of data never share
    a key.
    """

    impl = Text
    cache_ok = True

    def __init__(self, purpose="pii", *args, **kwargs):
        if not isinstance(purpose, str) or not purpose:
            raise ValueError("purpose must be a non-empty string")

        self.purpose = purpose

        super().__init__(*args, **kwargs)

    def process_bind_param(self, value, dialect):
        if value is None:
            return None

        if not isinstance(value, str):
            raise FieldCryptoError(
                "EncryptedText only stores text values"
            )

        envelope = get_crypto_provider().encrypt(
            self.purpose, value.encode("utf-8")
        )

        if not isinstance(envelope, dict) or not envelope:
            raise FieldCryptoError(
                "Crypto provider returned an invalid envelope"
            )

        try:
            return json.dumps(
                envelope, sort_keys=True, separators=(",", ":")
            )
        except (TypeError, ValueError):
            raise FieldCryptoError(
                "Crypto provider returned an invalid envelope"
            ) from None

    def process_result_value(self, value, dialect):
        if value is None:
            return None

        provider = get_crypto_provider()

        try:
            envelope = json.loads(value)
        except (TypeError, ValueError):
            raise FieldCryptoError(
                "Stored value is not an encryption envelope"
            ) from None

        if not isinstance(envelope, dict):
            raise FieldCryptoError(
                "Stored value is not an encryption envelope"
            )

        plaintext = provider.decrypt(self.purpose, envelope)

        if not isinstance(plaintext, bytes):
            raise FieldCryptoError(
                "Crypto provider returned invalid plaintext"
            )

        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError:
            raise FieldCryptoError(
                "Decrypted value is not valid text"
            ) from None
