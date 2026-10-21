
"""
Shared test fixtures.

pii_provider (SR-13): EnrolmentRecord.contact_email and
AddressRecord.address_text are EncryptedText columns, which
fail closed without a crypto provider. Fixtures that write
those records request this fixture. It uses crypto_agility
with in-memory development keys (the same as
EVP_CRYPTO_DEV_KEYS=1), never real keys.
"""

import pytest

import crypto_agility
from platform_security.field_crypto import set_crypto_provider


@pytest.fixture
def pii_provider():
    service = crypto_agility.build_service(dev_keys=True)
    set_crypto_provider(service)

    yield service

    set_crypto_provider(None)
