"""
Shared test fixtures.

pii_provider (SR-13): EnrolmentRecord.contact_email and
AddressRecord.address_text are EncryptedText columns, which
fail closed without a crypto provider. Fixtures that write
those records request this fixture.

ballot_crypto (SR-10, Workstream C): real SR-10 crypto for
isolated Workstream C database fixtures, patched into
ballot_chain and ballot_protection.

Both use crypto_agility with in-memory development keys (the
same as EVP_CRYPTO_DEV_KEYS=1), never real keys.
"""

import pytest

import ballot_chain
import ballot_protection
import crypto_agility
from crypto_agility import build_service
from platform_security.field_crypto import set_crypto_provider


@pytest.fixture
def pii_provider():
    service = crypto_agility.build_service(dev_keys=True)
    set_crypto_provider(service)

    yield service

    set_crypto_provider(None)


@pytest.fixture
def ballot_crypto(monkeypatch):
    service = build_service(dev_keys=True)
    monkeypatch.setattr(ballot_chain, "crypto", service)
    monkeypatch.setattr(ballot_protection, "crypto", service)
    return service
