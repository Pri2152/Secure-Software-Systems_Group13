"""
Shared test fixtures.

default_pii_provider (SR-13, autouse): EnrolmentRecord.contact_email
and AddressRecord.address_text are EncryptedText columns, which
fail closed without a crypto provider. Every test gets crypto_agility
with in-memory development keys installed before it runs and removed
afterwards, so fixtures in any workstream can write those records.
Tests that must run with no provider (the fail-closed tests) opt out
with @pytest.mark.no_pii_provider. Only tests change: production
start-up (gateway_runtime) still refuses to run without the PII key.

pii_provider (SR-13): installs a fresh development-key service and
returns it, for tests that need the provider object itself.

ballot_crypto (SR-10, Workstream C): real SR-10 crypto for
isolated Workstream C database fixtures, patched into
ballot_chain and ballot_protection.

All use crypto_agility with in-memory development keys (the
same as EVP_CRYPTO_DEV_KEYS=1), never real keys.
"""

import pytest

import ballot_chain
import ballot_protection
import crypto_agility
from crypto_agility import build_service
from platform_security.field_crypto import set_crypto_provider


NO_PII_PROVIDER = "no_pii_provider"


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        f"{NO_PII_PROVIDER}: run with no PII crypto provider installed "
        "(SR-13 fail-closed tests)",
    )


@pytest.fixture(autouse=True)
def default_pii_provider(request):
    if request.node.get_closest_marker(NO_PII_PROVIDER):
        service = None
    else:
        service = crypto_agility.build_service(dev_keys=True)

    set_crypto_provider(service)

    yield service

    set_crypto_provider(None)


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
