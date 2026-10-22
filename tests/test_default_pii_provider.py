"""
SR-13 tests for the shared default_pii_provider fixture (conftest.py).

Every test gets a development-key provider unless it is marked
no_pii_provider, and the marker really leaves encrypted columns
failing closed. Production start-up is unchanged: gateway_runtime
still refuses to run without the PII key.
"""

import pytest

from platform_security.field_crypto import (
    CryptoProviderNotConfigured,
    EncryptedText,
    get_crypto_provider,
)
from test_platform_pii_encryption import run_runtime


def test_provider_is_installed_by_default(default_pii_provider):
    assert get_crypto_provider() is default_pii_provider

    column = EncryptedText("pii")
    stored = column.process_bind_param("someone@example.test", None)

    assert "someone" not in stored
    assert column.process_result_value(stored, None) == "someone@example.test"


@pytest.mark.no_pii_provider
def test_marker_removes_the_provider(default_pii_provider):
    assert default_pii_provider is None

    with pytest.raises(CryptoProviderNotConfigured):
        get_crypto_provider()


@pytest.mark.no_pii_provider
def test_marked_test_fails_closed_on_write():
    with pytest.raises(CryptoProviderNotConfigured):
        EncryptedText("pii").process_bind_param("someone@example.test", None)


def test_pii_provider_fixture_still_overrides(pii_provider):
    assert get_crypto_provider() is pii_provider


@pytest.mark.no_pii_provider
def test_pii_provider_fixture_works_in_marked_test(pii_provider):
    assert get_crypto_provider() is pii_provider


def test_marker_is_registered(pytestconfig):
    markers = pytestconfig.getini("markers")

    assert any(line.startswith("no_pii_provider:") for line in markers)


def test_production_start_up_still_needs_the_pii_key():
    result = run_runtime()

    assert result.returncode != 0
    assert "PII encryption key is not available" in result.stderr
