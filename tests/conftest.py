"""Shared real SR-10 crypto for isolated Workstream C database fixtures."""

import pytest

import ballot_chain
import ballot_protection
from crypto_agility import build_service


@pytest.fixture
def ballot_crypto(monkeypatch):
    service = build_service(dev_keys=True)
    monkeypatch.setattr(ballot_chain, "crypto", service)
    monkeypatch.setattr(ballot_protection, "crypto", service)
    return service
