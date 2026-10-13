
"""
SR-07: Diplomatic-mission access policy tests.

All addresses and certificate fingerprints
are synthetic testing values.
"""

import logging

import pytest

from mission_access import MissionAccessPolicy


REGISTERED_CERT = "a" * 64
UNREGISTERED_CERT = "b" * 64

AUSTRALIAN_SOURCE = "203.0.113.10"
MISSION_SOURCE = "198.51.100.20"
OTHER_OVERSEAS_SOURCE = "192.0.2.20"


@pytest.fixture
def policy():

    countries = {
        AUSTRALIAN_SOURCE: "AU",
        MISSION_SOURCE: "GB",
        OTHER_OVERSEAS_SOURCE: "GB",
    }

    return MissionAccessPolicy(
        mission_networks=[
            "198.51.100.0/24"
        ],
        registered_fingerprints=[
            REGISTERED_CERT
        ],
        country_lookup=lambda ip: countries.get(ip)
    )


# Test 1: Domestic connection is permitted
def test_domestic_connection_allowed(policy):
    result = policy.evaluate(
        AUSTRALIAN_SOURCE
    )

    assert result.allowed is True
    assert result.reason == "domestic_connection"


# Test 2: Registered mission connection succeeds
def test_registered_mission_allowed(policy):
    result = policy.evaluate(
        MISSION_SOURCE,
        cert_verified=True,
        cert_fingerprint=REGISTERED_CERT
    )

    assert result.allowed is True


# Test 3: Non-mission overseas network denied
def test_non_mission_network_denied(policy):
    result = policy.evaluate(
        OTHER_OVERSEAS_SOURCE,
        cert_verified=True,
        cert_fingerprint=REGISTERED_CERT
    )

    assert result.allowed is False
    assert result.reason == "non_mission_network"


# Test 4: Missing certificate denied
def test_missing_certificate_denied(policy):
    result = policy.evaluate(
        MISSION_SOURCE
    )

    assert result.allowed is False
    assert result.reason == "certificate_not_verified"


# Test 5: Unverified certificate denied
def test_unverified_certificate_denied(policy):
    result = policy.evaluate(
        MISSION_SOURCE,
        cert_verified=False,
        cert_fingerprint=REGISTERED_CERT
    )

    assert result.allowed is False


# Test 6: Unregistered certificate denied
def test_unregistered_certificate_denied(policy):
    result = policy.evaluate(
        MISSION_SOURCE,
        cert_verified=True,
        cert_fingerprint=UNREGISTERED_CERT
    )

    assert result.allowed is False
    assert result.reason == "unregistered_credential"


# Test 7: Malformed source addresses denied
@pytest.mark.parametrize(
    "invalid_ip",
    [
        None,
        "",
        "not-an-ip-address",
    ]
)
def test_invalid_source_denied(
    policy, invalid_ip
):
    result = policy.evaluate(invalid_ip)

    assert result.allowed is False
    assert result.reason == "invalid_source"


# Test 8: Unknown location fails closed
def test_unknown_location_denied(policy):
    result = policy.evaluate(
        "192.0.2.99",
        cert_verified=True,
        cert_fingerprint=REGISTERED_CERT
    )

    assert result.allowed is False
    assert result.reason == "location_unavailable"


# Test 9: Country lookup errors fail closed
def test_lookup_failure_denied():
    def broken_lookup(ip):
        raise RuntimeError("Lookup unavailable")

    policy = MissionAccessPolicy(
        mission_networks=["198.51.100.0/24"],
        registered_fingerprints=[REGISTERED_CERT],
        country_lookup=broken_lookup
    )

    result = policy.evaluate(
        MISSION_SOURCE
    )

    assert result.allowed is False
    assert result.reason == "location_unavailable"


# Test 10: Denial is logged without credential
def test_denial_logged_safely(policy, caplog):
    with caplog.at_level(
        logging.WARNING,
        logger="evp.mission_access"
    ):
        result = policy.evaluate(
            MISSION_SOURCE,
            cert_verified=True,
            cert_fingerprint=UNREGISTERED_CERT
        )

    assert result.allowed is False
    assert "mission_access_denied" in caplog.text
    assert "unregistered_credential" in caplog.text
    assert UNREGISTERED_CERT not in caplog.text


# Test 11: Invalid certificate format denied
def test_malformed_certificate_denied(policy):
    result = policy.evaluate(
        MISSION_SOURCE,
        cert_verified=True,
        cert_fingerprint="invalid-certificate"
    )

    assert result.allowed is False
