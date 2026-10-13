
"""
SR-07: Automated trusted gateway security tests.

Tests certificate fingerprint validation, mission
network restrictions and gateway peer verification.

Uses generated synthetic certificates.
No external certificate files are required.
"""

from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import pytest

from flask import Flask, request
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from gateway_security import evaluate_gateway_request
from mission_access import MissionAccessPolicy


test_app = Flask(__name__)


@pytest.fixture(scope="module")
def client_certificate():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    name = x509.Name([
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            "EVP Synthetic Test Device"
        )
    ])

    now = datetime.now(timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )

    pem = certificate.public_bytes(
        serialization.Encoding.PEM
    ).decode("ascii")

    return {
        "encoded": quote(pem, safe=""),
        "fingerprint": certificate.fingerprint(
            hashes.SHA256()
        ).hex()
    }


@pytest.fixture
def mission_policy(client_certificate):
    return MissionAccessPolicy(
        mission_networks=["198.51.100.0/24"],
        registered_fingerprints=[
            client_certificate["fingerprint"]
        ],
        country_lookup=lambda ip: "GB"
    )


def gateway_headers(
    encoded_certificate="",
    status="NONE",
    source_ip="198.51.100.42"
):
    return {
        "X-EVP-Source-IP": source_ip,
        "X-EVP-Client-Verify": status,
        "X-EVP-Client-Cert": encoded_certificate
    }


def evaluate(headers, policy, peer="127.0.0.1"):
    with test_app.test_request_context(
        "/",
        headers=headers,
        environ_base={"REMOTE_ADDR": peer}
    ):
        return evaluate_gateway_request(
            request,
            policy
        )


def test_registered_device_is_allowed(
    client_certificate,
    mission_policy
):
    decision = evaluate(
        gateway_headers(
            client_certificate["encoded"],
            "SUCCESS"
        ),
        mission_policy
    )

    assert decision.allowed is True
    assert decision.reason == "approved_mission_connection"


def test_missing_client_certificate_is_denied(
    mission_policy
):
    decision = evaluate(
        gateway_headers(),
        mission_policy
    )

    assert decision.allowed is False
    assert decision.reason == "certificate_not_verified"


def test_unregistered_device_is_denied(
    client_certificate
):
    policy = MissionAccessPolicy(
        mission_networks=["198.51.100.0/24"],
        registered_fingerprints=["0" * 64],
        country_lookup=lambda ip: "GB"
    )

    decision = evaluate(
        gateway_headers(
            client_certificate["encoded"],
            "SUCCESS"
        ),
        policy
    )

    assert decision.allowed is False
    assert decision.reason == "unregistered_credential"


def test_non_mission_network_is_denied(
    client_certificate,
    mission_policy
):
    decision = evaluate(
        gateway_headers(
            client_certificate["encoded"],
            "SUCCESS",
            source_ip="192.0.2.50"
        ),
        mission_policy
    )

    assert decision.allowed is False
    assert decision.reason == "non_mission_network"


def test_untrusted_gateway_peer_is_denied(
    client_certificate,
    mission_policy
):
    decision = evaluate(
        gateway_headers(
            client_certificate["encoded"],
            "SUCCESS"
        ),
        mission_policy,
        peer="192.0.2.10"
    )

    assert decision.allowed is False
    assert decision.reason == "untrusted_gateway_peer"


def test_invalid_certificate_data_is_denied(
    mission_policy
):
    decision = evaluate(
        gateway_headers(
            quote("not a certificate", safe=""),
            "SUCCESS"
        ),
        mission_policy
    )

    assert decision.allowed is False
    assert decision.reason == "invalid_certificate_data"


def test_missing_verification_status_is_denied(
    mission_policy
):
    headers = gateway_headers()
    del headers["X-EVP-Client-Verify"]

    decision = evaluate(
        headers,
        mission_policy
    )

    assert decision.allowed is False
    assert decision.reason == "invalid_certificate_status"
