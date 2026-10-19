
"""
SR-07: Local Nginx-to-Flask integration runtime.

Academic demonstration using synthetic voter data.

Provides:
- Simulated overseas mission-network classification
- Registered client certificate enforcement
- SR-01 password and TOTP authentication
- SR-05 synthetic voter records
- SR-16 authenticated session integration

Not suitable for production election infrastructure.
"""

import ipaddress
import json
import os

from pathlib import Path

from app import app
from auth import hash_password
from gateway_security import parse_network_list
from login_flow import LoginCoordinator, VoterRecord
from mission_access import MissionAccessPolicy
from records import db, EnrolmentRecord, AddressRecord


REGISTRY_PATH = Path(
    "/run/evp/registered_fingerprints.txt"
)

DEMO_VOTER_PATH = Path(
    "/run/evp/demo-voter.json"
)

# Read once at start-up; invalid values stop the app.
SIMULATED_MISSION_NETWORKS = parse_network_list(
    os.environ.get("EVP_SIMULATED_MISSION_NETWORKS", "127.0.0.1/32"),
    "EVP_SIMULATED_MISSION_NETWORKS"
)


def lab_country_lookup(source_ip):
    """
    Simulate an overseas mission connection.

    Loopback represents a mock overseas mission
    only for this isolated local demonstration.
    EVP_SIMULATED_MISSION_NETWORKS can replace it.
    """

    address = ipaddress.ip_address(source_ip)

    if any(
        address in network
        for network in SIMULATED_MISSION_NETWORKS
        if address.version == network.version
    ):
        return "GB"

    raise LookupError(
        "No simulated country mapping for source"
    )


def load_registered_fingerprints():
    """
    Load explicitly registered device fingerprints.
    """

    fingerprints = [
        line.strip()
        for line in REGISTRY_PATH.read_text(
            encoding="ascii"
        ).splitlines()
        if line.strip()
    ]

    if not fingerprints:
        raise RuntimeError(
            "No registered mission devices configured"
        )

    return fingerprints


def load_demo_voter():
    """
    Load synthetic credentials from an external
    read-only file, never from the Git repository.
    """

    try:
        data = json.loads(
            DEMO_VOTER_PATH.read_text(
                encoding="utf-8"
            )
        )
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            "Synthetic demo voter configuration unavailable"
        ) from exc

    if not isinstance(data, dict):
        raise RuntimeError(
            "Invalid synthetic voter configuration"
        )

    account_id = data.get("account_id")
    password = data.get("password")
    totp_secret = data.get("totp_secret")

    if (
        not isinstance(account_id, str)
        or not account_id.strip()
        or not isinstance(password, str)
        or not password
        or not isinstance(totp_secret, str)
        or not totp_secret
    ):
        raise RuntimeError(
            "Incomplete synthetic voter configuration"
        )

    account_id = account_id.strip().casefold()

    voter = VoterRecord(
        voter_id=account_id,
        password_hash=hash_password(password),
        totp_secret=totp_secret,
    )

    return account_id, voter


def configure_local_gateway():

    if os.environ.get("EVP_LOCAL_LAB") != "1":
        raise RuntimeError(
            "Local lab mode must be explicitly enabled"
        )

    policy = MissionAccessPolicy(
        mission_networks=[
            str(network)
            for network in SIMULATED_MISSION_NETWORKS
        ],
        registered_fingerprints=(
            load_registered_fingerprints()
        ),
        country_lookup=lab_country_lookup,
    )

    account_id, voter = load_demo_voter()

    coordinator = LoginCoordinator(
        lookup_voter=lambda account: (
            voter if account == account_id else None
        )
    )

    app.config.update(
        SR07_GATEWAY_ENFORCED=True,
        MISSION_ACCESS_POLICY=policy,
        LOGIN_COORDINATOR=coordinator,
    )

    # Synthetic in-memory data for SR-05 demonstrations.
    with app.app_context():
        db.create_all()

        db.session.add_all([
            EnrolmentRecord(
                id=701,
                owner_voter_id=account_id,
                enrolment_status="enrolled",
                contact_email="demo-voter@example.test",
            ),
            AddressRecord(
                id=801,
                owner_voter_id=account_id,
                address_text="Synthetic Test Address",
            ),
        ])

        db.session.commit()

    return app


application = configure_local_gateway()
