
"""
SR-01 and SR-07 integration tests.

Verify that Flask uses the original source IP
validated by the trusted gateway, rather than
the Nginx loopback address.

Uses simulated IP and country information.
"""

from types import SimpleNamespace

from app import app
from mission_access import MissionAccessPolicy


class RecordingCoordinator:

    def __init__(self):
        self.source_id = None

    def authenticate(
        self,
        *,
        account_id,
        password,
        totp_code,
        source_id,
        on_authenticated
    ):
        self.source_id = source_id

        return SimpleNamespace(
            success=False,
            status="invalid_credentials"
        )


def test_login_uses_original_gateway_source_ip(
    monkeypatch
):
    coordinator = RecordingCoordinator()

    # Simulated domestic connection.
    policy = MissionAccessPolicy(
        mission_networks=["198.51.100.0/24"],
        registered_fingerprints=[],
        country_lookup=lambda ip: "AU"
    )

    monkeypatch.setitem(
        app.config,
        "SR07_GATEWAY_ENFORCED",
        True
    )

    monkeypatch.setitem(
        app.config,
        "MISSION_ACCESS_POLICY",
        policy
    )

    monkeypatch.setitem(
        app.config,
        "LOGIN_COORDINATOR",
        coordinator
    )

    monkeypatch.setitem(
        app.config,
        "WTF_CSRF_ENABLED",
        False
    )

    client = app.test_client()

    response = client.post(
        "/login",
        json={
            "account_id": "test-voter",
            "password": "test-password",
            "totp_code": "123456"
        },
        headers={
            "X-EVP-Source-IP": "198.51.100.42",
            "X-EVP-Client-Verify": "NONE"
        },
        environ_overrides={
            "REMOTE_ADDR": "127.0.0.1"
        }
    )

    assert response.status_code == 401

    assert coordinator.source_id == (
        "198.51.100.42"
    )


def test_direct_untrusted_peer_is_denied(
    monkeypatch
):
    coordinator = RecordingCoordinator()

    policy = MissionAccessPolicy(
        mission_networks=["198.51.100.0/24"],
        registered_fingerprints=[],
        country_lookup=lambda ip: "AU"
    )

    monkeypatch.setitem(
        app.config,
        "SR07_GATEWAY_ENFORCED",
        True
    )

    monkeypatch.setitem(
        app.config,
        "MISSION_ACCESS_POLICY",
        policy
    )

    monkeypatch.setitem(
        app.config,
        "LOGIN_COORDINATOR",
        coordinator
    )

    monkeypatch.setitem(
        app.config,
        "WTF_CSRF_ENABLED",
        False
    )

    client = app.test_client()

    response = client.post(
        "/login",
        json={
            "account_id": "test-voter",
            "password": "test-password",
            "totp_code": "123456"
        },
        headers={
            "X-EVP-Source-IP": "198.51.100.42",
            "X-EVP-Client-Verify": "NONE"
        },
        environ_overrides={
            "REMOTE_ADDR": "192.0.2.10"
        }
    )

    assert response.status_code == 403
    assert coordinator.source_id is None
