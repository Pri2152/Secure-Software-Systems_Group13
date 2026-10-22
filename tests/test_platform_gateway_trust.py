
"""
SR-20 / SR-07 tests for the configurable gateway trust.

- Default: only a loopback peer is trusted (unchanged)
- EVP_TRUSTED_GATEWAY_NETWORKS: only listed peers are trusted
- Any other peer is rejected, even with X-EVP-* headers
- Invalid values stop start-up (fail closed)
- EVP_SIMULATED_MISSION_NETWORKS replaces the lab's
  127.0.0.1 -> GB mapping, with the same default
"""

import ipaddress
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

import gateway_security

from gateway_security import (
    evaluate_gateway_request,
    is_trusted_gateway_peer,
    load_trusted_gateway_networks,
    parse_network_list,
)
from mission_access import AccessDecision


REPO_ROOT = Path(__file__).resolve().parent.parent
GATEWAY_ADDRESS = "172.30.0.10"

INVALID_VALUES = [
    "",
    " ",
    "not-an-ip",
    "172.30.0.10/33",
    "172.30.0.10/24",   # host bits set
    "172.30.0.10,",
    ",172.30.0.10",
    "172.30.0.10;10.0.0.1",
    "0.0.0.0/0",
    "::/0",
    "localhost",
]


class RecordingPolicy:
    """Stands in for MissionAccessPolicy; records calls."""

    def __init__(self):
        self.calls = []

    def evaluate(self, source_ip, **kwargs):
        self.calls.append(source_ip)
        return AccessDecision(True, "domestic_connection")


def forwarded_request(peer):
    return SimpleNamespace(
        remote_addr=peer,
        headers={
            "X-EVP-Source-IP": "203.0.113.10",
            "X-EVP-Client-Verify": "NONE",
            "X-EVP-Client-Cert": "",
        },
    )


def peer(value):
    return ipaddress.ip_address(value)


def subprocess_env(**overrides):
    env = {
        key: value for key, value in os.environ.items()
        if not key.startswith("EVP_")
    }
    env.update(overrides)
    return env


@pytest.fixture
def configured_gateway(monkeypatch):
    monkeypatch.setattr(
        gateway_security,
        "TRUSTED_GATEWAY_NETWORKS",
        parse_network_list(
            f"{GATEWAY_ADDRESS}/32", "EVP_TRUSTED_GATEWAY_NETWORKS"
        ),
    )


# Default: loopback only

def test_default_setting_is_unset(monkeypatch):
    monkeypatch.delenv("EVP_TRUSTED_GATEWAY_NETWORKS", raising=False)

    assert load_trusted_gateway_networks() is None


@pytest.mark.parametrize("address", ["127.0.0.1", "127.0.0.53", "::1"])
def test_default_trusts_loopback(monkeypatch, address):
    monkeypatch.setattr(gateway_security, "TRUSTED_GATEWAY_NETWORKS", None)

    assert is_trusted_gateway_peer(peer(address)) is True


@pytest.mark.parametrize("address", [
    GATEWAY_ADDRESS, "172.30.0.1", "10.0.0.1", "203.0.113.10", "::2",
])
def test_default_rejects_non_loopback(monkeypatch, address):
    monkeypatch.setattr(gateway_security, "TRUSTED_GATEWAY_NETWORKS", None)

    assert is_trusted_gateway_peer(peer(address)) is False


def test_default_request_from_container_peer_is_denied(monkeypatch):
    monkeypatch.setattr(gateway_security, "TRUSTED_GATEWAY_NETWORKS", None)
    policy = RecordingPolicy()

    decision = evaluate_gateway_request(
        forwarded_request(GATEWAY_ADDRESS), policy
    )

    assert decision.reason == "untrusted_gateway_peer"
    assert policy.calls == []


# Configured gateway address

def test_configured_gateway_is_trusted(configured_gateway):
    policy = RecordingPolicy()

    decision = evaluate_gateway_request(
        forwarded_request(GATEWAY_ADDRESS), policy
    )

    assert decision.allowed is True
    assert policy.calls == ["203.0.113.10"]


@pytest.mark.parametrize("address", [
    "172.30.0.11",     # neighbour on the same subnet
    "172.30.0.1",      # network gateway
    "172.30.0.2",
    "127.0.0.1",       # loopback is replaced, not added
    "::1",
    "::ffff:172.30.0.10",
    "10.0.0.10",
])
def test_other_peer_rejected_even_with_headers(configured_gateway, address):
    policy = RecordingPolicy()

    decision = evaluate_gateway_request(forwarded_request(address), policy)

    assert decision.allowed is False
    assert decision.reason == "untrusted_gateway_peer"
    assert policy.calls == []


@pytest.mark.parametrize("address", [None, "", "gateway", "172.30.0.10:443"])
def test_unparseable_peer_is_denied(configured_gateway, address):
    decision = evaluate_gateway_request(
        forwarded_request(address), RecordingPolicy()
    )

    assert decision.reason == "invalid_gateway_peer"


def test_setting_is_read_from_environment(monkeypatch):
    monkeypatch.setenv(
        "EVP_TRUSTED_GATEWAY_NETWORKS",
        f" {GATEWAY_ADDRESS} , 10.20.30.0/28 ",
    )

    assert load_trusted_gateway_networks() == (
        ipaddress.ip_network(f"{GATEWAY_ADDRESS}/32"),
        ipaddress.ip_network("10.20.30.0/28"),
    )


# Invalid values fail closed

@pytest.mark.parametrize("value", INVALID_VALUES)
def test_invalid_value_is_rejected(monkeypatch, value):
    monkeypatch.setenv("EVP_TRUSTED_GATEWAY_NETWORKS", value)

    with pytest.raises(ValueError):
        load_trusted_gateway_networks()


def test_error_does_not_echo_the_value(monkeypatch):
    monkeypatch.setenv("EVP_TRUSTED_GATEWAY_NETWORKS", "secret-looking-text")

    with pytest.raises(ValueError) as error:
        load_trusted_gateway_networks()

    assert "secret-looking-text" not in str(error.value)


def run_app_import(**env):
    return subprocess.run(
        [sys.executable, "-c",
         "import app, gateway_security; "
         "print(gateway_security.TRUSTED_GATEWAY_NETWORKS)"],
        cwd=REPO_ROOT,
        env=subprocess_env(**env),
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize("value", ["not-an-ip", "", "0.0.0.0/0"])
def test_invalid_value_stops_app_start_up(value):
    result = run_app_import(EVP_TRUSTED_GATEWAY_NETWORKS=value)

    assert result.returncode != 0
    assert "EVP_TRUSTED_GATEWAY_NETWORKS" in result.stderr


def test_valid_value_loads_at_start_up():
    result = run_app_import(EVP_TRUSTED_GATEWAY_NETWORKS=GATEWAY_ADDRESS)

    assert result.returncode == 0, result.stderr
    assert "IPv4Network('172.30.0.10/32')" in result.stdout


def test_unset_value_keeps_loopback_default_at_start_up():
    result = run_app_import()

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] == "None"


# Simulated mission network in gateway_runtime.py

RUNTIME_PROBE = textwrap.dedent("""
    import json, pathlib, sys

    fake_files = {
        "/run/evp/registered_fingerprints.txt": "ab" * 32 + "\\n",
        "/run/evp/demo-voter.json": json.dumps({
            "account_id": "demo-voter",
            "password": "synthetic-test-only",
            "totp_secret": "JBSWY3DPEHPK3PXP",
        }),
    }
    original = pathlib.Path.read_text

    def fake_read_text(self, *args, **kwargs):
        if str(self) in fake_files:
            return fake_files[str(self)]
        return original(self, *args, **kwargs)

    pathlib.Path.read_text = fake_read_text

    import gateway_runtime

    def lookup(address):
        try:
            return gateway_runtime.lab_country_lookup(address)
        except LookupError:
            return None

    policy = gateway_runtime.app.config["MISSION_ACCESS_POLICY"]
    print(json.dumps({
        "networks": [str(n) for n in policy.mission_networks],
        "lookups": {a: lookup(a) for a in sys.argv[1:]},
    }))
""")

PROBE_ADDRESSES = ["127.0.0.1", "172.30.0.1", "172.30.0.10"]


def run_runtime(**env):
    return subprocess.run(
        [sys.executable, "-c", RUNTIME_PROBE, *PROBE_ADDRESSES],
        cwd=REPO_ROOT,
        # SR-13: the runtime needs a PII key; development keys here.
        env=subprocess_env(EVP_LOCAL_LAB="1", EVP_CRYPTO_DEV_KEYS="1", **env),
        capture_output=True,
        text=True,
    )


def test_mission_network_default_is_loopback_gb():
    result = run_runtime()

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.splitlines()[-1]) == {
        "networks": ["127.0.0.1/32"],
        "lookups": {
            "127.0.0.1": "GB",
            "172.30.0.1": None,
            "172.30.0.10": None,
        },
    }


def test_mission_network_can_be_configured():
    result = run_runtime(EVP_SIMULATED_MISSION_NETWORKS="172.30.0.1/32")

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.splitlines()[-1]) == {
        "networks": ["172.30.0.1/32"],
        "lookups": {
            "127.0.0.1": None,
            "172.30.0.1": "GB",
            "172.30.0.10": None,
        },
    }


@pytest.mark.parametrize("value", ["not-an-ip", "", "::/0"])
def test_invalid_mission_network_stops_start_up(value):
    result = run_runtime(EVP_SIMULATED_MISSION_NETWORKS=value)

    assert result.returncode != 0
    assert "EVP_SIMULATED_MISSION_NETWORKS" in result.stderr
