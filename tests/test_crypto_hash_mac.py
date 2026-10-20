"""
SR-14: Self-describing hash and HMAC envelope tests.

Uses throwaway in-memory keys only.
"""

import base64

import pytest

import crypto_agility
from crypto_agility import (
    DEFAULT_POLICY,
    CryptoNotConfigured,
    CryptoService,
    KeyNotFound,
    default_registry,
)
from crypto_agility.algorithms import HASH, MAC
from crypto_agility.keys import KeyStore, parse_kid


DATA = b"synthetic audit entry 42"


@pytest.fixture
def service():
    return CryptoService(
        default_registry(), DEFAULT_POLICY, KeyStore.ephemeral()
    )


@pytest.fixture
def unconfigured(monkeypatch):
    monkeypatch.delenv("EVP_CRYPTO_DEV_KEYS", raising=False)
    monkeypatch.delenv("EVP_KEY_DIR", raising=False)
    monkeypatch.delenv("EVP_CRYPTO_POLICY", raising=False)
    crypto_agility.configure(None)

    yield

    crypto_agility.configure(None)


def flip_first_byte(value: str) -> str:
    raw = bytearray(base64.b64decode(value))
    raw[0] ^= 0x01

    return base64.b64encode(bytes(raw)).decode("ascii")


# Test 1: Hash output names its algorithm
def test_hash_is_self_describing(service):
    value = service.hash(DATA)

    assert value.startswith("sha256:")
    assert len(value) == len("sha256:") + 64


# Test 2: Hash verifies against the same data
def test_hash_round_trip(service):
    assert service.verify_hash(DATA, service.hash(DATA)) is True


# Test 3: Tampered data fails hash verification
def test_hash_of_tampered_data_fails(service):
    value = service.hash(DATA)

    assert service.verify_hash(DATA + b"!", value) is False


# Test 4: Old SHA-256 hashes still verify after switching to SHA3-256
def test_old_hash_verifies_after_default_change(service):
    old_value = service.hash(DATA)

    upgraded = service.with_policy(
        DEFAULT_POLICY.with_default(HASH, "sha3-256")
    )

    assert upgraded.hash(DATA).startswith("sha3-256:")
    assert upgraded.verify_hash(DATA, old_value) is True


# Test 5: Retired hash algorithm no longer verifies
def test_retired_hash_algorithm_fails(service):
    old_value = service.hash(DATA)

    retired = service.with_policy(
        DEFAULT_POLICY.with_default(HASH, "sha3-256")
        .with_allowed(HASH, {"sha3-256"})
    )

    assert retired.verify_hash(DATA, old_value) is False


# Test 6: Changing the algorithm prefix breaks verification
def test_hash_with_swapped_prefix_fails(service):
    digest = service.hash(DATA).split(":", 1)[1]

    assert service.verify_hash(DATA, "sha3-256:" + digest) is False


# Test 7: Malformed hash values are rejected without raising
@pytest.mark.parametrize("value", [
    None, 5, b"sha256:00", "", "sha256", "md5:abcd",
    "sha256:" + "z" * 64, "sha256:é", "sha256:" + "0" * 1000,
])
def test_malformed_hash_value_is_rejected(service, value):
    assert service.verify_hash(DATA, value) is False


# Test 8: Hashing refuses non-bytes input
def test_hash_requires_bytes(service):
    with pytest.raises(TypeError):
        service.hash("text")


# Test 9: MAC envelope records algorithm, key ID and version
def test_mac_envelope_is_self_describing(service):
    envelope = service.mac("audit", DATA)

    assert set(envelope) == {"alg", "kid", "v", "sig"}
    assert envelope["alg"] == "hmac-sha256"
    assert envelope["kid"] == "audit.hmac-sha256.v1"
    assert envelope["v"] == 1


# Test 10: MAC round trip
def test_mac_round_trip(service):
    envelope = service.mac("audit", DATA)

    assert service.verify_mac("audit", DATA, envelope) is True


# Test 11: Tampered data fails MAC verification
def test_mac_of_tampered_data_fails(service):
    envelope = service.mac("audit", DATA)

    assert service.verify_mac("audit", b"changed", envelope) is False


# Test 12: Tampered tag fails MAC verification
def test_mac_with_tampered_tag_fails(service):
    envelope = service.mac("audit", DATA)
    envelope["sig"] = flip_first_byte(envelope["sig"])

    assert service.verify_mac("audit", DATA, envelope) is False


# Test 13: MAC from another purpose is refused (key confusion)
def test_mac_for_other_purpose_fails(service):
    envelope = service.mac("audit", DATA)

    assert service.verify_mac("ballot", DATA, envelope) is False


# Test 14: Each purpose has its own key
def test_purposes_use_different_keys(service):
    audit = service.mac("audit", DATA)
    ballot = service.mac("ballot", DATA)

    assert audit["sig"] != ballot["sig"]


# Test 15: Another service's key does not verify (wrong key)
def test_mac_with_wrong_key_fails(service):
    other = CryptoService(
        default_registry(), DEFAULT_POLICY, KeyStore.ephemeral()
    )

    envelope = other.mac("audit", DATA)

    assert service.verify_mac("audit", DATA, envelope) is False


# Test 16: Swapping the algorithm field is refused
def test_mac_with_swapped_algorithm_fails(service):
    envelope = service.mac("audit", DATA)
    envelope["alg"] = "hmac-sha3-256"

    assert service.verify_mac("audit", DATA, envelope) is False


# Test 17: Old HMAC-SHA256 envelopes verify after switching to HMAC-SHA3-256
def test_old_mac_verifies_after_default_change(service):
    old_envelope = service.mac("audit", DATA)

    upgraded = service.with_policy(
        DEFAULT_POLICY.with_default(MAC, "hmac-sha3-256")
    )

    new_envelope = upgraded.mac("audit", DATA)

    assert new_envelope["alg"] == "hmac-sha3-256"
    assert new_envelope["kid"] == "audit.hmac-sha3-256.v1"
    assert upgraded.verify_mac("audit", DATA, old_envelope) is True
    assert upgraded.verify_mac("audit", DATA, new_envelope) is True


# Test 18: Malformed MAC envelopes are rejected without raising
@pytest.mark.parametrize("change", [
    lambda e: e.pop("kid"),
    lambda e: e.update(extra="x"),
    lambda e: e.update(v=2),
    lambda e: e.update(v=True),
    lambda e: e.update(v="1"),
    lambda e: e.update(alg=None),
    lambda e: e.update(alg="md5"),
    lambda e: e.update(kid="audit.hmac-sha256.v99"),
    lambda e: e.update(kid="not a kid"),
    lambda e: e.update(sig="***"),
    lambda e: e.update(sig="A" * 5000),
    lambda e: e.update(sig=12),
])
def test_malformed_mac_envelope_is_rejected(service, change):
    envelope = service.mac("audit", DATA)
    change(envelope)

    assert service.verify_mac("audit", DATA, envelope) is False


# Test 19: Non-dict envelopes are rejected without raising
@pytest.mark.parametrize("envelope", [None, "x", [], 1])
def test_non_dict_mac_envelope_is_rejected(service, envelope):
    assert service.verify_mac("audit", DATA, envelope) is False


# Test 20: Invalid purposes are refused
@pytest.mark.parametrize("purpose", ["", "Audit", "a.b", "a" * 40, None])
def test_invalid_purpose_is_refused(service, purpose):
    with pytest.raises(ValueError):
        service.mac(purpose, DATA)


# Test 21: Rotated key signs new MACs; old version still verifies
def test_rotated_mac_key_keeps_old_version(service):
    old_envelope = service.mac("audit", DATA)

    algorithm = service.factory.for_new(MAC)
    service.keys.rotate("audit", algorithm)

    new_envelope = service.mac("audit", DATA)

    assert new_envelope["kid"] == "audit.hmac-sha256.v2"
    assert service.verify_mac("audit", DATA, old_envelope) is True
    assert service.verify_mac("audit", DATA, new_envelope) is True


# Test 22: Key IDs are parsed strictly
def test_key_id_parsing():
    assert parse_kid("audit.hmac-sha256.v3") == ("audit", "hmac-sha256", 3)

    for kid in ("audit.hmac-sha256", "audit.hmac-sha256.v0",
                "../x.y.v1", "Audit.x.v1", None):
        with pytest.raises(KeyNotFound):
            parse_kid(kid)


# Test 23: Key store without generation refuses missing keys
def test_store_without_generation_has_no_keys():
    service = CryptoService(
        default_registry(), DEFAULT_POLICY, KeyStore()
    )

    with pytest.raises(KeyNotFound):
        service.mac("audit", DATA)


# Test 24: Key material never appears in repr
def test_key_material_is_not_in_repr(service):
    service.mac("audit", DATA)

    entry = service.keys.current("audit", service.factory.for_new(MAC))

    assert entry.material.secret.hex() not in repr(entry)
    assert "redacted" in repr(entry.material)


# Test 25: Module-level crypto fails closed without configuration
def test_unconfigured_crypto_fails_closed(unconfigured):
    with pytest.raises(CryptoNotConfigured):
        crypto_agility.crypto.hash(DATA)


# Test 26: Dev-key flag configures module-level crypto
def test_dev_keys_flag_configures_crypto(unconfigured, monkeypatch):
    monkeypatch.setenv("EVP_CRYPTO_DEV_KEYS", "1")

    envelope = crypto_agility.crypto.mac("audit", DATA)

    assert crypto_agility.crypto.verify_mac("audit", DATA, envelope)


# Test 27: Only the exact value "1" enables dev keys
def test_dev_keys_flag_must_be_exact(unconfigured, monkeypatch):
    monkeypatch.setenv("EVP_CRYPTO_DEV_KEYS", "true")

    with pytest.raises(CryptoNotConfigured):
        crypto_agility.crypto.hash(DATA)


# Test 28: configure() installs an explicit service
def test_configure_installs_service(unconfigured, service):
    crypto_agility.configure(service)

    envelope = crypto_agility.crypto.mac("audit", DATA)

    assert service.verify_mac("audit", DATA, envelope) is True


# Test 29: configure() rejects other objects
def test_configure_rejects_non_service(unconfigured):
    with pytest.raises(TypeError):
        crypto_agility.configure(object())
