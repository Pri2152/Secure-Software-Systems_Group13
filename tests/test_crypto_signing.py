"""
SR-14: Digital signature and algorithm-migration tests.

Shows crypto-agility: the default signing algorithm
changes by configuration, old signatures keep
verifying until the algorithm is retired.
"""

import base64

import pytest

from crypto_agility import (
    DEFAULT_POLICY,
    CryptoService,
    KeyNotFound,
    default_registry,
)
from crypto_agility.algorithms import (
    ECDSA_P256_SHA256,
    ED25519,
    SIGN,
    KeyMaterial,
)
from crypto_agility.keys import KeyStore


BALLOT = b'{"ballot_id": "synthetic-001"}'


@pytest.fixture
def service():
    return CryptoService(
        default_registry(), DEFAULT_POLICY, KeyStore.ephemeral()
    )


def ecdsa_policy():
    return DEFAULT_POLICY.with_default(SIGN, "ecdsa-p256-sha256")


def flip_first_byte(value: str) -> str:
    raw = bytearray(base64.b64decode(value))
    raw[0] ^= 0x01

    return base64.b64encode(bytes(raw)).decode("ascii")


# Test 1: Default signature is Ed25519 with a versioned key ID
def test_sign_uses_default_ed25519(service):
    envelope = service.sign("ballot", BALLOT)

    assert set(envelope) == {"alg", "kid", "v", "sig"}
    assert envelope["alg"] == "ed25519"
    assert envelope["kid"] == "ballot.ed25519.v1"
    assert envelope["v"] == 1


# Test 2: Signature round trip
def test_sign_verify_round_trip(service):
    envelope = service.sign("ballot", BALLOT)

    assert service.verify("ballot", BALLOT, envelope) is True


# Test 3: Tampered data fails verification
def test_tampered_data_fails_verification(service):
    envelope = service.sign("ballot", BALLOT)

    assert service.verify("ballot", BALLOT + b" ", envelope) is False


# Test 4: Algorithm switch: new ECDSA, old Ed25519 still verifies
def test_switch_to_ecdsa_keeps_old_signatures_valid(service):
    old_envelope = service.sign("ballot", BALLOT)

    migrated = service.with_policy(ecdsa_policy())
    new_envelope = migrated.sign("ballot", BALLOT)

    assert new_envelope["alg"] == "ecdsa-p256-sha256"
    assert new_envelope["kid"] == "ballot.ecdsa-p256-sha256.v1"
    assert migrated.verify("ballot", BALLOT, new_envelope) is True
    assert migrated.verify("ballot", BALLOT, old_envelope) is True


# Test 5: Retiring Ed25519 makes its old signatures fail
def test_retired_ed25519_signatures_fail(service):
    old_envelope = service.sign("ballot", BALLOT)

    migrated = service.with_policy(ecdsa_policy())
    new_envelope = migrated.sign("ballot", BALLOT)

    retired = migrated.with_policy(
        ecdsa_policy().with_allowed(SIGN, {"ecdsa-p256-sha256"})
    )

    assert retired.verify("ballot", BALLOT, old_envelope) is False
    assert retired.verify("ballot", BALLOT, new_envelope) is True


# Test 6: Tampered signature fails
def test_tampered_signature_fails(service):
    envelope = service.sign("ballot", BALLOT)
    envelope["sig"] = flip_first_byte(envelope["sig"])

    assert service.verify("ballot", BALLOT, envelope) is False


# Test 7: Changing the alg field fails (downgrade/confusion attempt)
def test_tampered_alg_field_fails(service):
    service.with_policy(ecdsa_policy()).sign("ballot", BALLOT)
    envelope = service.sign("ballot", BALLOT)

    envelope["alg"] = "ecdsa-p256-sha256"

    assert service.verify("ballot", BALLOT, envelope) is False


# Test 8: Pointing kid at another existing key fails
def test_tampered_kid_field_fails(service):
    envelope = service.sign("ballot", BALLOT)
    service.keys.rotate("ballot", ED25519)

    envelope["kid"] = "ballot.ed25519.v2"

    assert service.verify("ballot", BALLOT, envelope) is False


# Test 9: kid from another purpose is refused (key confusion)
def test_kid_from_other_purpose_is_refused(service):
    tally = service.sign("tally", BALLOT)

    assert service.verify("ballot", BALLOT, tally) is False


# Test 10: Signature reused under another purpose fails
def test_signature_for_other_purpose_fails(service):
    envelope = service.sign("ballot", BALLOT)
    service.sign("results", BALLOT)

    assert service.verify("results", BALLOT, envelope) is False


# Test 11: Reserved or unknown algorithm in envelope fails
@pytest.mark.parametrize("alg", ["ml-dsa-65", "rsa-pss", "", "hmac-sha256"])
def test_unknown_or_wrong_family_alg_fails(service, alg):
    envelope = service.sign("ballot", BALLOT)
    envelope["alg"] = alg

    assert service.verify("ballot", BALLOT, envelope) is False


# Test 12: Malformed envelopes never raise
@pytest.mark.parametrize("envelope", [
    None, {}, [], "sig",
    {"alg": "ed25519", "kid": "ballot.ed25519.v1", "v": 1},
    {"alg": "ed25519", "kid": "ballot.ed25519.v1", "v": 1, "sig": None},
    {"alg": "ed25519", "kid": "ballot.ed25519.v1", "v": 1, "sig": "%%"},
    {"alg": "ed25519", "kid": 7, "v": 1, "sig": "AAAA"},
])
def test_malformed_signature_envelope_fails(service, envelope):
    service.sign("ballot", BALLOT)

    assert service.verify("ballot", BALLOT, envelope) is False


# Test 13: Non-bytes data never raises during verification
def test_verify_with_non_bytes_data_fails(service):
    envelope = service.sign("ballot", BALLOT)

    assert service.verify("ballot", BALLOT.decode(), envelope) is False


# Test 14: Key rotation: new version signs, old version verifies
def test_rotation_keeps_old_signatures_valid(service):
    old_envelope = service.sign("ballot", BALLOT)

    service.keys.rotate("ballot", ED25519)
    new_envelope = service.sign("ballot", BALLOT)

    assert new_envelope["kid"] == "ballot.ed25519.v2"
    assert service.verify("ballot", BALLOT, old_envelope) is True
    assert service.verify("ballot", BALLOT, new_envelope) is True


# Test 15: Public key PEM verifies outside the private compartment
def test_public_key_only_store_verifies(service):
    envelope = service.sign("results", BALLOT)

    current = service.keys.current("results", ED25519)
    public_only = KeyStore()
    public_only.add(
        "results",
        ED25519,
        KeyMaterial(public_key=current.material.public_key),
        version=1,
        current=True,
    )

    verifier = CryptoService(
        default_registry(), DEFAULT_POLICY, public_only
    )

    assert verifier.verify("results", BALLOT, envelope) is True

    with pytest.raises(KeyNotFound):
        verifier.sign("results", BALLOT)


# Test 16: public_key_pem returns the current signing key
def test_public_key_pem_for_signing_purpose(service):
    pem = service.public_key_pem("results")

    assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert b"PRIVATE" not in pem


# Test 17: Mismatched key pair is rejected when loading
def test_mismatched_key_pair_is_rejected():
    first = ED25519.generate_key()
    second = ED25519.generate_key()

    with pytest.raises(ValueError):
        ED25519.check_key(
            KeyMaterial(
                private_key=first.private_key,
                public_key=second.public_key,
            )
        )


# Test 18: ECDSA key cannot be registered for Ed25519
def test_wrong_key_type_is_rejected():
    store = KeyStore()

    with pytest.raises(ValueError):
        store.add(
            "ballot", ED25519, ECDSA_P256_SHA256.generate_key(), 1
        )
