"""
SR-14: Argon2id rehash-on-login helper and reserved
post-quantum signature slot tests.
"""

import pytest

from auth import hash_password as workstream_a_hash_password
from crypto_agility import (
    DEFAULT_POLICY,
    AlgorithmUnavailable,
    CryptoFactory,
    CryptoService,
    default_registry,
)
from crypto_agility.algorithms import PASSWORD, SIGN
from crypto_agility.keys import KeyStore
from crypto_agility.passwords import (
    ARGON2ID_V1,
    Argon2idAlgorithm,
    Argon2Parameters,
    hash_password,
    verify_and_upgrade,
)


PASSWORD_TEXT = "SyntheticStaffPassword2026!"

# Deliberately weak "old" parameters, used only to create an outdated hash
OUTDATED = Argon2idAlgorithm(
    "argon2id-test-outdated",
    Argon2Parameters(time_cost=1, memory_cost_kib=8192, parallelism=1),
)


@pytest.fixture
def service():
    return CryptoService(
        default_registry(), DEFAULT_POLICY, KeyStore.ephemeral()
    )


# Test 1: Hashes are Argon2id with the v1 parameters
def test_hash_uses_current_argon2id_parameters():
    stored = hash_password(PASSWORD_TEXT)

    assert stored.startswith("$argon2id$v=19$m=65536,t=3,p=4$")


# Test 2: Correct password with current parameters: no rehash
def test_current_hash_verifies_without_rehash():
    stored = hash_password(PASSWORD_TEXT)

    assert verify_and_upgrade(stored, PASSWORD_TEXT) == (True, None)


# Test 3: Outdated parameters are upgraded on successful login
def test_outdated_hash_is_upgraded_on_login():
    old_hash = OUTDATED.hash(PASSWORD_TEXT)

    ok, new_hash = verify_and_upgrade(old_hash, PASSWORD_TEXT)

    assert ok is True
    assert new_hash is not None
    assert new_hash.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert verify_and_upgrade(new_hash, PASSWORD_TEXT) == (True, None)


# Test 4: Wrong password never produces a new hash
def test_wrong_password_is_not_upgraded():
    old_hash = OUTDATED.hash(PASSWORD_TEXT)

    assert verify_and_upgrade(old_hash, "wrong-password") == (False, None)


# Test 5: Malformed inputs fail closed
@pytest.mark.parametrize("stored, password", [
    (None, PASSWORD_TEXT),
    ("not-a-hash", PASSWORD_TEXT),
    ("$argon2id$v=19$m=1,t=1,p=1$xx$yy", PASSWORD_TEXT),
    ("$argon2id$v=19$m=65536,t=3,p=4$abc$def", None),
    ("$argon2id$v=19$m=65536,t=3,p=4$abc$def", ""),
])
def test_malformed_password_input_fails(stored, password):
    assert verify_and_upgrade(stored, password) == (False, None)


# Test 6: Empty passwords cannot be hashed
def test_empty_password_is_refused():
    with pytest.raises(ValueError):
        hash_password("")


# Test 7: Workstream A's voter hashes are already current
def test_workstream_a_hashes_need_no_rehash():
    stored = workstream_a_hash_password(PASSWORD_TEXT)

    assert verify_and_upgrade(stored, PASSWORD_TEXT) == (True, None)


# Test 8: Password parameter set is chosen by policy
def test_service_uses_policy_password_algorithm(service):
    assert service.factory.for_new(PASSWORD) is ARGON2ID_V1

    stored = service.hash_password(PASSWORD_TEXT)

    assert service.verify_and_upgrade_password(
        stored, PASSWORD_TEXT
    ) == (True, None)


# Test 9: Service upgrades outdated hashes too
def test_service_upgrades_outdated_hash(service):
    ok, new_hash = service.verify_and_upgrade_password(
        OUTDATED.hash(PASSWORD_TEXT), PASSWORD_TEXT
    )

    assert ok is True
    assert new_hash.startswith("$argon2id$v=19$m=65536,t=3,p=4$")


# Test 10: ml-dsa-65 is registered as a reserved signing slot
def test_pqc_slot_is_registered_but_unavailable():
    algorithm = default_registry().get(SIGN, "ml-dsa-65")

    assert algorithm.available is False

    with pytest.raises(AlgorithmUnavailable):
        algorithm.sign(None, b"data")


# Test 11: Factory refuses the PQC slot for verification
def test_factory_refuses_pqc_slot():
    factory = CryptoFactory(default_registry(), DEFAULT_POLICY)

    with pytest.raises(AlgorithmUnavailable):
        factory.for_verify(SIGN, "ml-dsa-65")


# Test 12: Policy cannot enable the PQC slot yet
def test_policy_enabling_pqc_slot_is_rejected():
    policy = DEFAULT_POLICY.with_default(SIGN, "ml-dsa-65")

    with pytest.raises(AlgorithmUnavailable):
        CryptoService(default_registry(), policy, KeyStore.ephemeral())


# Test 13: Envelope claiming ml-dsa-65 does not verify
def test_pqc_envelope_does_not_verify(service):
    envelope = service.sign("ballot", b"data")
    envelope["alg"] = "ml-dsa-65"
    envelope["kid"] = "ballot.ml-dsa-65.v1"

    assert service.verify("ballot", b"data", envelope) is False
