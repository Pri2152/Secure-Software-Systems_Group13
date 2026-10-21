"""
SR-14: Algorithm registry, policy and secure factory tests.
"""

import json

import pytest

from crypto_agility import (
    DEFAULT_POLICY,
    AlgorithmNotAllowed,
    AlgorithmRegistry,
    AlgorithmUnavailable,
    CryptoFactory,
    CryptoPolicy,
    InvalidPolicy,
    UnknownAlgorithm,
    default_registry,
)
from crypto_agility.algorithms import (
    HASH,
    MAC,
    SHA256,
    ReservedAlgorithm,
)


@pytest.fixture
def registry():
    registry = default_registry()
    registry.register(ReservedAlgorithm("future-hash", HASH))

    return registry


# Test 1: Factory returns the policy default for new outputs
def test_factory_returns_policy_default(registry):
    factory = CryptoFactory(registry, DEFAULT_POLICY)

    assert factory.for_new(HASH).name == "sha256"


# Test 2: Changing configuration changes the algorithm, not the code
def test_policy_change_switches_new_algorithm(registry):
    policy = DEFAULT_POLICY.with_default(HASH, "sha3-256")

    factory = CryptoFactory(registry, policy)

    assert factory.for_new(HASH).name == "sha3-256"


# Test 3: Verification uses the algorithm named in the output
def test_verify_uses_named_allowed_algorithm(registry):
    factory = CryptoFactory(registry, DEFAULT_POLICY)

    assert factory.for_verify(HASH, "sha3-256").name == "sha3-256"


# Test 4: Unknown algorithm name is refused
def test_unknown_algorithm_is_refused(registry):
    factory = CryptoFactory(registry, DEFAULT_POLICY)

    with pytest.raises(UnknownAlgorithm):
        factory.for_verify(HASH, "md5")


# Test 5: Non-string algorithm name is refused
@pytest.mark.parametrize("name", [None, 1, b"sha256", ["sha256"]])
def test_non_string_algorithm_name_is_refused(registry, name):
    factory = CryptoFactory(registry, DEFAULT_POLICY)

    with pytest.raises(UnknownAlgorithm):
        factory.for_verify(HASH, name)


# Test 6: A name from another family is refused (no family confusion)
def test_algorithm_from_wrong_family_is_refused(registry):
    with pytest.raises(UnknownAlgorithm):
        registry.get(MAC, "sha256")


# Test 7: Registered but disallowed algorithm is refused for verify
def test_disallowed_algorithm_is_refused_for_verify(registry):
    policy = DEFAULT_POLICY.with_allowed(HASH, {"sha256"})

    factory = CryptoFactory(registry, policy)

    with pytest.raises(AlgorithmNotAllowed):
        factory.for_verify(HASH, "sha3-256")


# Test 8: Reserved algorithm is unavailable even if named
def test_reserved_algorithm_is_unavailable(registry):
    factory = CryptoFactory(registry, DEFAULT_POLICY)

    with pytest.raises(AlgorithmUnavailable):
        factory.for_verify(HASH, "future-hash")


# Test 9: Using a reserved algorithm's operations raises
def test_reserved_algorithm_operations_raise():
    reserved = ReservedAlgorithm("future-hash", HASH)

    with pytest.raises(AlgorithmUnavailable):
        reserved.digest(b"data")


# Test 10: Policy that allows a reserved algorithm is rejected
def test_policy_allowing_reserved_algorithm_is_rejected(registry):
    policy = DEFAULT_POLICY.with_allowed(
        HASH, {"sha256", "future-hash"}
    )

    with pytest.raises(AlgorithmUnavailable):
        CryptoFactory(registry, policy)


# Test 11: Policy naming an unknown algorithm is rejected
def test_policy_with_unknown_algorithm_is_rejected(registry):
    policy = DEFAULT_POLICY.with_allowed(HASH, {"sha256", "md5"})

    with pytest.raises(UnknownAlgorithm):
        CryptoFactory(registry, policy)


# Test 12: Default outside the allow-list is rejected
def test_default_must_be_allowed():
    with pytest.raises(AlgorithmNotAllowed):
        CryptoPolicy(
            defaults={HASH: "sha3-256"},
            allowed={HASH: {"sha256"}},
        )


# Test 13: Unknown family is rejected
def test_unknown_family_is_rejected():
    with pytest.raises(InvalidPolicy):
        CryptoPolicy(defaults={}, allowed={"cipher": {"des"}})


# Test 14: Family with no default cannot produce new outputs
def test_missing_default_refuses_new_outputs(registry):
    policy = CryptoPolicy(defaults={}, allowed={HASH: {"sha256"}})

    factory = CryptoFactory(registry, policy)

    with pytest.raises(AlgorithmNotAllowed):
        factory.for_new(HASH)


# Test 15: Family with no allow-list denies verification
def test_missing_allow_list_denies_verification(registry):
    policy = CryptoPolicy(defaults={}, allowed={})

    factory = CryptoFactory(registry, policy)

    with pytest.raises(AlgorithmNotAllowed):
        factory.for_verify(HASH, "sha256")


# Test 16: Policy is immutable
def test_policy_is_immutable():
    with pytest.raises(AttributeError):
        DEFAULT_POLICY.defaults = {}

    with pytest.raises(TypeError):
        DEFAULT_POLICY.defaults[HASH] = "sha3-256"


# Test 17: Policy round-trips through a dictionary
def test_policy_from_dict_round_trip():
    policy = CryptoPolicy.from_dict(DEFAULT_POLICY.to_dict())

    assert policy == DEFAULT_POLICY


# Test 18: Malformed policy dictionaries are rejected
@pytest.mark.parametrize("data", [
    None,
    [],
    {"defaults": {}},
    {"defaults": {}, "allowed": {}, "extra": 1},
    {"defaults": {}, "allowed": {HASH: "sha256"}},
    {"defaults": {HASH: 5}, "allowed": {HASH: ["sha256"]}},
    {"defaults": [], "allowed": {}},
    {"defaults": {}, "allowed": {HASH: [None]}},
])
def test_malformed_policy_dict_is_rejected(data):
    with pytest.raises(InvalidPolicy):
        CryptoPolicy.from_dict(data)


# Test 19: Policy loads from a JSON file
def test_policy_loads_from_json_file(tmp_path):
    path = tmp_path / "crypto_policy.json"
    path.write_text(json.dumps({
        "defaults": {HASH: "sha3-256"},
        "allowed": {HASH: ["sha256", "sha3-256"]},
    }), encoding="utf-8")

    policy = CryptoPolicy.from_json_file(path)

    assert policy.default_for(HASH) == "sha3-256"


# Test 20: Unreadable or invalid policy files fail closed
def test_invalid_policy_file_is_rejected(tmp_path):
    path = tmp_path / "crypto_policy.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(InvalidPolicy):
        CryptoPolicy.from_json_file(path)

    with pytest.raises(InvalidPolicy):
        CryptoPolicy.from_json_file(tmp_path / "missing.json")


# Test 21: Duplicate registration is refused
def test_duplicate_registration_is_refused():
    registry = AlgorithmRegistry([SHA256])

    with pytest.raises(ValueError):
        registry.register(SHA256)


# Test 22: Registry lists names per family
def test_registry_lists_names_per_family(registry):
    assert registry.names(HASH) == {
        "sha256", "sha3-256", "future-hash"
    }
