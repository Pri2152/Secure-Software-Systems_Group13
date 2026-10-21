"""SR-10 real AEAD and canonical selection/metadata protection."""

import json

import pytest

import ballot_protection
from ballot_protection import (
    BallotProtectionError, _open_ballot, ballot_metadata, canonical_json, protect_ballot,
)
from crypto_agility import build_service


@pytest.fixture
def protection(monkeypatch):
    service = build_service(dev_keys=True)
    monkeypatch.setattr(ballot_protection, "crypto", service)
    return service


@pytest.fixture
def metadata():
    return ballot_metadata("a" * 64, "election-2026", "Melbourne", 1, "sha256:" + "0" * 64)


def test_protected_selection_and_payload_round_trip(protection, metadata):
    payload = '{"candidate_id":999,"ct":"synthetic"}'
    stored = protect_ballot(7, payload, metadata)
    assert payload not in stored
    envelope = json.loads(stored)
    assert set(envelope) == {"alg", "kid", "v", "nonce", "ct"}
    assert envelope["alg"] == "aes-256-gcm"
    assert _open_ballot(stored, metadata) == dict(v=1, candidate_id=7, payload=payload)


def test_encryption_is_randomised(protection, metadata):
    assert protect_ballot(7, "opaque", metadata) != protect_ballot(7, "opaque", metadata)


def test_canonical_json_does_not_depend_on_dict_order():
    assert canonical_json(dict(b="é", a=1)) == canonical_json(dict(a=1, b="é"))


@pytest.mark.parametrize("field,value", [
    ("ballot_id", "b" * 64), ("election_id", "another-election"),
    ("electoral_division", "Sydney"), ("chain_index", 2),
    ("previous_hash", "sha256:" + "1" * 64),
])
def test_metadata_or_position_swap_fails_authentication(protection, metadata, field, value):
    stored = protect_ballot(7, "opaque", metadata)
    changed = dict(metadata, **{field: value})
    with pytest.raises(BallotProtectionError):
        _open_ballot(stored, changed)


def test_ciphertext_change_fails_authentication(protection, metadata):
    envelope = json.loads(protect_ballot(7, "opaque", metadata))
    envelope["ct"] = ("A" if envelope["ct"][0] != "A" else "B") + envelope["ct"][1:]
    with pytest.raises(BallotProtectionError):
        _open_ballot(canonical_json(envelope), metadata)


@pytest.mark.parametrize("content", [
    dict(v=1, candidate_id=True, payload="opaque"),
    dict(v=1, candidate_id=7, payload="opaque", voter_id="forbidden"),
    dict(v=2, candidate_id=7, payload="opaque"),
])
def test_authenticated_but_invalid_plaintext_is_rejected(protection, metadata, content):
    envelope = protection.encrypt("ballot", canonical_json(content).encode(),
                                  aad=canonical_json(metadata).encode())
    with pytest.raises(BallotProtectionError):
        _open_ballot(canonical_json(envelope), metadata)


def test_missing_key_fails_closed(protection, metadata, monkeypatch):
    from crypto_agility import KeyNotFound

    def fail(*args, **kwargs):
        raise KeyNotFound("private key details")

    monkeypatch.setattr(protection, "encrypt", fail)
    with pytest.raises(BallotProtectionError, match="^Ballot protection failed$"):
        protect_ballot(7, "opaque", metadata)
