"""
SR-14: Authenticated encryption and public-key sealing tests.

Includes tamper tests, a Workstream E provider
compatibility check (SR-13) and a Workstream D voter
client interoperability check (seal format).
"""

import base64
import json
import os

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import crypto_agility
from crypto_agility import (
    DEFAULT_POLICY,
    CryptoService,
    DecryptionError,
    default_registry,
)
from crypto_agility.algorithms import AEAD, AES_256_GCM, KeyMaterial
from crypto_agility.keys import KeyStore


PII = b"12 Example Street, Testville"
BALLOT = b'{"preferences": [2, 1, 3]}'


@pytest.fixture(scope="module")
def service():
    # Module scope: the RSA-3072 key is generated once
    return CryptoService(
        default_registry(), DEFAULT_POLICY, KeyStore.ephemeral()
    )


def flip_byte(value: str, index: int = 0) -> str:
    raw = bytearray(base64.b64decode(value))
    raw[index] ^= 0x01

    return base64.b64encode(bytes(raw)).decode("ascii")


# Test 1: Encryption envelope is self-describing
def test_encrypt_envelope_format(service):
    envelope = service.encrypt("pii", PII)

    assert set(envelope) == {"alg", "kid", "v", "nonce", "ct"}
    assert envelope["alg"] == "aes-256-gcm"
    assert envelope["kid"] == "pii.aes-256-gcm.v1"
    assert len(base64.b64decode(envelope["nonce"])) == 12
    assert PII not in base64.b64decode(envelope["ct"])


# Test 2: Encrypt/decrypt round trip
def test_encrypt_decrypt_round_trip(service):
    envelope = service.encrypt("pii", PII)

    assert service.decrypt("pii", envelope) == PII


# Test 3: Round trip with associated data
def test_round_trip_with_aad(service):
    envelope = service.encrypt("pii", PII, aad=b"voter:demo-001")

    assert service.decrypt("pii", envelope, aad=b"voter:demo-001") == PII


# Test 4: A fresh nonce is used for each message
def test_each_encryption_uses_new_nonce(service):
    first = service.encrypt("pii", PII)
    second = service.encrypt("pii", PII)

    assert first["nonce"] != second["nonce"]
    assert first["ct"] != second["ct"]


# Test 5: Flipped ciphertext byte is detected
def test_flipped_ciphertext_byte_raises(service):
    envelope = service.encrypt("pii", PII)
    envelope["ct"] = flip_byte(envelope["ct"])

    with pytest.raises(DecryptionError):
        service.decrypt("pii", envelope)


# Test 6: Flipped tag byte (end of ciphertext) is detected
def test_flipped_tag_byte_raises(service):
    envelope = service.encrypt("pii", PII)
    envelope["ct"] = flip_byte(envelope["ct"], -1)

    with pytest.raises(DecryptionError):
        service.decrypt("pii", envelope)


# Test 7: Flipped nonce byte is detected
def test_flipped_nonce_byte_raises(service):
    envelope = service.encrypt("pii", PII)
    envelope["nonce"] = flip_byte(envelope["nonce"])

    with pytest.raises(DecryptionError):
        service.decrypt("pii", envelope)


# Test 8: Wrong associated data is detected (ciphertext moved between rows)
def test_wrong_aad_raises(service):
    envelope = service.encrypt("pii", PII, aad=b"voter:demo-001")

    with pytest.raises(DecryptionError):
        service.decrypt("pii", envelope, aad=b"voter:demo-002")


# Test 9: Ciphertext from another purpose is refused
def test_ciphertext_from_other_purpose_raises(service):
    envelope = service.encrypt("pii", PII)

    with pytest.raises(DecryptionError):
        service.decrypt("ballot", envelope)


# Test 10: Another deployment's key cannot decrypt (wrong key)
def test_wrong_key_raises(service):
    other = CryptoService(
        default_registry(), DEFAULT_POLICY, KeyStore.ephemeral()
    )

    envelope = other.encrypt("pii", PII)

    with pytest.raises(DecryptionError):
        service.decrypt("pii", envelope)


# Test 11: Malformed or disallowed envelopes raise DecryptionError
@pytest.mark.parametrize("change", [
    lambda e: e.pop("nonce"),
    lambda e: e.update(extra=1),
    lambda e: e.update(v=2),
    lambda e: e.update(alg="chacha20-poly1305"),
    lambda e: e.update(alg="des"),
    lambda e: e.update(kid="pii.aes-256-gcm.v9"),
    lambda e: e.update(nonce="AAAA"),
    lambda e: e.update(ct="not base64!"),
])
def test_malformed_encryption_envelope_raises(service, change):
    envelope = service.encrypt("pii", PII)
    change(envelope)

    with pytest.raises(DecryptionError):
        service.decrypt("pii", envelope)


# Test 12: Non-dict envelope raises DecryptionError
def test_non_dict_encryption_envelope_raises(service):
    with pytest.raises(DecryptionError):
        service.decrypt("pii", "ciphertext")


# Test 13: Encryption refuses non-bytes and oversized plaintext
def test_encrypt_input_validation(service):
    with pytest.raises(TypeError):
        service.encrypt("pii", "text")

    with pytest.raises(ValueError):
        service.encrypt("pii", b"x" * (1024 * 1024 + 1))


# Test 14: Old AES-GCM data decrypts after switching to ChaCha20
def test_old_ciphertext_decrypts_after_default_change(service):
    old_envelope = service.encrypt("pii", PII)

    migrated = service.with_policy(
        DEFAULT_POLICY.with_default(AEAD, "chacha20-poly1305")
    )
    new_envelope = migrated.encrypt("pii", PII)

    assert new_envelope["alg"] == "chacha20-poly1305"
    assert migrated.decrypt("pii", old_envelope) == PII
    assert migrated.decrypt("pii", new_envelope) == PII


# Test 15: Seal envelope format
def test_seal_envelope_format(service):
    envelope = service.seal("election", BALLOT)

    assert set(envelope) == {
        "alg", "kid", "v", "wrapped_key", "nonce", "ct"
    }
    assert envelope["alg"] == "rsa-oaep-sha256+aes-256-gcm"
    assert envelope["kid"] == "election.rsa-oaep-sha256+aes-256-gcm.v1"
    assert len(base64.b64decode(envelope["wrapped_key"])) == 384


# Test 16: Seal/open round trip
def test_seal_open_round_trip(service):
    envelope = service.seal("election", BALLOT)

    assert service.open("election", envelope) == BALLOT


# Test 17: Tampering with any sealed field is detected
@pytest.mark.parametrize("field", ["wrapped_key", "nonce", "ct"])
def test_flipped_seal_field_raises(service, field):
    envelope = service.seal("election", BALLOT)
    envelope[field] = flip_byte(envelope[field])

    with pytest.raises(DecryptionError):
        service.open("election", envelope)


# Test 18: Changing the kid of a sealed envelope is detected
def test_sealed_kid_change_raises(service):
    envelope = service.seal("election", BALLOT)
    envelope["kid"] = "election.rsa-oaep-sha256+aes-256-gcm.v2"

    with pytest.raises(DecryptionError):
        service.open("election", envelope)


# Test 19: public_key_pem("election") is the sealing key
def test_election_public_key_is_rsa_3072(service):
    pem = service.public_key_pem("election")

    public_key = serialization.load_pem_public_key(pem)

    assert public_key.key_size == 3072


# Test 20: Voter-client seal (Workstream D format) opens on the server
def test_client_side_seal_opens(service):
    public_key = serialization.load_pem_public_key(
        service.public_key_pem("election")
    )
    kid = service.seal("election", b"probe")["kid"]

    # What the voter client does with the `cryptography` library
    data_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    envelope = {
        "alg": "rsa-oaep-sha256+aes-256-gcm",
        "kid": kid,
        "v": 1,
        "wrapped_key": base64.b64encode(public_key.encrypt(
            data_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(
            AESGCM(data_key).encrypt(nonce, BALLOT, kid.encode())
        ).decode(),
    }

    assert service.open("election", envelope) == BALLOT


# Test 21: Public-key-only compartment can seal but not open
def test_public_only_compartment_cannot_open(service):
    public_key = serialization.load_pem_public_key(
        service.public_key_pem("election")
    )
    algorithm = service.factory.for_new("seal")

    public_only = KeyStore()
    public_only.add(
        "election", algorithm, KeyMaterial(public_key=public_key),
        version=1, current=True,
    )
    voter_side = CryptoService(
        default_registry(), DEFAULT_POLICY, public_only
    )

    envelope = voter_side.seal("election", BALLOT)

    assert service.open("election", envelope) == BALLOT

    with pytest.raises(DecryptionError):
        voter_side.open("election", envelope)


# Test 22: Short RSA keys are refused for sealing
def test_short_rsa_key_is_refused():
    short = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    algorithm = default_registry().get("seal", "rsa-oaep-sha256+aes-256-gcm")

    with pytest.raises(ValueError):
        KeyStore().add(
            "election", algorithm,
            KeyMaterial(private_key=short, public_key=short.public_key()),
            version=1,
        )


# Test 23: Wrong-size AES key is refused
def test_wrong_size_aes_key_is_refused():
    with pytest.raises(ValueError):
        KeyStore().add(
            "pii", AES_256_GCM, KeyMaterial(secret=os.urandom(16)), 1
        )


# Test 24: Workstream E provider interface (field_crypto, SR-13)
def test_service_satisfies_field_crypto_provider(service):
    for method in ("encrypt", "decrypt"):
        assert callable(getattr(service, method, None))

    envelope = service.encrypt("pii", PII)
    stored = json.dumps(envelope, sort_keys=True, separators=(",", ":"))

    assert service.decrypt("pii", json.loads(stored)) == PII


# Test 25: Module-level crypto passes E's provider check before configuration
def test_module_crypto_is_a_field_crypto_provider(monkeypatch, service):
    monkeypatch.delenv("EVP_CRYPTO_DEV_KEYS", raising=False)
    crypto_agility.configure(None)

    try:
        for method in ("encrypt", "decrypt"):
            assert callable(getattr(crypto_agility.crypto, method, None))

        crypto_agility.configure(service)
        envelope = crypto_agility.crypto.encrypt("pii", PII)

        assert crypto_agility.crypto.decrypt("pii", envelope) == PII

    finally:
        crypto_agility.configure(None)
