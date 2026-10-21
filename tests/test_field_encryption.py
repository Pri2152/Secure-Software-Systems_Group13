
"""
SR-13 tests for field encryption with the real app models.

Uses Workstream A's application, models and record routes,
with Workstream B's crypto_agility service (development
keys from the shared pii_provider fixture):

- address_records.address_text is stored as JSON ciphertext
- the ORM returns the plaintext
- a single flipped ciphertext byte makes the read fail, and
  the record route answers with a generic error only
- start-up without the PII key refuses to run
- every envelope records the key version (kid)
"""

import base64
import json

import pytest
from sqlalchemy import text

import app as application
from crypto_agility import DecryptionError
from crypto_agility.algorithms import AEAD
from crypto_agility.keys import parse_kid
from records import AddressRecord, EnrolmentRecord, db
from test_main_integration import HTTPS_URL, environment, login  # noqa: F401
from test_platform_pii_encryption import run_runtime


ADDRESS = "Original Address One"
OTHER_ADDRESS = "Original Address Two"
EMAIL = "voter1@example.test"


def stored(column, table, record_id):
    with application.app.app_context():
        return db.session.execute(
            text(f"SELECT {column} FROM {table} WHERE id = :id"),
            {"id": record_id},
        ).scalar_one()


def store_raw(column, table, record_id, value):
    with application.app.app_context():
        db.session.execute(
            text(f"UPDATE {table} SET {column} = :value WHERE id = :id"),
            {"value": value, "id": record_id},
        )
        db.session.commit()


def flip_one_byte(raw_envelope, position=0):
    envelope = json.loads(raw_envelope)
    ciphertext = bytearray(base64.b64decode(envelope["ct"]))
    ciphertext[position] ^= 0x01
    envelope["ct"] = base64.b64encode(bytes(ciphertext)).decode("ascii")

    return json.dumps(envelope)


# Stored ciphertext

def test_raw_select_returns_json_ciphertext(environment):  # noqa: F811
    raw = stored("address_text", "address_records", 201)
    envelope = json.loads(raw)

    assert set(envelope) == {"alg", "kid", "v", "nonce", "ct"}
    assert envelope["alg"] == "aes-256-gcm"
    assert ADDRESS not in raw
    assert "Original" not in raw


def test_every_pii_value_is_ciphertext(environment):  # noqa: F811
    with application.app.app_context():
        rows = db.session.execute(text(
            "SELECT address_text FROM address_records "
            "UNION ALL SELECT contact_email FROM enrolment_records"
        )).scalars().all()

    assert len(rows) == 4

    for raw in rows:
        assert json.loads(raw)["ct"]
        for plaintext in (ADDRESS, OTHER_ADDRESS, EMAIL, "@example.test"):
            assert plaintext not in raw


def test_orm_returns_plaintext(environment):  # noqa: F811
    with application.app.app_context():
        assert db.session.get(AddressRecord, 201).address_text == ADDRESS
        assert db.session.get(EnrolmentRecord, 101).contact_email == EMAIL


def test_route_returns_plaintext_to_owner(environment):  # noqa: F811
    client, now = environment
    assert login(client, now).status_code == 200

    response = client.get("/records/addresses/201", base_url=HTTPS_URL)

    assert response.status_code == 200
    assert response.get_json() == {"id": 201, "address_text": ADDRESS}


# Tampering

@pytest.mark.parametrize("position", [0, -1])
def test_flipped_ciphertext_byte_fails_to_read(environment, position):  # noqa: F811
    raw = stored("address_text", "address_records", 201)
    store_raw("address_text", "address_records", 201,
              flip_one_byte(raw, position))

    with application.app.app_context():
        with pytest.raises(DecryptionError):
            db.session.get(AddressRecord, 201).address_text


def test_tampered_nonce_fails_to_read(environment):  # noqa: F811
    envelope = json.loads(stored("address_text", "address_records", 201))
    nonce = bytearray(base64.b64decode(envelope["nonce"]))
    nonce[0] ^= 0x01
    envelope["nonce"] = base64.b64encode(bytes(nonce)).decode("ascii")
    store_raw("address_text", "address_records", 201, json.dumps(envelope))

    with application.app.app_context():
        with pytest.raises(DecryptionError):
            db.session.get(AddressRecord, 201).address_text


def test_known_limit_ciphertext_moved_between_rows_still_decrypts(
    environment  # noqa: F811
):
    # Documents a known limit: the envelope is bound to the key ID
    # and purpose, not to its row, so someone with write access to
    # the database could copy one voter's ciphertext into another
    # row. A voter still only reaches rows they own (SR-05).
    other = stored("address_text", "address_records", 202)
    store_raw("address_text", "address_records", 201, other)

    with application.app.app_context():
        assert db.session.get(AddressRecord, 201).address_text == OTHER_ADDRESS


@pytest.fixture
def production_errors(monkeypatch):
    """Answer errors the way the deployed app does (no TESTING)."""

    monkeypatch.setitem(application.app.config, "TESTING", False)
    monkeypatch.setitem(application.app.config, "PROPAGATE_EXCEPTIONS", False)
    monkeypatch.setitem(application.app.config, "DEBUG", False)


def test_route_gives_generic_error_on_tampered_record(
    environment, production_errors  # noqa: F811
):
    client, now = environment
    assert login(client, now).status_code == 200

    raw = stored("address_text", "address_records", 201)
    tampered = flip_one_byte(raw)
    store_raw("address_text", "address_records", 201, tampered)

    response = client.get("/records/addresses/201", base_url=HTTPS_URL)
    body = response.get_data(as_text=True)

    assert response.status_code == 500
    assert response.get_json(silent=True) in (
        None, {"error": "Internal server error"}
    )

    for leak in (ADDRESS, "Original", tampered, json.loads(tampered)["ct"],
                 "Traceback", "DecryptionError", "Decryption failed",
                 "crypto_agility", "records.py", "pii.aes-256-gcm",
                 "address_text", "File \""):
        assert leak not in body, leak


def test_tampered_record_does_not_affect_other_records(
    environment, production_errors  # noqa: F811
):
    client, now = environment
    assert login(client, now).status_code == 200

    raw = stored("address_text", "address_records", 201)
    store_raw("address_text", "address_records", 201, flip_one_byte(raw))

    response = client.get("/records/enrolments/101", base_url=HTTPS_URL)

    assert response.status_code == 200
    assert response.get_json()["contact_email"] == EMAIL


# Start-up

def test_start_up_without_pii_key_refuses_to_run():
    result = run_runtime()

    assert result.returncode != 0
    assert "PII encryption key is not available" in result.stderr


def test_start_up_with_pii_key_runs():
    result = run_runtime(EVP_CRYPTO_DEV_KEYS="1")

    assert result.returncode == 0, result.stderr


# Key version

def test_envelope_records_key_version(environment):  # noqa: F811
    for column, table, record_id in (
        ("address_text", "address_records", 201),
        ("contact_email", "enrolment_records", 101),
    ):
        envelope = json.loads(stored(column, table, record_id))
        purpose, alg, version = parse_kid(envelope["kid"])

        assert (purpose, alg, version) == ("pii", "aes-256-gcm", 1)
        assert envelope["v"] == 1


def test_new_key_version_is_recorded_and_old_rows_still_read(
    environment, pii_provider  # noqa: F811
):
    algorithm = pii_provider.factory.for_new(AEAD)
    pii_provider.keys.rotate("pii", algorithm)

    with application.app.app_context():
        record = db.session.get(AddressRecord, 202)
        record.address_text = "New Address Two"
        db.session.commit()

    old = json.loads(stored("address_text", "address_records", 201))
    new = json.loads(stored("address_text", "address_records", 202))

    assert old["kid"] == "pii.aes-256-gcm.v1"
    assert new["kid"] == "pii.aes-256-gcm.v2"

    with application.app.app_context():
        assert db.session.get(AddressRecord, 201).address_text == ADDRESS
        assert (
            db.session.get(AddressRecord, 202).address_text
            == "New Address Two"
        )
