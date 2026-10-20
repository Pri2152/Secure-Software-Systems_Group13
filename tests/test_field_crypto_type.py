
"""
SR-13 tests for the EncryptedText column type.

Uses its own in-memory SQLite engine and declarative
base, never the app's db, and a test-only AES-256-GCM
provider in place of Workstream B's crypto service.
"""

import ast
import json
from pathlib import Path

import pytest
from sqlalchemy import Integer, String, Text, create_engine, select, text
from sqlalchemy.exc import StatementError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from aesgcm_test_provider import AesGcmTestProvider
from platform_security import field_crypto
from platform_security.field_crypto import (
    CryptoProviderNotConfigured,
    EncryptedText,
    FieldCryptoError,
    get_crypto_provider,
    set_crypto_provider,
)


PLAINTEXT = "12 Example Street, Melbourne VIC 3000"


class Base(DeclarativeBase):
    pass


class Person(Base):
    __tablename__ = "people"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    label: Mapped[str] = mapped_column(String(32), default="")
    address: Mapped[str | None] = mapped_column(EncryptedText())
    ballot_note: Mapped[str | None] = mapped_column(
        EncryptedText("ballot")
    )


@pytest.fixture(autouse=True)
def no_provider_after_test():
    set_crypto_provider(None)
    yield
    set_crypto_provider(None)


@pytest.fixture
def provider():
    provider = AesGcmTestProvider()
    set_crypto_provider(provider)

    return provider


@pytest.fixture
def engine():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)

    yield engine

    engine.dispose()


def save(engine, **fields):
    with Session(engine) as session:
        person = Person(**fields)
        session.add(person)
        session.commit()

        return person.id


def load(engine, person_id):
    with Session(engine) as session:
        return session.get(Person, person_id)


def raw_column(engine, column, person_id):
    with engine.connect() as connection:
        return connection.execute(
            text(f"SELECT {column} FROM people WHERE id = :id"),
            {"id": person_id},
        ).scalar_one()


# Type definition

def test_type_is_text_with_pii_default_and_cache_ok():
    column_type = EncryptedText()

    assert EncryptedText.impl is Text
    assert EncryptedText.cache_ok is True
    assert column_type.purpose == "pii"
    assert EncryptedText("ballot").purpose == "ballot"


@pytest.mark.parametrize("purpose", ["", None, 1])
def test_invalid_purpose_is_rejected(purpose):
    with pytest.raises(ValueError):
        EncryptedText(purpose)


def test_module_has_sr13_docstring():
    module = ast.parse(Path(field_crypto.__file__).read_text())
    docstring = ast.get_docstring(module)

    assert docstring.startswith("SR-13")
    assert "Security controls:" in docstring


def test_module_imports_no_crypto_library():
    module = ast.parse(Path(field_crypto.__file__).read_text())
    imported = set()

    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module)

    for name in imported:
        root = name.split(".")[0]
        assert root not in {"cryptography", "Crypto", "nacl", "hashlib",
                            "hmac", "secrets", "os"}, name


# Required behaviour

def test_round_trip(provider, engine):
    person_id = save(engine, address=PLAINTEXT)

    assert load(engine, person_id).address == PLAINTEXT


def test_raw_value_is_json_envelope_without_plaintext(provider, engine):
    person_id = save(engine, address=PLAINTEXT)

    raw = raw_column(engine, "address", person_id)
    envelope = json.loads(raw)

    assert set(envelope) == {"alg", "kid", "v", "nonce", "ct"}
    assert PLAINTEXT not in raw
    assert "Example" not in raw
    assert "Melbourne" not in raw


def test_same_text_encrypts_differently_each_time(provider, engine):
    first = save(engine, address=PLAINTEXT)
    second = save(engine, address=PLAINTEXT)

    first_envelope = json.loads(raw_column(engine, "address", first))
    second_envelope = json.loads(raw_column(engine, "address", second))

    assert first_envelope["nonce"] != second_envelope["nonce"]
    assert first_envelope["ct"] != second_envelope["ct"]


def test_missing_provider_raises_on_write_and_stores_nothing(engine):
    with pytest.raises(StatementError) as error:
        save(engine, address=PLAINTEXT)

    assert isinstance(error.value.orig, CryptoProviderNotConfigured)

    with engine.connect() as connection:
        count = connection.execute(
            text("SELECT COUNT(*) FROM people")
        ).scalar_one()

    assert count == 0


def test_missing_provider_raises_on_read(provider, engine):
    person_id = save(engine, address=PLAINTEXT)

    set_crypto_provider(None)

    with pytest.raises(CryptoProviderNotConfigured):
        load(engine, person_id)


def test_get_crypto_provider_fails_closed():
    with pytest.raises(CryptoProviderNotConfigured):
        get_crypto_provider()


# Extra safety checks

def test_none_stays_none(provider, engine):
    person_id = save(engine, address=None)

    assert raw_column(engine, "address", person_id) is None
    assert load(engine, person_id).address is None


def test_empty_string_is_still_encrypted(provider, engine):
    person_id = save(engine, address="")

    assert json.loads(raw_column(engine, "address", person_id))["ct"]
    assert load(engine, person_id).address == ""


def test_unicode_round_trip(provider, engine):
    value = "Ōtautahi — 東京 ✓"
    person_id = save(engine, address=value)

    assert load(engine, person_id).address == value


def test_purpose_is_passed_to_provider(engine):
    calls = []

    class Recording(AesGcmTestProvider):
        def encrypt(self, purpose, plaintext_bytes):
            calls.append(purpose)
            return super().encrypt(purpose, plaintext_bytes)

    set_crypto_provider(Recording())
    save(engine, address="a", ballot_note="b")

    assert sorted(calls) == ["ballot", "pii"]


def test_ciphertext_cannot_be_moved_to_other_purpose(provider, engine):
    person_id = save(engine, address=PLAINTEXT)
    envelope = raw_column(engine, "address", person_id)

    with engine.begin() as connection:
        connection.execute(
            text("UPDATE people SET ballot_note = :value WHERE id = :id"),
            {"value": envelope, "id": person_id},
        )

    with pytest.raises(Exception):
        load(engine, person_id)


def test_tampered_ciphertext_is_rejected(provider, engine):
    person_id = save(engine, address=PLAINTEXT)
    envelope = json.loads(raw_column(engine, "address", person_id))
    flipped = "AAAA" if envelope["ct"][-4:] != "AAAA" else "BBBB"
    envelope["ct"] = envelope["ct"][:-4] + flipped

    with engine.begin() as connection:
        connection.execute(
            text("UPDATE people SET address = :value WHERE id = :id"),
            {"value": json.dumps(envelope), "id": person_id},
        )

    with pytest.raises(Exception):
        load(engine, person_id)


def test_plaintext_planted_in_database_is_not_returned(provider, engine):
    with engine.begin() as connection:
        connection.execute(
            text("INSERT INTO people (id, label, address) "
                 "VALUES (1, '', :value)"),
            {"value": PLAINTEXT},
        )

    with pytest.raises(FieldCryptoError) as error:
        load(engine, 1)

    assert PLAINTEXT not in str(error.value)


def test_non_text_value_is_rejected(provider, engine):
    with pytest.raises(StatementError) as error:
        save(engine, address=12345)

    assert isinstance(error.value.orig, FieldCryptoError)


@pytest.mark.parametrize("bad_envelope", [None, {}, "text", b"bytes",
                                          {"ct": b"\x00"}])
def test_invalid_envelope_from_provider_is_rejected(engine, bad_envelope):
    class BadProvider:
        def encrypt(self, purpose, plaintext_bytes):
            return bad_envelope

        def decrypt(self, purpose, envelope):
            return b""

    set_crypto_provider(BadProvider())

    with pytest.raises(StatementError) as error:
        save(engine, address=PLAINTEXT)

    assert isinstance(error.value.orig, FieldCryptoError)
    assert PLAINTEXT not in str(error.value.orig)


def test_hide_parameters_keeps_plaintext_out_of_errors():
    # SQLAlchemy's own StatementError text includes bound
    # parameters (the plaintext) unless the engine hides them.
    engine = create_engine("sqlite://", hide_parameters=True)
    Base.metadata.create_all(engine)

    with pytest.raises(StatementError) as error:
        save(engine, address=PLAINTEXT)

    assert isinstance(error.value.orig, CryptoProviderNotConfigured)
    assert PLAINTEXT not in str(error.value)

    engine.dispose()


def test_non_bytes_plaintext_from_provider_is_rejected(provider, engine):
    person_id = save(engine, address=PLAINTEXT)

    class StringProvider(AesGcmTestProvider):
        def decrypt(self, purpose, envelope):
            return PLAINTEXT

    set_crypto_provider(StringProvider())

    with pytest.raises(FieldCryptoError):
        load(engine, person_id)


@pytest.mark.parametrize("bad_provider", [object(), "provider", 42])
def test_provider_without_interface_is_refused(bad_provider):
    with pytest.raises(TypeError):
        set_crypto_provider(bad_provider)

    with pytest.raises(CryptoProviderNotConfigured):
        get_crypto_provider()


def test_query_on_other_columns_still_works(provider, engine):
    save(engine, label="first", address=PLAINTEXT)

    with Session(engine) as session:
        person = session.scalars(
            select(Person).where(Person.label == "first")
        ).one()

    assert person.address == PLAINTEXT
