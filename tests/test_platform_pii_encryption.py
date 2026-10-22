
"""
SR-13 tests: voter PII encrypted at rest through
Workstream B's crypto_agility service.

- contact_email and address_text are EncryptedText('pii')
- SR-05 ownership still filters on plaintext id and owner
- voter-access start-up registers the provider and refuses
  to start without a usable PII key; importing app.py
  needs no keys
- voter-access mounts only its own manifest and the PII key
"""

import base64
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml
from flask import Flask
from sqlalchemy import text

import crypto_agility
from platform_security.crypto_setup import install_pii_provider
from platform_security.field_crypto import (
    CryptoProviderNotConfigured,
    EncryptedText,
    get_crypto_provider,
    set_crypto_provider,
)
from records import AddressRecord, EnrolmentRecord, db, find_owned_record
from test_platform_gateway_trust import subprocess_env


REPO_ROOT = Path(__file__).resolve().parent.parent
MAKE_KEYS = REPO_ROOT / "deploy" / "scripts" / "make_keys.py"
COMPOSE_PATH = REPO_ROOT / "deploy" / "docker-compose.yml"

DEMO_EMAIL = "demo-voter@example.test"
DEMO_ADDRESS = "Synthetic Test Address"


# Model columns

@pytest.mark.parametrize("model, column", [
    (EnrolmentRecord, "contact_email"),
    (AddressRecord, "address_text"),
])
def test_pii_columns_are_encrypted_and_required(model, column):
    field = model.__table__.columns[column]

    assert isinstance(field.type, EncryptedText)
    assert field.type.purpose == "pii"
    assert field.nullable is False


@pytest.mark.parametrize("model", [EnrolmentRecord, AddressRecord])
def test_ownership_columns_stay_plaintext(model):
    for column in ("id", "owner_voter_id"):
        assert not isinstance(
            model.__table__.columns[column].type, EncryptedText
        )


# Records stored encrypted; SR-05 unchanged

@pytest.fixture
def records_app(pii_provider):
    test_app = Flask(__name__)
    test_app.config.update(
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )
    db.init_app(test_app)

    with test_app.app_context():
        db.create_all()
        db.session.add_all([
            EnrolmentRecord(id=1, owner_voter_id="voter-001",
                            enrolment_status="enrolled",
                            contact_email="one@example.test"),
            AddressRecord(id=2, owner_voter_id="voter-001",
                          address_text="1 First Street"),
        ])
        db.session.commit()
        db.session.expire_all()

        yield test_app

        db.session.remove()
        db.drop_all()


def raw(table, column):
    return db.session.execute(
        text(f"SELECT {column} FROM {table}")
    ).scalar_one()


def test_database_holds_only_envelopes(records_app):
    for table, column, plaintext in (
        ("enrolment_records", "contact_email", "one@example.test"),
        ("address_records", "address_text", "1 First Street"),
    ):
        stored = raw(table, column)
        envelope = json.loads(stored)

        assert envelope["kid"] == "pii.aes-256-gcm.v1"
        assert plaintext not in stored


def test_owner_reads_decrypted_records(records_app):
    record = find_owned_record(EnrolmentRecord, 1, "voter-001")
    address = find_owned_record(AddressRecord, 2, "voter-001")

    assert record.contact_email == "one@example.test"
    assert address.address_text == "1 First Street"


def test_other_voter_still_gets_nothing(records_app):
    assert find_owned_record(EnrolmentRecord, 1, "voter-002") is None
    assert find_owned_record(AddressRecord, 2, "voter-002") is None


def test_updated_address_is_encrypted(records_app):
    address = find_owned_record(AddressRecord, 2, "voter-001")
    address.address_text = "2 Second Street"
    db.session.commit()

    assert "Second" not in raw("address_records", "address_text")


# install_pii_provider

@pytest.fixture
def clean_crypto():
    crypto_agility.configure(None)
    set_crypto_provider(None)

    yield

    crypto_agility.configure(None)
    set_crypto_provider(None)


@pytest.mark.no_pii_provider
def test_install_registers_crypto_agility(clean_crypto):
    install_pii_provider({"EVP_CRYPTO_DEV_KEYS": "1"})

    assert get_crypto_provider() is crypto_agility.crypto

    column = EncryptedText("pii")
    stored = column.process_bind_param("someone@example.test", None)

    assert "someone" not in stored
    assert column.process_result_value(stored, None) == "someone@example.test"


@pytest.mark.no_pii_provider
def test_install_without_keys_fails_closed(clean_crypto):
    with pytest.raises(CryptoProviderNotConfigured, match="EVP_KEY_DIR"):
        install_pii_provider({})

    with pytest.raises(CryptoProviderNotConfigured):
        get_crypto_provider()


def write_key_dir(folder, entries):
    folder.mkdir()
    for name, content in entries.items():
        (folder / name).write_text(content)


@pytest.mark.no_pii_provider
def test_install_without_pii_key_fails_closed(clean_crypto, tmp_path):
    keys = tmp_path / "keys"
    write_key_dir(keys, {
        "audit_hmac_v1": base64.b64encode(os.urandom(32)).decode(),
        "manifest.json": json.dumps({"keys": [{
            "kid": "audit.hmac-sha256.v1", "purpose": "audit",
            "family": "mac", "alg": "hmac-sha256",
            "file": "audit_hmac_v1", "current": True,
        }]}),
    })

    with pytest.raises(CryptoProviderNotConfigured):
        install_pii_provider({"EVP_KEY_DIR": str(keys)})

    with pytest.raises(CryptoProviderNotConfigured):
        get_crypto_provider()


@pytest.mark.no_pii_provider
def test_installing_is_not_done_on_import():
    result = subprocess.run(
        [sys.executable, "-c",
         "import app, records; "
         "from platform_security.field_crypto import get_crypto_provider\n"
         "try:\n    get_crypto_provider()\n    print('provider')\n"
         "except Exception:\n    print('none')"],
        cwd=REPO_ROOT,
        env=subprocess_env(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] == "none"


# voter-access start-up (gateway_runtime), in a fresh interpreter

RUNTIME_PROBE = textwrap.dedent("""
    import json, pathlib

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
    from records import db, EnrolmentRecord, AddressRecord
    from sqlalchemy import text

    with gateway_runtime.app.app_context():
        print(json.dumps({
            "raw_email": db.session.execute(
                text("SELECT contact_email FROM enrolment_records")
            ).scalar_one(),
            "raw_address": db.session.execute(
                text("SELECT address_text FROM address_records")
            ).scalar_one(),
            "email": db.session.get(EnrolmentRecord, 701).contact_email,
            "address": db.session.get(AddressRecord, 801).address_text,
        }))
""")


def run_runtime(**env):
    return subprocess.run(
        [sys.executable, "-c", RUNTIME_PROBE],
        cwd=REPO_ROOT,
        env=subprocess_env(EVP_LOCAL_LAB="1", **env),
        capture_output=True,
        text=True,
    )


def load_make_keys():
    spec = importlib.util.spec_from_file_location("make_keys", MAKE_KEYS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


@pytest.fixture
def voter_access_keys(tmp_path):
    """The key folder exactly as Compose mounts it for voter-access."""

    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "pii_key_v1").write_text(os.urandom(32).hex())
    load_make_keys().make_keys(secrets, report=lambda line: None)

    mounted = tmp_path / "evp_keys"
    mounted.mkdir()
    shutil.copy(secrets / "keys" / "manifest-voter-access.json",
                mounted / "manifest.json")
    shutil.copy(secrets / "keys" / "pii_key_v1", mounted / "pii_key_v1")

    return mounted


def test_runtime_refuses_to_start_without_keys():
    result = run_runtime()

    assert result.returncode != 0
    assert "PII encryption key is not available" in result.stderr


def test_runtime_refuses_to_start_with_empty_key_dir(tmp_path):
    empty = tmp_path / "keys"
    empty.mkdir()

    result = run_runtime(EVP_KEY_DIR=str(empty))

    assert result.returncode != 0
    assert "PII encryption key is not available" in result.stderr


def test_runtime_starts_with_voter_access_keys(voter_access_keys):
    result = run_runtime(EVP_KEY_DIR=str(voter_access_keys))

    assert result.returncode == 0, result.stderr

    probe = json.loads(result.stdout.splitlines()[-1])

    assert probe["email"] == DEMO_EMAIL
    assert probe["address"] == DEMO_ADDRESS
    assert DEMO_EMAIL not in probe["raw_email"]
    assert DEMO_ADDRESS not in probe["raw_address"]
    assert json.loads(probe["raw_email"])["kid"] == "pii.aes-256-gcm.v1"

    key = (voter_access_keys / "pii_key_v1").read_text().strip()

    assert key not in result.stdout + result.stderr


def test_runtime_starts_with_development_keys():
    result = run_runtime(EVP_CRYPTO_DEV_KEYS="1")

    assert result.returncode == 0, result.stderr


# Keys and Compose

def test_voter_access_manifest_holds_only_the_pii_key():
    assert load_make_keys().COMPARTMENT_KEYS["voter-access"] == (
        "pii.aes-256-gcm.v1",
    )


@pytest.mark.parametrize("name", ["voter-access-1", "voter-access-2"])
def test_voter_access_mounts_only_its_manifest_and_pii_key(name):
    compose = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    service = compose["services"][name]
    key_dir = service["environment"]["EVP_KEY_DIR"]

    assert key_dir == "/run/secrets/evp_keys"

    mounts = {
        secret["target"]: secret["source"]
        for secret in service["secrets"]
        if isinstance(secret, dict) and secret["target"].startswith(key_dir)
    }

    assert mounts == {
        f"{key_dir}/manifest.json": "voter_access_keys_manifest",
        f"{key_dir}/pii_key_v1": "key_pii_v1",
    }
    assert compose["secrets"]["voter_access_keys_manifest"]["file"] == (
        "./secrets/keys/manifest-voter-access.json"
    )
    assert "audit" not in str(service["secrets"])


def test_schema_stores_envelopes_as_text():
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "deploy" / "scripts" / "schema_sql.py"),
         "create", "enrolment_records"],
        capture_output=True, text=True, check=True,
    )

    assert "contact_email TEXT NOT NULL" in result.stdout
