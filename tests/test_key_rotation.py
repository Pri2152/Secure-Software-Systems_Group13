
"""
SR-13 / SR-14 tests for deploy/scripts/rotate_pii_key.py.

Uses the real EnrolmentRecord / AddressRecord models on a
temporary SQLite database, and a key folder built by
make_keys.py exactly as make_secrets.sh builds it.
"""

import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from crypto_agility import build_service
from platform_security.field_crypto import set_crypto_provider
from records import AddressRecord, EnrolmentRecord, db


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "deploy" / "scripts"
README_PATH = REPO_ROOT / "deploy" / "README.md"

V1 = "pii.aes-256-gcm.v1"
V2 = "pii.aes-256-gcm.v2"
ROWS = 7


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


rotation = load("rotate_pii_key")


@pytest.fixture
def key_dir(tmp_path):
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "pii_key_v1").write_text(os.urandom(32).hex())
    load("make_keys").make_keys(secrets_dir, report=lambda line: None)

    return secrets_dir / "keys"


def emails():
    return [f"voter{i}@example.test" for i in range(ROWS)]


def addresses():
    return [f"{i} Synthetic Street" for i in range(ROWS)]


@pytest.fixture
def engine(tmp_path, key_dir):
    """A database with rows written under pii v1."""

    engine = create_engine(f"sqlite:///{tmp_path / 'identity.db'}")
    db.metadata.create_all(
        engine,
        tables=[EnrolmentRecord.__table__, AddressRecord.__table__],
    )

    set_crypto_provider(build_service(key_dir=str(key_dir)))

    with Session(engine) as session:
        for i in range(ROWS):
            session.add(EnrolmentRecord(
                id=i + 1, owner_voter_id=f"voter-{i}",
                enrolment_status="enrolled", contact_email=emails()[i],
            ))
            session.add(AddressRecord(
                id=i + 1, owner_voter_id=f"voter-{i}",
                address_text=addresses()[i],
            ))
        session.commit()

    set_crypto_provider(None)

    yield engine

    set_crypto_provider(None)
    engine.dispose()


def raw_values(engine):
    with engine.connect() as connection:
        return (
            connection.execute(text(
                "SELECT contact_email FROM enrolment_records ORDER BY id"
            )).scalars().all()
            + connection.execute(text(
                "SELECT address_text FROM address_records ORDER BY id"
            )).scalars().all()
        )


def kids(engine):
    return [json.loads(value)["kid"] for value in raw_values(engine)]


def read_all(engine, key_dir):
    """Decrypt every row with a service built from the key folder."""

    set_crypto_provider(build_service(key_dir=str(key_dir)))

    try:
        with Session(engine) as session:
            return (
                [r.contact_email for r in
                 session.query(EnrolmentRecord).order_by(EnrolmentRecord.id)],
                [r.address_text for r in
                 session.query(AddressRecord).order_by(AddressRecord.id)],
            )
    finally:
        set_crypto_provider(None)


def manifest(key_dir, name="manifest.json"):
    return json.loads((key_dir / name).read_text())


def current_pii(key_dir, name="manifest.json"):
    return [entry["kid"] for entry in manifest(key_dir, name)["keys"]
            if entry["purpose"] == "pii" and entry["current"]]


def rotate(engine, key_dir, **options):
    options.setdefault("generate", True)
    options.setdefault("batch_size", 3)
    options.setdefault("report", lambda line: None)

    return rotation.rotate(engine, key_dir, **options)


# Required behaviour

def test_rows_written_under_v1_are_readable_after_rotation(engine, key_dir):
    assert set(kids(engine)) == {V1}

    result = rotate(engine, key_dir)

    assert result == {"rows": 2 * ROWS, "changed": 2 * ROWS, "kid": V2,
                      "dry_run": False}
    assert set(kids(engine)) == {V2}
    assert read_all(engine, key_dir) == (emails(), addresses())


def test_new_writes_use_v2(engine, key_dir):
    rotate(engine, key_dir)

    set_crypto_provider(build_service(key_dir=str(key_dir)))
    with Session(engine) as session:
        session.add(AddressRecord(id=100, owner_voter_id="voter-new",
                                  address_text="New Street"))
        session.commit()
    set_crypto_provider(None)

    with engine.connect() as connection:
        stored = connection.execute(text(
            "SELECT address_text FROM address_records WHERE id = 100"
        )).scalar_one()

    assert json.loads(stored)["kid"] == V2
    assert current_pii(key_dir) == [V2]


class FailingService:
    """Wraps the new-key service and fails on the Nth encryption."""

    def __init__(self, service, fail_on):
        self.service = service
        self.calls = 0
        self.fail_on = fail_on

    def encrypt(self, purpose, plaintext):
        self.calls += 1
        if self.calls == self.fail_on:
            raise RuntimeError("simulated crash")
        return self.service.encrypt(purpose, plaintext)

    def decrypt(self, purpose, envelope):
        return self.service.decrypt(purpose, envelope)


def test_failure_halfway_leaves_every_row_readable(engine, key_dir, monkeypatch):
    real = rotation.new_key_service
    monkeypatch.setattr(
        rotation, "new_key_service",
        lambda secret, version: FailingService(real(secret, version), 9),
    )

    with pytest.raises(RuntimeError, match="simulated crash"):
        rotate(engine, key_dir)

    # Batches of 3: the first table's batches (3+3+1) committed; the
    # 9th encryption fails inside the second table's first batch,
    # which rolls back as a whole.
    emails_kids, addresses_kids = kids(engine)[:ROWS], kids(engine)[ROWS:]

    assert sorted([emails_kids, addresses_kids]) == [[V1] * ROWS, [V2] * ROWS]

    # Still on v1 for new writes, v2 listed so both decrypt.
    assert current_pii(key_dir) == [V1]
    assert read_all(engine, key_dir) == (emails(), addresses())

    # Running again finishes the job.
    monkeypatch.setattr(rotation, "new_key_service", real)
    result = rotate(engine, key_dir, generate=False)

    assert result["changed"] == ROWS
    assert set(kids(engine)) == {V2}
    assert read_all(engine, key_dir) == (emails(), addresses())


@pytest.mark.parametrize("fail_on", [1, 3, 4, 2 * ROWS])
def test_failure_at_any_point_leaves_rows_readable(engine, key_dir,
                                                   monkeypatch, fail_on):
    real = rotation.new_key_service
    monkeypatch.setattr(
        rotation, "new_key_service",
        lambda secret, version: FailingService(real(secret, version), fail_on),
    )

    with pytest.raises(RuntimeError):
        rotate(engine, key_dir)

    assert read_all(engine, key_dir) == (emails(), addresses())
    assert current_pii(key_dir) == [V1]


def test_failed_verification_keeps_v1_current(engine, key_dir, monkeypatch):
    def broken_verify(*args):
        raise rotation.RotationError("check failed")

    monkeypatch.setattr(rotation, "verify", broken_verify)

    with pytest.raises(rotation.RotationError):
        rotate(engine, key_dir)

    assert current_pii(key_dir) == [V1]
    assert read_all(engine, key_dir) == (emails(), addresses())


def key_service(key_dir, version):
    secret = bytes.fromhex(
        (key_dir / f"pii_key_v{version}").read_text().strip()
    )
    return rotation.new_key_service(secret, version)


def test_verify_rejects_a_row_left_on_the_old_key(engine, key_dir):
    rotate(engine, key_dir)
    left_behind = json.dumps(key_service(key_dir, 1).encrypt("pii", b"old"))

    with engine.begin() as connection:
        connection.execute(text(
            "UPDATE address_records SET address_text = :value WHERE id = 1"
        ), {"value": left_behind})

    with pytest.raises(rotation.RotationError, match="old key"):
        rotation.verify(engine, key_service(key_dir, 2), V2,
                        rotation.encrypted_columns())


# Old key, dry run, manifests

def test_old_key_is_kept(engine, key_dir):
    rotate(engine, key_dir)

    assert (key_dir / "pii_key_v1").is_file()
    assert V1 in [entry["kid"] for entry in manifest(key_dir)["keys"]]


def test_every_pii_manifest_is_updated(engine, key_dir):
    rotate(engine, key_dir)

    for name in ("manifest.json", "manifest-voter-access.json",
                 "manifest-admin-audit.json"):
        assert current_pii(key_dir, name) == [V2], name
        assert stat.S_IMODE((key_dir / name).stat().st_mode) == 0o600

    assert stat.S_IMODE((key_dir / "pii_key_v2").stat().st_mode) == 0o600


def test_dry_run_changes_nothing(engine, key_dir):
    before_rows = raw_values(engine)
    before_files = {path.name: path.read_bytes() for path in key_dir.iterdir()}

    result = rotate(engine, key_dir, dry_run=True)

    assert result == {"rows": 2 * ROWS, "kid": V2, "dry_run": True}
    assert raw_values(engine) == before_rows
    assert {path.name: path.read_bytes()
            for path in key_dir.iterdir()} == before_files


def test_missing_new_key_is_refused_without_generate(engine, key_dir):
    before = raw_values(engine)

    with pytest.raises(rotation.RotationError, match="pii_key_v2"):
        rotate(engine, key_dir, generate=False)

    assert raw_values(engine) == before


def test_reused_old_key_is_refused(engine, key_dir):
    (key_dir / "pii_key_v2").write_text((key_dir / "pii_key_v1").read_text())

    with pytest.raises(rotation.RotationError, match="repeats"):
        rotate(engine, key_dir, generate=False)

    assert set(kids(engine)) == {V1}


def test_encrypted_columns_are_found_from_the_models():
    found = {(table.name, key.name, column.name)
             for table, key, column in rotation.encrypted_columns()}

    assert found == {
        ("enrolment_records", "id", "contact_email"),
        ("address_records", "id", "address_text"),
    }


# Audit

def test_key_rotated_is_recorded_in_admin_stream(engine, key_dir):
    from audit.events import validate_event

    events = []

    def record_event(event_type, **fields):
        validate_event(event_type, fields["stream"], fields["actor_type"],
                       fields["actor_id"], fields["outcome"], None)
        events.append((event_type, fields))

    rotate(engine, key_dir, record_event=record_event)

    assert events == [("KEY_ROTATED", {
        "stream": "admin", "actor_type": "system",
        "actor_id": "rotate_pii_key", "outcome": "success",
        "details": {"purpose": "pii", "new_version": 2, "values": 2 * ROWS},
    })]


def test_no_event_when_rotation_fails(engine, key_dir, monkeypatch):
    events = []
    monkeypatch.setattr(rotation, "verify",
                        lambda *args: (_ for _ in ()).throw(
                            rotation.RotationError("check failed")))

    with pytest.raises(rotation.RotationError):
        rotate(engine, key_dir, record_event=lambda *a, **k: events.append(a))

    assert events == []


# Command line

def run_cli(key_dir, db_path, *arguments, **env):
    return subprocess.run(
        [sys.executable, str(SCRIPTS / "rotate_pii_key.py"),
         "--key-dir", str(key_dir), *arguments],
        env={**{k: v for k, v in os.environ.items()
                if not k.startswith("EVP_")},
             "EVP_IDENTITY_DB_URL": f"sqlite:///{db_path}", **env},
        capture_output=True, text=True,
    )


def test_cli_rotates_without_printing_secrets(engine, key_dir, tmp_path):
    result = run_cli(key_dir, tmp_path / "identity.db", "--generate-new-key",
                     "--batch-size", "2")

    assert result.returncode == 0, result.stderr
    assert set(kids(engine)) == {V2}

    output = result.stdout + result.stderr
    for secret in (*emails(), *addresses(),
                   (key_dir / "pii_key_v1").read_text().strip(),
                   (key_dir / "pii_key_v2").read_text().strip()):
        assert secret not in output

    assert "Audit log not configured" in result.stdout


def test_cli_dry_run(engine, key_dir, tmp_path):
    result = run_cli(key_dir, tmp_path / "identity.db", "--dry-run",
                     "--generate-new-key")

    assert result.returncode == 0, result.stderr
    assert "Dry run: 14 encrypted values" in result.stdout
    assert set(kids(engine)) == {V1}
    assert not (key_dir / "pii_key_v2").exists()


def test_cli_needs_database_url_from_environment(key_dir):
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "rotate_pii_key.py"),
         "--key-dir", str(key_dir)],
        env={k: v for k, v in os.environ.items() if not k.startswith("EVP_")},
        capture_output=True, text=True,
    )

    assert result.returncode == 2
    assert "EVP_IDENTITY_DB_URL" in result.stderr


def test_cli_failure_message_is_safe(engine, key_dir, tmp_path):
    result = run_cli(key_dir, tmp_path / "identity.db")

    assert result.returncode == 1
    assert "pii_key_v2 does not exist" in result.stderr
    assert "still readable" in result.stderr


# Script and README

def test_script_has_sr_docstring():
    header = (SCRIPTS / "rotate_pii_key.py").read_text()[:200]

    assert "SR-13" in header and "Security controls:" in (
        SCRIPTS / "rotate_pii_key.py").read_text()


def test_readme_has_key_rotation_section():
    text = README_PATH.read_text(encoding="utf-8")
    section = text[text.index("## Key rotation"):]

    assert "at least every 12 months" in section
    assert "separately from database backups" in section
    assert "--dry-run" in section
