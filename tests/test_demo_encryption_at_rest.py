
"""
SR-13 tests for scripts/demo_encryption_at_rest.py.

Runs the demo in a fresh interpreter on a temporary SQLite
file, with a key folder built by make_keys.py (as
make_secrets.sh builds it), and reads the file back with
Python's sqlite3 module.
"""

import importlib.util
import json
import os
import shlex
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "demo_encryption_at_rest.py"
MAKE_KEYS = REPO_ROOT / "deploy" / "scripts" / "make_keys.py"

EMAIL = "demo.voter@example.test"
ADDRESS = "1 Synthetic Lane, Testville VIC 3999"


@pytest.fixture
def key_dir(tmp_path):
    spec = importlib.util.spec_from_file_location("make_keys", MAKE_KEYS)
    make_keys = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(make_keys)

    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "pii_key_v1").write_text(os.urandom(32).hex())
    make_keys.make_keys(secrets_dir, report=lambda line: None)

    return secrets_dir / "keys"


def run_demo(database, key_dir=None, **extra_env):
    env = {k: v for k, v in os.environ.items() if not k.startswith("EVP_")}
    if key_dir is not None:
        env["EVP_KEY_DIR"] = str(key_dir)
    env.update(extra_env)

    return subprocess.run(
        [sys.executable, str(SCRIPT), str(database)],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True,
    )


def stored(database, column, table):
    with sqlite3.connect(database) as connection:
        return connection.execute(
            f"SELECT owner_voter_id, {column} FROM {table}"
        ).fetchall()


def test_stored_values_are_json_ciphertext(tmp_path, key_dir):
    database = tmp_path / "demo.db"

    result = run_demo(database, key_dir)

    assert result.returncode == 0, result.stderr

    for column, table, plaintext in (
        ("contact_email", "enrolment_records", EMAIL),
        ("address_text", "address_records", ADDRESS),
    ):
        [(owner, raw)] = stored(database, column, table)
        envelope = json.loads(raw)

        assert owner == "demo-voter-001"
        assert set(envelope) == {"alg", "kid", "v", "nonce", "ct"}
        assert envelope["kid"] == "pii.aes-256-gcm.v1"
        assert plaintext not in raw
        assert "Synthetic" not in raw and "example.test" not in raw


def test_prints_plaintext_from_the_orm(tmp_path, key_dir):
    result = run_demo(tmp_path / "demo.db", key_dir)

    assert "demo-voter-001" in result.stdout
    assert f"contact_email  {EMAIL}" in result.stdout
    assert f"address_text   {ADDRESS}" in result.stdout
    assert "key ID         pii.aes-256-gcm.v1" in result.stdout


def test_prints_working_sqlite3_commands(tmp_path, key_dir):
    database = tmp_path / "demo.db"
    result = run_demo(database, key_dir)
    lines = [line.strip() for line in result.stdout.splitlines()
             if line.strip().startswith("sqlite3 ")]

    assert len(lines) == 2

    for line, table in zip(lines, ("enrolment_records", "address_records")):
        program, path, sql = shlex.split(line)

        assert program == "sqlite3"
        assert Path(path) == database.resolve()

        with sqlite3.connect(path) as connection:
            [row] = connection.execute(sql).fetchall()

        assert row[1] == "demo-voter-001"
        assert json.loads(row[2])["ct"]
        assert table in sql


def test_never_prints_key_material(tmp_path, key_dir):
    result = run_demo(tmp_path / "demo.db", key_dir)
    output = result.stdout + result.stderr
    key = (key_dir / "pii_key_v1").read_text().strip()

    assert key not in output
    assert key.upper() not in output
    assert '"ct"' not in output and '"nonce"' not in output


def test_uses_real_keys_not_development_keys(tmp_path):
    # With no key folder, development keys must not be used instead.
    database = tmp_path / "demo.db"

    result = run_demo(database, tmp_path / "no-keys",
                      EVP_CRYPTO_DEV_KEYS="1")

    assert result.returncode == 1
    assert "No usable PII key" in result.stderr
    assert not database.exists()


def test_refuses_a_path_inside_the_repository(key_dir):
    database = REPO_ROOT / "demo-should-not-exist.db"

    result = run_demo(database, key_dir)

    assert result.returncode == 1
    assert "outside the repository" in result.stderr
    assert not database.exists()


def test_refuses_an_existing_file(tmp_path, key_dir):
    database = tmp_path / "demo.db"
    database.write_text("keep me")

    result = run_demo(database, key_dir)

    assert result.returncode == 1
    assert "already exists" in result.stderr
    assert database.read_text() == "keep me"


def test_needs_exactly_one_argument():
    result = subprocess.run([sys.executable, str(SCRIPT)],
                            cwd=REPO_ROOT, capture_output=True, text=True)

    assert result.returncode == 2
    assert "Usage" in result.stderr


def test_script_has_sr_docstring():
    text = SCRIPT.read_text(encoding="utf-8")

    assert text.startswith('"""\nSR-13')
    assert "Security controls:" in text
