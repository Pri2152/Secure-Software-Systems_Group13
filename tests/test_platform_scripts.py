
"""
SR-13 / SR-20 tests for deploy/scripts/make_secrets.sh.

Static checks on the script text, then behaviour checks
that run a copy of it inside a temporary folder, so the
real deploy/secrets/ is never touched by the tests.
"""

import base64
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "deploy" / "scripts" / "make_secrets.sh"
KEYS_HELPER_PATH = REPO_ROOT / "deploy" / "scripts" / "make_keys.py"

GENERATED = {
    "flask_secret_key": r"[0-9a-f]{64}",
    "pii_key_v1": r"[0-9a-f]{64}",
    "db_identity_root_password": r"[A-Za-z0-9_-]{43}",
    "db_ballot_root_password": r"[A-Za-z0-9_-]{43}",
    "db_audit_root_password": r"[A-Za-z0-9_-]{43}",
    "voter_access_db_password": r"[A-Za-z0-9_-]{43}",
    "ballot_db_password": r"[A-Za-z0-9_-]{43}",
    "audit_db_password": r"[A-Za-z0-9_-]{43}",
    "tally_db_password": r"[A-Za-z0-9_-]{43}",
}

KEY_FILES = (
    "manifest.json",
    "pii_key_v1",
    "audit_hmac_v1",
    "audit_sign_v1",
    "ballot_sign_v1",
    "results_sign_v1",
    "election_seal_v1",
)


def script_text():
    return SCRIPT_PATH.read_text(encoding="utf-8")


def code_lines():
    return [
        line for line in script_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


# Static checks

def test_script_exists_and_is_executable():
    assert SCRIPT_PATH.is_file()
    assert SCRIPT_PATH.stat().st_mode & stat.S_IXUSR


def test_script_uses_bash_and_strict_mode():
    assert script_text().startswith("#!/usr/bin/env bash\n")
    assert "set -euo pipefail" in code_lines()


def test_script_has_sr_docstring():
    header = script_text()[:400]

    assert "SR-13" in header and "SR-20" in header
    assert "Security controls:" in header


def test_script_restricts_permissions():
    lines = [line.strip() for line in code_lines()]

    assert "umask 077" in lines
    assert any(line.startswith("chmod 600 ") for line in lines)
    assert any(line.startswith("chmod 700 ") for line in lines)


def test_script_uses_python_secrets_module_only():
    text = "\n".join(code_lines())

    assert "python3 -c \"import secrets" in text
    for weak in ("$RANDOM", "/dev/urandom", "openssl", "uuidgen",
                 "date +%s", "random."):
        assert weak not in text


def test_script_writes_only_under_deploy_secrets():
    text = "\n".join(code_lines())

    assert 'SECRETS_DIR="$(dirname "$SCRIPT_DIR")/secrets"' in text

    # Every file redirect goes to a temporary file inside SECRETS_DIR.
    for target in re.findall(r"(?<![0-9&])>(?!&)\s*(\"?[^\s;|]+)", text):
        assert target in {'"$temporary"', "/dev/null"}, target

    assert 'mktemp "$SECRETS_DIR/' in text
    assert 'mv -f "$temporary" "$target"' in text
    assert 'target="$SECRETS_DIR/$name"' in text


def test_script_contains_no_hard_coded_key_material():
    text = script_text()

    assert "BEGIN" not in text
    assert not re.search(r"[0-9a-fA-F]{32,}", text)

    # Long base64-like runs containing digits look like keys;
    # file paths are split on "/" so they do not match.
    for candidate in re.findall(r"[A-Za-z0-9+/_=-]{32,}", text):
        for segment in candidate.split("/"):
            assert not (
                len(segment) >= 32
                and any(character.isdigit() for character in segment)
            ), segment

    assert not re.search(r"(?i)(password|secret|key)=['\"]?\w", text)


def test_script_does_not_touch_certificates():
    text = "\n".join(code_lines()).lower()

    for word in ("openssl", "certs", ".crt", ".pem", ".key", "x509"):
        assert word not in text


# Behaviour (on a temporary copy)

@pytest.fixture
def sandbox(tmp_path):
    scripts = tmp_path / "deploy" / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(SCRIPT_PATH, scripts / SCRIPT_PATH.name)
    shutil.copy2(KEYS_HELPER_PATH, scripts / KEYS_HELPER_PATH.name)

    return tmp_path


def run_script(sandbox, *arguments):
    return subprocess.run(
        ["bash", str(sandbox / "deploy" / "scripts" / SCRIPT_PATH.name),
         *arguments],
        cwd=sandbox,
        # The sandbox has no .venv, so use this test's Python for keys.
        env=dict(os.environ, EVP_KEY_PYTHON=sys.executable),
        capture_output=True,
        text=True,
    )


def all_files(root):
    return {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    }


def read_secrets(sandbox):
    return {
        name: (sandbox / "deploy" / "secrets" / name).read_text()
        for name in GENERATED
    }


def read_keys(sandbox):
    return {
        name: (sandbox / "deploy" / "secrets" / "keys" / name).read_text()
        for name in KEY_FILES
    }


def test_generates_every_secret(sandbox):
    result = run_script(sandbox)

    assert result.returncode == 0, result.stderr

    for name, pattern in read_secrets(sandbox).items():
        assert re.fullmatch(GENERATED[name], pattern), name


def test_writes_nothing_outside_deploy_secrets(sandbox):
    before = all_files(sandbox)

    run_script(sandbox)

    added = all_files(sandbox) - before

    assert added == (
        {f"deploy/secrets/{name}" for name in GENERATED}
        | {f"deploy/secrets/keys/{name}" for name in KEY_FILES}
    )


def test_files_are_600_and_directory_is_700(sandbox):
    run_script(sandbox)
    secrets_dir = sandbox / "deploy" / "secrets"

    assert stat.S_IMODE(secrets_dir.stat().st_mode) == 0o700

    for name in GENERATED:
        assert stat.S_IMODE((secrets_dir / name).stat().st_mode) == 0o600

    keys_dir = secrets_dir / "keys"

    assert stat.S_IMODE(keys_dir.stat().st_mode) == 0o700

    for name in KEY_FILES:
        assert stat.S_IMODE((keys_dir / name).stat().st_mode) == 0o600


def test_values_are_distinct(sandbox):
    run_script(sandbox)

    values = list(read_secrets(sandbox).values())

    assert len(set(values)) == len(values)


def test_secret_values_are_never_printed(sandbox):
    result = run_script(sandbox)

    for value in read_secrets(sandbox).values():
        assert value not in result.stdout
        assert value not in result.stderr

    for name, value in read_keys(sandbox).items():
        if name == "manifest.json":
            continue

        body = value.strip().splitlines()[len(value.strip().splitlines()) // 2]

        assert body not in result.stdout
        assert body not in result.stderr

    assert "PRIVATE KEY" not in result.stdout + result.stderr


# Without --force, existing files are kept and only missing ones made.

def test_rerun_without_force_changes_nothing(sandbox):
    run_script(sandbox)
    before = (read_secrets(sandbox), read_keys(sandbox))

    result = run_script(sandbox)

    assert result.returncode == 0, result.stderr
    assert (read_secrets(sandbox), read_keys(sandbox)) == before
    assert "Kept existing deploy/secrets/pii_key_v1" in result.stdout
    assert "Kept existing deploy/secrets/keys/manifest.json" in result.stdout
    assert "Wrote" not in result.stdout


def test_only_missing_secrets_are_created(sandbox):
    secrets_dir = sandbox / "deploy" / "secrets"
    secrets_dir.mkdir(parents=True)
    existing = "ab" * 32
    (secrets_dir / "pii_key_v1").write_text(existing)
    (secrets_dir / "flask_secret_key").write_text("existing-flask-key")

    result = run_script(sandbox)

    assert result.returncode == 0, result.stderr
    assert (secrets_dir / "pii_key_v1").read_text() == existing
    assert (secrets_dir / "flask_secret_key").read_text() == "existing-flask-key"
    assert (secrets_dir / "keys" / "pii_key_v1").read_text().strip() == existing

    for name in GENERATED:
        assert (secrets_dir / name).is_file(), name


def test_only_missing_keys_are_created(sandbox):
    run_script(sandbox)
    keys_dir = sandbox / "deploy" / "secrets" / "keys"
    before = read_keys(sandbox)
    (keys_dir / "audit_sign_v1").unlink()

    result = run_script(sandbox)
    after = read_keys(sandbox)

    assert result.returncode == 0, result.stderr
    assert "Wrote deploy/secrets/keys/audit_sign_v1" in result.stdout
    assert after["audit_sign_v1"] != before["audit_sign_v1"]

    for name in KEY_FILES:
        if name != "audit_sign_v1":
            assert after[name] == before[name], name


def test_invalid_existing_pii_key_is_refused_and_kept(sandbox):
    secrets_dir = sandbox / "deploy" / "secrets"
    secrets_dir.mkdir(parents=True)
    (secrets_dir / "pii_key_v1").write_text("existing-key")

    result = run_script(sandbox)

    assert result.returncode != 0
    assert (secrets_dir / "pii_key_v1").read_text() == "existing-key"
    assert not (secrets_dir / "keys").exists()
    assert "existing-key" not in result.stdout + result.stderr


def test_mismatched_pii_copy_is_refused(sandbox):
    run_script(sandbox)
    secrets_dir = sandbox / "deploy" / "secrets"
    (secrets_dir / "pii_key_v1").write_text("cd" * 32)
    before = read_keys(sandbox)

    result = run_script(sandbox)

    assert result.returncode != 0
    assert "does not match" in result.stderr
    assert (secrets_dir / "pii_key_v1").read_text() == "cd" * 32
    assert read_keys(sandbox) == before


def test_force_replaces_every_secret(sandbox):
    run_script(sandbox)
    before = read_secrets(sandbox)
    keys_before = read_keys(sandbox)

    result = run_script(sandbox, "--force")

    assert result.returncode == 0, result.stderr

    after = read_secrets(sandbox)

    for name in GENERATED:
        assert after[name] != before[name]

    keys_after = read_keys(sandbox)

    for name in KEY_FILES:
        if name != "manifest.json":
            assert keys_after[name] != keys_before[name], name

    assert keys_after["pii_key_v1"].strip() == after["pii_key_v1"]


def test_unknown_argument_is_rejected(sandbox):
    result = run_script(sandbox, "--overwrite")

    assert result.returncode != 0
    assert not (sandbox / "deploy" / "secrets").exists()


def test_symlinked_secrets_folder_is_refused(sandbox, tmp_path_factory):
    elsewhere = tmp_path_factory.mktemp("elsewhere")
    os.symlink(elsewhere, sandbox / "deploy" / "secrets")

    result = run_script(sandbox)

    assert result.returncode != 0
    assert list(elsewhere.iterdir()) == []


def test_symlinked_keys_folder_is_refused(sandbox, tmp_path_factory):
    elsewhere = tmp_path_factory.mktemp("elsewhere")
    secrets_dir = sandbox / "deploy" / "secrets"
    secrets_dir.mkdir(parents=True)
    os.symlink(elsewhere, secrets_dir / "keys")

    result = run_script(sandbox)

    assert result.returncode != 0
    assert list(elsewhere.iterdir()) == []


def test_missing_cryptography_python_is_refused(sandbox):
    result = subprocess.run(
        ["bash", str(sandbox / "deploy" / "scripts" / SCRIPT_PATH.name)],
        cwd=sandbox,
        env=dict(os.environ, EVP_KEY_PYTHON=str(sandbox / "no-python")),
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "cryptography" in result.stderr
    assert not (sandbox / "deploy" / "secrets").exists()


def test_no_temporary_files_left_behind(sandbox):
    run_script(sandbox)

    leftovers = [
        path.name for path in (sandbox / "deploy" / "secrets").rglob("*")
        if path.name.startswith(".")
    ]

    assert leftovers == []


def test_reminds_about_workstream_a_files(sandbox):
    result = run_script(sandbox)

    assert "deploy/secrets/demo-voter.json" in result.stdout
    assert "deploy/secrets/registered_fingerprints.txt" in result.stdout


# Key folder: crypto_agility must accept it

@pytest.fixture
def key_service(sandbox):
    from crypto_agility import build_service

    assert run_script(sandbox).returncode == 0

    return build_service(key_dir=str(sandbox / "deploy" / "secrets" / "keys"))


def test_crypto_agility_round_trips_pii(key_service, sandbox):
    envelope = key_service.encrypt("pii", b"12 Example Street")

    assert envelope["kid"] == "pii.aes-256-gcm.v1"
    assert b"12 Example Street" not in json.dumps(envelope).encode()
    assert key_service.decrypt("pii", envelope) == b"12 Example Street"


def test_pii_key_is_the_existing_pii_key_v1(key_service, sandbox):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from crypto_agility.service import _bound_aad

    envelope = key_service.encrypt("pii", b"same key")
    hex_key = (sandbox / "deploy" / "secrets" / "pii_key_v1").read_text()

    # Decrypting with the raw pii_key_v1 proves the manifest reuses it.
    nonce = base64.b64decode(envelope["nonce"])
    ct = base64.b64decode(envelope["ct"])

    aad = _bound_aad(envelope["kid"], b"")

    assert AESGCM(bytes.fromhex(hex_key)).decrypt(nonce, ct, aad) == b"same key"


def test_every_default_policy_key_works(key_service):
    data = b"checkpoint"

    assert key_service.verify_mac("audit", data, key_service.mac("audit", data))

    for purpose in ("audit", "ballot", "results"):
        assert key_service.verify(purpose, data, key_service.sign(purpose, data))

    assert key_service.open(
        "election", key_service.seal("election", data)
    ) == data


def test_field_crypto_accepts_generated_keys(key_service):
    from platform_security.field_crypto import (
        EncryptedText,
        set_crypto_provider,
    )

    set_crypto_provider(key_service)

    try:
        column = EncryptedText()
        stored = column.process_bind_param("Voter address", None)

        assert "Voter address" not in stored
        assert column.process_result_value(stored, None) == "Voter address"
    finally:
        set_crypto_provider(None)


def test_manifest_has_one_current_key_per_slot(sandbox):
    run_script(sandbox)
    manifest = json.loads(read_keys(sandbox)["manifest.json"])
    slots = [
        (entry["purpose"], entry["family"], entry["alg"])
        for entry in manifest["keys"]
    ]

    assert len(slots) == len(set(slots))
    assert all(entry["current"] is True for entry in manifest["keys"])
    assert sorted(entry["file"] for entry in manifest["keys"]) == sorted(
        name for name in KEY_FILES if name != "manifest.json"
    )


def test_db_password_files_match_roles_sql():
    roles = (REPO_ROOT / "deploy" / "db" / "roles.sql").read_text()
    placeholders = set(re.findall(r"\$\{([A-Z_]+)\}", roles))

    assert {name.lower() for name in placeholders} == {
        name for name in GENERATED if name.endswith("_db_password")
    }


# make_keys.py (static)

def keys_helper_code():
    return KEYS_HELPER_PATH.read_text(encoding="utf-8")


def test_keys_helper_has_sr_docstring():
    header = keys_helper_code()[:600]

    assert "SR-13" in header and "SR-14" in header and "SR-20" in header
    assert "Security controls:" in header


def test_keys_helper_makes_no_certificates():
    text = keys_helper_code().lower()

    for word in ("x509", "certificatebuilder", "openssl", "nginx", "certs/"):
        assert word not in text, word


def test_key_files_do_not_look_like_tls_files(sandbox):
    run_script(sandbox)

    for name in KEY_FILES:
        assert not name.endswith((".crt", ".pem", ".key", ".csr")), name


def test_keys_helper_uses_strong_sources_only():
    text = keys_helper_code()

    assert "secrets.token_bytes" in text
    assert "import random" not in text and "random." not in text
    assert "key_size=RSA_SEAL_KEY_BITS" in text
    assert "RSA_SEAL_KEY_BITS = 3072" in text
    assert "NoEncryption()" in text  # files are protected by 600 and Docker secrets
    assert not re.search(r"[0-9a-fA-F]{32,}", text)
    assert "BEGIN" not in text


# README

def test_readme_has_exact_commands_and_certificate_note():
    text = (REPO_ROOT / "deploy" / "README.md").read_text(encoding="utf-8")

    for command in (
        "bash deploy/scripts/make_secrets.sh",
        "docker compose -f deploy/docker-compose.yml up -d --build",
        "docker compose -f deploy/docker-compose.yml down",
    ):
        assert command in text

    assert "nginx/certs/" in text
    assert "docs/WORKSTREAM_A_IMPLEMENTATION.md" in text
