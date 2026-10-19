
"""
SR-13 / SR-20 tests for deploy/scripts/make_secrets.sh.

Static checks on the script text, then behaviour checks
that run a copy of it inside a temporary folder, so the
real deploy/secrets/ is never touched by the tests.
"""

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "deploy" / "scripts" / "make_secrets.sh"

GENERATED = {
    "flask_secret_key": r"[0-9a-f]{64}",
    "pii_key_v1": r"[0-9a-f]{64}",
    "db_identity_root_password": r"[A-Za-z0-9_-]{43}",
    "db_ballot_root_password": r"[A-Za-z0-9_-]{43}",
    "db_audit_root_password": r"[A-Za-z0-9_-]{43}",
}


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

    return tmp_path


def run_script(sandbox, *arguments):
    return subprocess.run(
        ["bash", str(sandbox / "deploy" / "scripts" / SCRIPT_PATH.name),
         *arguments],
        cwd=sandbox,
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


def test_generates_every_secret(sandbox):
    result = run_script(sandbox)

    assert result.returncode == 0, result.stderr

    for name, pattern in read_secrets(sandbox).items():
        assert re.fullmatch(GENERATED[name], pattern), name


def test_writes_nothing_outside_deploy_secrets(sandbox):
    before = all_files(sandbox)

    run_script(sandbox)

    added = all_files(sandbox) - before

    assert added == {f"deploy/secrets/{name}" for name in GENERATED}


def test_files_are_600_and_directory_is_700(sandbox):
    run_script(sandbox)
    secrets_dir = sandbox / "deploy" / "secrets"

    assert stat.S_IMODE(secrets_dir.stat().st_mode) == 0o700

    for name in GENERATED:
        assert stat.S_IMODE((secrets_dir / name).stat().st_mode) == 0o600


def test_values_are_distinct(sandbox):
    run_script(sandbox)

    values = list(read_secrets(sandbox).values())

    assert len(set(values)) == len(values)


def test_secret_values_are_never_printed(sandbox):
    result = run_script(sandbox)

    for value in read_secrets(sandbox).values():
        assert value not in result.stdout
        assert value not in result.stderr


def test_refuses_to_overwrite_without_force(sandbox):
    run_script(sandbox)
    before = read_secrets(sandbox)

    result = run_script(sandbox)

    assert result.returncode != 0
    assert "Refusing to overwrite" in result.stderr
    assert read_secrets(sandbox) == before


def test_refuses_if_any_single_file_exists(sandbox):
    secrets_dir = sandbox / "deploy" / "secrets"
    secrets_dir.mkdir(parents=True)
    (secrets_dir / "pii_key_v1").write_text("existing-key")

    result = run_script(sandbox)

    assert result.returncode != 0
    assert (secrets_dir / "pii_key_v1").read_text() == "existing-key"
    assert sorted(path.name for path in secrets_dir.iterdir()) == ["pii_key_v1"]


def test_force_replaces_every_secret(sandbox):
    run_script(sandbox)
    before = read_secrets(sandbox)

    result = run_script(sandbox, "--force")

    assert result.returncode == 0, result.stderr

    after = read_secrets(sandbox)

    for name in GENERATED:
        assert after[name] != before[name]


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


def test_no_temporary_files_left_behind(sandbox):
    run_script(sandbox)

    leftovers = [
        path.name for path in (sandbox / "deploy" / "secrets").iterdir()
        if path.name.startswith(".")
    ]

    assert leftovers == []


def test_reminds_about_workstream_a_files(sandbox):
    result = run_script(sandbox)

    assert "deploy/secrets/demo-voter.json" in result.stdout
    assert "deploy/secrets/registered_fingerprints.txt" in result.stdout


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
