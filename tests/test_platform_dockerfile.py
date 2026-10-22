
"""
SR-20 static tests for the shared application image.

Checks deploy/Dockerfile.app pins its base image,
runs as a non-root user, has no default command and
never copies tests, notes, secrets or certificates.
"""

import fnmatch
import glob
import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE_PATH = REPO_ROOT / "deploy" / "Dockerfile.app"
DOCKERIGNORE_PATH = REPO_ROOT / ".dockerignore"
ENTRYPOINTS_PATH = REPO_ROOT / "deploy" / "ENTRYPOINTS.md"

FORBIDDEN_SOURCES = [
    "tests", "tests/*", ".notes", ".notes/*", ".git", ".git/*",
    "deploy", "deploy/*", "*secrets*", "*certs*", "nginx", "nginx/*",
    "backups", "backups/*", ".env", ".env.*", ".venv",
    "*.key", "*.pem", "*.crt", "*.p12", "*.csr",
]


def instructions():
    """Return (INSTRUCTION, arguments) pairs."""

    text = DOCKERFILE_PATH.read_text(encoding="utf-8")
    text = re.sub(r"\\\n", " ", text)

    parsed = []

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        keyword, _, arguments = line.partition(" ")
        parsed.append((keyword.upper(), arguments.strip()))

    return parsed


def arguments_for(keyword):
    return [
        arguments
        for instruction, arguments in instructions()
        if instruction == keyword
    ]


def copy_sources():
    sources = []

    for arguments in arguments_for("COPY"):
        parts = [
            part for part in arguments.split()
            if not part.startswith("--")
        ]
        sources.extend(parts[:-1])

    return sources


# Base image

def test_single_pinned_python_311_slim_base():
    images = arguments_for("FROM")

    assert len(images) == 1
    assert re.fullmatch(
        r"python:3\.11\.\d+-slim(@sha256:[0-9a-f]{64})?",
        images[0],
    ), images[0]


def test_python_environment_settings():
    environment = arguments_for("ENV")

    assert "PYTHONDONTWRITEBYTECODE=1" in environment
    assert "PYTHONUNBUFFERED=1" in environment


def test_requirements_and_pinned_gunicorn_installed():
    installs = [
        command for command in arguments_for("RUN")
        if "pip install" in command
    ]

    assert len(installs) == 1
    assert "-r requirements.txt" in installs[0]
    assert re.search(r"\bgunicorn==\d+\.\d+\.\d+\b", installs[0])


# Non-root user and no default command

def test_final_user_is_not_root():
    users = arguments_for("USER")

    assert users, "No USER instruction"
    assert users[-1].split(":")[0] not in {"root", "0", ""}


def test_user_has_uid_10001():
    assert any(
        "useradd" in command and "--uid 10001" in command
        for command in arguments_for("RUN")
    )


def test_user_switch_is_last_instruction():
    assert instructions()[-1][0] == "USER"


def test_no_default_command():
    assert arguments_for("CMD") == []
    assert arguments_for("ENTRYPOINT") == []


# What goes into the image

def test_no_add_instruction():
    # ADD can fetch URLs and unpack archives; COPY cannot.
    assert arguments_for("ADD") == []


def test_copied_code_is_not_owned_by_runtime_user():
    for arguments in arguments_for("COPY"):
        assert "--chown" not in arguments


@pytest.mark.parametrize("source", copy_sources())
def test_no_secrets_tests_or_notes_copied(source):
    normalised = source.rstrip("/") or source

    assert normalised not in {".", "./", "*", "/"}

    for pattern in FORBIDDEN_SOURCES:
        assert not fnmatch.fnmatch(normalised, pattern), (
            f"{source} matches forbidden {pattern}"
        )


@pytest.mark.parametrize("source", copy_sources())
def test_copy_sources_exist(source):
    assert glob.glob(str(REPO_ROOT / source)), f"{source} not found"


def test_root_python_files_are_not_tests():
    for path in REPO_ROOT.glob("*.py"):
        assert not path.name.startswith("test_"), path.name


def test_application_code_is_copied():
    sources = copy_sources()

    assert "*.py" in sources
    assert "platform_security/" in sources


@pytest.mark.parametrize("folder", ["admin", "audit", "crypto_agility"])
def test_workstream_b_packages_are_copied(folder):
    assert f"{folder}/ ./{folder}/" in arguments_for("COPY")


# Workstream C's voting page: voting_routes.py looks for these
# folders next to the code, under /app.
@pytest.mark.parametrize("folder", ["templates", "static"])
def test_voting_page_folders_are_copied(folder):
    assert f"{folder}/ ./{folder}/" in arguments_for("COPY")
    assert (REPO_ROOT / folder / "voting").is_dir()


# .dockerignore

def dockerignore_rules():
    return {
        line.strip()
        for line in DOCKERIGNORE_PATH.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip() and not line.startswith("#")
    }


@pytest.mark.parametrize("rule", [
    ".notes", "deploy/secrets", "backups", "tests",
])
def test_dockerignore_excludes_workstream_e_paths(rule):
    assert rule in dockerignore_rules()


def test_dockerignore_keeps_existing_rules():
    for rule in (".git", ".venv", "nginx/", ".env", "*.key",
                 "*.crt", "*.pem", "*.db"):
        assert rule in dockerignore_rules()


# Entrypoint table

EXPECTED_ENTRYPOINTS = {
    "voter-access": ("gateway_runtime.py", "gateway_runtime:application", "Workstream A"),
    "admin-audit": ("admin/wsgi.py", "admin.wsgi:app", "Workstream B"),
    "ballot": ("ballot/wsgi.py", "ballot.wsgi:app", "Workstream C"),
    "tally": ("verification/wsgi.py", "verification.wsgi:app", "Workstream D"),
    "results-consumer": ("results_consumer/wsgi.py", "results_consumer.wsgi:app", "Workstream D"),
}


def entrypoint_rows():
    rows = {}

    for line in ENTRYPOINTS_PATH.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|") or line.startswith("|---"):
            continue

        cells = [cell.strip().strip("`") for cell in line.strip("|").split("|")]

        if cells[0] == "Compartment":
            continue

        rows[cells[0]] = cells[1:]

    return rows


def test_entrypoint_table_lists_every_compartment():
    rows = entrypoint_rows()

    assert set(rows) == set(EXPECTED_ENTRYPOINTS)

    for compartment, (path, target, owner) in EXPECTED_ENTRYPOINTS.items():
        assert rows[compartment][:3] == [path, target, owner]


def test_entrypoint_status_matches_repository():
    for compartment, cells in entrypoint_rows().items():
        exists = (REPO_ROOT / cells[0]).is_file()

        assert cells[3] == ("Yes" if exists else "No"), (
            f"{compartment}: update the 'On main yet' column"
        )


def test_audit_archive_folder_is_writable_by_runtime_user_only():
    # The admin-audit checkpoint volume starts from this folder, so a
    # fresh named volume is owned by evpuser and closed to others.
    assert any(
        "install -d -o evpuser -g evpuser -m 700 /var/lib/evp/audit" in command
        for command in arguments_for("RUN")
    )
