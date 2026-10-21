#!/usr/bin/env bash
#
# SR-13 / SR-20: Generate local deployment secrets.
#
# Security controls:
# - Random values from Python's secrets module (CSPRNG) only
# - Written only to deploy/secrets/ (git-ignored), directory 700, files 600
# - Creates only missing files; existing files are left untouched
#   unless --force is given
# - Key folder deploy/secrets/keys/ for crypto_agility (SR-14), built by
#   make_keys.py with the cryptography package from .venv
# - Never prints secret values; only file names
# - Does not create or change TLS certificates (Workstream A owns HTTPS)
#
# Usage (from anywhere):
#   bash deploy/scripts/make_secrets.sh [--force]
#
# EVP_KEY_PYTHON overrides the Python used for keys (default .venv/bin/python).
#
# Workstream A supplies deploy/secrets/demo-voter.json and
# deploy/secrets/registered_fingerprints.txt separately.
#
# Local academic prototype.

set -euo pipefail
umask 077

usage() {
    echo "Usage: $0 [--force]" >&2
    exit 2
}

FORCE=0

for argument in "$@"; do
    case "$argument" in
        --force) FORCE=1 ;;
        *) usage ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SECRETS_DIR="$(dirname "$SCRIPT_DIR")/secrets"
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
KEY_PYTHON="${EVP_KEY_PYTHON:-$REPO_ROOT/.venv/bin/python}"

# Name and generator for each secret. Generators are Python
# expressions evaluated with the secrets module imported.
SECRET_NAMES="flask_secret_key pii_key_v1 db_identity_root_password db_ballot_root_password db_audit_root_password voter_access_db_password admin_db_password ballot_db_password audit_db_password tally_db_password"

generator_for() {
    case "$1" in
        flask_secret_key)          echo "secrets.token_hex(32)" ;;  # 256-bit Flask SECRET_KEY
        pii_key_v1)                echo "secrets.token_hex(32)" ;;  # 256-bit AES key, version 1 (SR-13)
        db_*_root_password)        echo "secrets.token_urlsafe(32)" ;;
        *_db_password)             echo "secrets.token_urlsafe(32)" ;;  # service accounts in db/roles.sql
        *) echo "Unknown secret: $1" >&2; exit 1 ;;
    esac
}

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required" >&2
    exit 1
fi

if ! "$KEY_PYTHON" -c "import cryptography" >/dev/null 2>&1; then
    echo "A Python with the cryptography package is required for keys:" >&2
    echo "create .venv from requirements.txt or set EVP_KEY_PYTHON" >&2
    exit 1
fi

if [ -L "$SECRETS_DIR" ]; then
    echo "Refusing to use $SECRETS_DIR: it is a symbolic link" >&2
    exit 1
fi

mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

existing=""

# Remove a half-written temporary file if anything fails.
temporary=""
trap 'rm -f "${temporary:-}"' EXIT

for name in $SECRET_NAMES; do
    target="$SECRETS_DIR/$name"

    # Without --force, an existing file is never touched.
    if [ -e "$target" ] || [ -L "$target" ]; then
        if [ "$FORCE" -ne 1 ]; then
            echo "Kept existing deploy/secrets/$name"
            continue
        fi

        existing="$existing $name"
    fi

    temporary="$(mktemp "$SECRETS_DIR/.${name}.XXXXXX")"

    python3 -c "import secrets, sys; sys.stdout.write($(generator_for "$name"))" > "$temporary"
    chmod 600 "$temporary"
    mv -f "$temporary" "$target"

    echo "Wrote deploy/secrets/$name"
done

if [ "$FORCE" -eq 1 ]; then
    "$KEY_PYTHON" "$SCRIPT_DIR/make_keys.py" "$SECRETS_DIR" --force
else
    "$KEY_PYTHON" "$SCRIPT_DIR/make_keys.py" "$SECRETS_DIR"
fi

if [ -n "$existing" ]; then
    echo "Replaced existing secrets. A database that is already initialised" >&2
    echo "keeps its old root password until its volume is recreated." >&2
fi

for name in demo-voter.json registered_fingerprints.txt; do
    if [ ! -f "$SECRETS_DIR/$name" ]; then
        echo "Still needed from Workstream A: deploy/secrets/$name"
    fi
done
