#!/usr/bin/env bash
#
# SR-19: Scheduled database backups (RPO <= 15 minutes).
#
# Runs inside the "backup" Compose service. Every 15 minutes it dumps the
# identity, ballot and audit databases into /backups/<UTC timestamp>/ as
# gzip files, and keeps the newest 96 backups (24 hours).
#
# Security controls:
# - mysqldump --single-transaction: a consistent snapshot of each
#   database without locking out the apps
# - Root passwords read from Docker secret files into MYSQL_PWD, never
#   on a command line and never printed
# - A backup appears under its final name only when all three dumps
#   succeeded; a failed run leaves no partial backup behind
# - Backups go to their own volume, separate from the database volumes;
#   encryption keys are never backed up here (deploy/README.md)
# - Files are created owner-only (umask 077)
#
# Usage:
#   evp-backup.sh          run forever, every BACKUP_INTERVAL_SECONDS
#   evp-backup.sh --once   take one backup and exit (tests, drills)
#
# Local academic prototype.

set -euo pipefail
umask 077

BACKUP_DIR="${BACKUP_DIR:-/backups}"
SECRETS_DIR="${BACKUP_SECRETS_DIR:-/run/secrets}"
INTERVAL_SECONDS="${BACKUP_INTERVAL_SECONDS:-900}"
KEEP="${BACKUP_KEEP:-96}"

# database:host:root password secret
DATABASES="identity_db:db-identity:db_identity_root_password ballot_db:db-ballot:db_ballot_root_password audit_db:db-audit:db_audit_root_password"

for setting in "$INTERVAL_SECONDS" "$KEEP"; do
    if ! [[ "$setting" =~ ^[1-9][0-9]*$ ]]; then
        echo "BACKUP_INTERVAL_SECONDS and BACKUP_KEEP must be positive integers" >&2
        exit 2
    fi
done

prune() {
    # Timestamps sort in time order; keep the newest $KEEP.
    find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -name '[0-9]*Z' \
        | sort -r \
        | tail -n +"$((KEEP + 1))" \
        | while read -r old; do
            rm -rf -- "$old"
            echo "Removed old backup $(basename "$old")"
        done
}

backup_once() {
    local stamp work entry database host secret

    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    work="$BACKUP_DIR/.partial-$stamp"

    # Remove what an interrupted earlier run left behind.
    find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -name '.partial-*' \
        -exec rm -rf -- {} +

    mkdir -p "$work"

    for entry in $DATABASES; do
        IFS=: read -r database host secret <<< "$entry"

        if [ ! -r "$SECRETS_DIR/$secret" ]; then
            echo "Backup $stamp failed: secret $secret is not readable" >&2
            rm -rf -- "$work"
            return 1
        fi

        if ! MYSQL_PWD="$(cat "$SECRETS_DIR/$secret")" mysqldump \
                --host="$host" --user=root \
                --single-transaction --routines --triggers --events \
                --set-gtid-purged=OFF \
                --databases "$database" \
                | gzip -9 > "$work/$database.sql.gz"; then
            echo "Backup $stamp failed while dumping $database" >&2
            rm -rf -- "$work"
            return 1
        fi
    done

    mv -- "$work" "$BACKUP_DIR/$stamp"
    echo "Backup $stamp complete"

    prune
}

if [ "${1:-}" = "--once" ]; then
    backup_once
    exit
fi

if [ "$#" -ne 0 ]; then
    echo "Usage: $0 [--once]" >&2
    exit 2
fi

while true; do
    backup_once || echo "Backup failed; retrying in $INTERVAL_SECONDS s" >&2
    sleep "$INTERVAL_SECONDS"
done
