#!/usr/bin/env bash
#
# SR-19: Restore all databases from one backup (RTO <= 2 hours).
#
# Stops the app services, restores the identity, ballot and audit
# databases from /backups/<timestamp>/, starts the services again, then
# checks the restored data: the audit hash chain (Workstream B) and the
# ballot store (Workstream C's verify_ballot_store), when they exist.
# Prints the start time, end time and total duration for the drill log.
#
# Security controls:
# - Every backup file is checked (gzip -t) before anything is stopped
# - Root passwords are read inside each database container from its
#   Docker secret file; they never pass through this host shell
# - Dumps go straight from the backup volume into mysql on stdin; no
#   copy is written to this PC
# - On failure the app services stay stopped, so nothing runs on a
#   half-restored database
# - The restored data is verified before the drill is reported as passed
#
# Usage (from anywhere):
#   bash deploy/scripts/restore.sh <timestamp>      e.g. 20261021T093000Z
#
# Local academic prototype.

set -euo pipefail

if [ "$#" -ne 1 ] || ! [[ "$1" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]; then
    echo "Usage: $0 <timestamp>   (a backup folder name, e.g. 20261021T093000Z)" >&2
    exit 2
fi

STAMP="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$DEPLOY_DIR")"
COMPOSE_FILE="$DEPLOY_DIR/docker-compose.yml"

RTO_SECONDS=7200

# database:service:root password secret
DATABASES="identity_db:db-identity:db_identity_root_password ballot_db:db-ballot:db_ballot_root_password audit_db:db-audit:db_audit_root_password"

# Stopped while the databases are replaced (the backup service too, so
# it cannot dump a half-restored database).
APP_SERVICES="voter-access-1 voter-access-2 admin-audit ballot tally results-consumer backup"

compose() {
    docker compose -f "$COMPOSE_FILE" "$@"
}

mysql_root() {
    local service="$1" secret="$2"

    compose exec -T "$service" sh -c \
        'MYSQL_PWD="$(cat "$0")"; export MYSQL_PWD; exec mysql -uroot' \
        "/run/secrets/$secret"
}

# Read a file from the backups volume through a one-off backup container.
backup_tool() {
    compose run --rm --no-deps -T --entrypoint gzip backup "$@"
}

is_running() {
    printf '%s\n' "$running" | grep -qx "$1"
}

start_seconds="$(date +%s)"
echo "Restore of backup $STAMP started at $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# 1. Check the backup before stopping anything.
files=""
for entry in $DATABASES; do
    IFS=: read -r database _ _ <<< "$entry"
    files="$files /backups/$STAMP/$database.sql.gz"
done

# shellcheck disable=SC2086
if ! backup_tool -t $files; then
    echo "Backup $STAMP is missing or damaged; nothing was changed." >&2
    exit 1
fi
echo "Backup $STAMP is complete and readable"

# 2. Stop the app services that are running.
running="$(compose ps --status running --services)"
stopped=""

for service in $APP_SERVICES; do
    if is_running "$service"; then
        stopped="$stopped $service"
    fi
done

trap 'echo "Restore FAILED. These services are left stopped:${stopped:- none}. Fix the cause and run the restore again." >&2' ERR

if [ -n "$stopped" ]; then
    # shellcheck disable=SC2086
    compose stop $stopped
    echo "Stopped:$stopped"
fi

# 3. Restore each database.
for entry in $DATABASES; do
    IFS=: read -r database service secret <<< "$entry"

    backup_tool -dc "/backups/$STAMP/$database.sql.gz" \
        | mysql_root "$service" "$secret"

    echo "Restored $database on $service"
done

trap - ERR

# 4. Start the services again.
if [ -n "$stopped" ]; then
    # shellcheck disable=SC2086
    compose start $stopped
    echo "Started:$stopped"
fi

running="$(compose ps --status running --services)"

# 5. Verify the restored data.
checks_failed=0

if [ -f "$REPO_ROOT/audit/chain.py" ] \
        && grep -q "def verify_chain" "$REPO_ROOT/audit/__init__.py" 2>/dev/null; then
    if is_running admin-audit; then
        # The audit URL is built from the secret file, as at start-up.
        if compose exec -T admin-audit sh -c '
            audit_pw="$(cat /run/secrets/audit_db_password)"
            export EVP_AUDIT_DB_URL="mysql+pymysql://audit_writer:${audit_pw}@db-audit:3306/audit_db"
            unset audit_pw
            exec python -' <<'PY'
import sys

import audit
from audit.events import STREAMS

log = audit.build_audit_log_from_env()
results = [log.verify_chain(stream) for stream in STREAMS]

for result in results:
    state = "ok" if result.ok else "BROKEN"
    print("Audit chain", result.stream, state, result.checked, "entries")

sys.exit(0 if all(result.ok for result in results) else 1)
PY
        then
            echo "Audit chain check passed"
        else
            echo "Audit chain check FAILED" >&2
            checks_failed=1
        fi
    else
        echo "WARNING: admin-audit is not running; the audit chain was not checked." >&2
        checks_failed=1
    fi
else
    echo "WARNING: Workstream B's audit chain check is not merged yet; the audit log was not checked." >&2
fi

if grep -rqs "def verify_ballot_store" "$REPO_ROOT/ballot"; then
    if is_running ballot; then
        if compose exec -T ballot python -c \
            "import sys; from ballot import verify_ballot_store; sys.exit(0 if verify_ballot_store() else 1)"; then
            echo "Ballot store check passed"
        else
            echo "Ballot store check FAILED" >&2
            checks_failed=1
        fi
    else
        echo "WARNING: the ballot service is not running; the ballot store was not checked." >&2
        checks_failed=1
    fi
else
    echo "WARNING: Workstream C's verify_ballot_store is not merged yet; the ballot store was not checked." >&2
fi

# 6. Timing for the drill log.
end_seconds="$(date +%s)"
duration=$((end_seconds - start_seconds))

echo "Restore of backup $STAMP ended at $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
printf 'Total duration: %dm %02ds' "$((duration / 60))" "$((duration % 60))"

if [ "$duration" -le "$RTO_SECONDS" ]; then
    echo " (within the 2 hour RTO)"
else
    echo " (OVER the 2 hour RTO)"
fi

if [ "$checks_failed" -ne 0 ]; then
    echo "Restore finished, but verification did not pass." >&2
    exit 1
fi

echo "Restore finished and verified."
