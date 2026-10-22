#!/usr/bin/env bash
#
# SR-04 / SR-06 / SR-17 / SR-20: Apply database accounts and triggers.
#
# Run once after the databases are up (see deploy/README.md). Safe to
# re-run, for example after Workstream C's ballot tables exist or after
# make_secrets.sh --force.
#
# Security controls:
# - The identity and audit tables are created as root from their owners'
#   models (Workstream A's records.py, Workstream B's admin and audit)
#   (schema_sql.py), so no app account needs CREATE, INDEX or ALTER
# - Least-privilege accounts from deploy/db/roles.sql, each applied only
#   to the MySQL container that holds its database (roles_plan.py)
# - Service passwords read from deploy/secrets/ and piped to mysql on
#   stdin: never on a command line, never printed, never stored
# - Root passwords are read inside each container from its Docker secret
#   file (/run/secrets/...); they never pass through this host shell
# - A GRANT whose table does not exist yet is skipped with a warning
#   instead of failing the whole run
# - Append-only audit log triggers (SR-17) on db-audit and two-person
#   rule triggers (SR-06) on db-identity
# - Everything is checked before anything is applied
#
# Usage (from anywhere):
#   bash deploy/scripts/apply_db_security.sh
#
# Local academic prototype.

set -euo pipefail

if [ "$#" -ne 0 ]; then
    echo "Usage: $0" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$DEPLOY_DIR")"
APP_PYTHON="${EVP_APP_PYTHON:-$REPO_ROOT/.venv/bin/python}"
SECRETS_DIR="$DEPLOY_DIR/secrets"
COMPOSE_FILE="$DEPLOY_DIR/docker-compose.yml"
ROLES_SQL="$DEPLOY_DIR/db/roles.sql"
AUDIT_TRIGGERS_SQL="$DEPLOY_DIR/db/audit_triggers.sql"
DUAL_TRIGGERS_SQL="$DEPLOY_DIR/db/dual_authorisation_triggers.sql"
PLAN="$SCRIPT_DIR/roles_plan.py"
SCHEMA="$SCRIPT_DIR/schema_sql.py"

DB_SERVICES="db-identity db-ballot db-audit"

root_secret_for() {
    case "$1" in
        db-identity) echo "db_identity_root_password" ;;
        db-ballot)   echo "db_ballot_root_password" ;;
        db-audit)    echo "db_audit_root_password" ;;
        *) echo "Unknown database service: $1" >&2; exit 1 ;;
    esac
}

# Run mysql as root inside a database container. The root password is
# read there from its secret file into MYSQL_PWD, so it is never on a
# command line. Extra arguments go to mysql; stdin is passed through.
mysql_root() {
    local service="$1"
    shift

    docker compose -f "$COMPOSE_FILE" exec -T "$service" sh -c \
        'MYSQL_PWD="$(cat "$0")"; export MYSQL_PWD; exec mysql -uroot "$@"' \
        "/run/secrets/$(root_secret_for "$service")" "$@"
}

table_exists() {
    local count

    count="$(mysql_root "$1" -N -B -e \
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = '$2' AND table_name = '$3'" \
        < /dev/null)"

    [ "$count" = "1" ]
}

for tool in docker python3; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        echo "$tool is required" >&2
        exit 1
    fi
done

if ! "$APP_PYTHON" -c "import sqlalchemy" > /dev/null 2>&1; then
    echo "A Python with requirements.txt installed is needed for the schema:" >&2
    echo "create .venv from requirements.txt or set EVP_APP_PYTHON" >&2
    exit 1
fi

# 1. Check everything before applying anything.
python3 "$PLAN" check "$ROLES_SQL" "$SECRETS_DIR"
schema_tables="$("$APP_PYTHON" "$SCHEMA" tables)"

running="$(docker compose -f "$COMPOSE_FILE" ps --status running --services)"

for service in $DB_SERVICES; do
    if ! printf '%s\n' "$running" | grep -qx "$service"; then
        echo "$service is not running. Start the stack first:" >&2
        echo "  docker compose -f deploy/docker-compose.yml up -d --build" >&2
        exit 1
    fi
done

# 2. Identity and audit tables, created as root if missing.
while read -r service database table; do
    if ! table_exists "$service" "$database" "$table"; then
        "$APP_PYTHON" "$SCHEMA" create "$table" | mysql_root "$service"
        echo "Created $database.$table on $service"
    fi
done <<< "$schema_tables"

grant_targets="$(python3 "$PLAN" targets "$ROLES_SQL")"
skipped=""

while read -r service database table; do
    if ! table_exists "$service" "$database" "$table"; then
        echo "WARNING: skipping GRANTs on $database.$table: the table does not exist yet." >&2
        skipped="$skipped $database.$table"
    fi
done <<< "$grant_targets"

# 3. Accounts and GRANTs, one container at a time. The rendered SQL
# (with passwords) goes straight from roles_plan.py into mysql.
for service in $DB_SERVICES; do
    python3 "$PLAN" render "$ROLES_SQL" "$SECRETS_DIR" "$service" "$skipped" \
        | mysql_root "$service"

    echo "Applied database accounts on $service"
done

# 4. Triggers (second layer under the GRANTs).
mysql_root db-audit < "$AUDIT_TRIGGERS_SQL"
echo "Applied audit log triggers on db-audit"

mysql_root db-identity < "$DUAL_TRIGGERS_SQL"
echo "Applied two-person rule triggers on db-identity"

if [ -n "$skipped" ]; then
    echo "WARNING: some GRANTs were skipped:$skipped" >&2
    echo "Re-run this script once those tables exist." >&2
fi
