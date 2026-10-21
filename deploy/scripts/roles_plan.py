"""
SR-04 / SR-20: Split deploy/db/roles.sql per database container.

Each database lives in its own MySQL container, so every
user and GRANT in roles.sql must be applied only to the
container that holds its database. Called by
apply_db_security.sh; not meant to be run directly.

Commands:
  check   ROLES SECRETS            validate every password file
  targets ROLES                    print "<service> <db> <table>" per GRANT
  render  ROLES SECRETS SERVICE [SKIP]
                                   print the SQL for one container;
                                   SKIP is a space-separated list of
                                   db.table GRANT targets to leave out

Security controls:
- Users and GRANTs go only to the container holding their
  database (compartment separation)
- Only CREATE DATABASE, CREATE USER, GRANT and FLUSH
  PRIVILEGES statements are accepted, and GRANTs only of
  SELECT, INSERT, UPDATE or DELETE on one named table;
  anything else in roles.sql is refused
- Passwords come from deploy/secrets/<placeholder in lower
  case> and must be at least 32 URL-safe characters, so
  they cannot break out of the SQL string
- Rendered SQL is written only to stdout, for piping
  straight into mysql; it is never stored or logged
- Error messages name files and placeholders, never values

Local academic prototype.
"""

import re
import sys
from pathlib import Path


SERVICES = {
    "identity_db": "db-identity",
    "ballot_db": "db-ballot",
    "audit_db": "db-audit",
}

NAME = r"[a-z_][a-z0-9_]{0,63}"
PASSWORD_PATTERN = re.compile(r"[A-Za-z0-9_-]{32,256}")
ALLOWED_PRIVILEGES = frozenset({"SELECT", "INSERT", "UPDATE", "DELETE"})

CREATE_DATABASE = re.compile(
    rf"CREATE DATABASE IF NOT EXISTS (?P<db>{NAME})", re.IGNORECASE
)
CREATE_USER = re.compile(
    rf"CREATE USER IF NOT EXISTS '(?P<user>{NAME})'@'(?P<host>[%a-z0-9.]+)' "
    r"IDENTIFIED BY '\$\{(?P<placeholder>[A-Z][A-Z0-9_]*)\}'",
    re.IGNORECASE,
)
GRANT = re.compile(
    rf"GRANT (?P<privileges>[A-Z, ]+) ON (?P<db>{NAME})\.(?P<table>{NAME}) "
    rf"TO '(?P<user>{NAME})'@'(?P<host>[%a-z0-9.]+)'",
    re.IGNORECASE,
)
FLUSH = re.compile(r"FLUSH PRIVILEGES", re.IGNORECASE)


class PlanError(Exception):
    pass


def statements(text):
    text = re.sub(r"--[^\n]*", "", text)

    return [
        " ".join(statement.split())
        for statement in text.split(";")
        if statement.strip()
    ]


def parse(roles_path):
    users, grants = {}, []

    for statement in statements(Path(roles_path).read_text("utf-8")):
        if CREATE_DATABASE.fullmatch(statement) or FLUSH.fullmatch(statement):
            continue

        if match := CREATE_USER.fullmatch(statement):
            users[match["user"]] = match
            continue

        if match := GRANT.fullmatch(statement):
            if match["db"] not in SERVICES:
                raise PlanError(f"Unknown database in GRANT: {match['db']}")
            if match["user"] not in users:
                raise PlanError(f"GRANT for unknown user: {match['user']}")
            privileges = {
                part.strip().upper() for part in match["privileges"].split(",")
            }
            if not privileges <= ALLOWED_PRIVILEGES:
                raise PlanError("GRANT uses a privilege that is not allowed")
            grants.append(match)
            continue

        raise PlanError("roles.sql contains an unsupported statement")

    services = {}

    for grant in grants:
        services.setdefault(grant["user"], set()).add(SERVICES[grant["db"]])

    for user, found in services.items():
        if len(found) != 1:
            raise PlanError(f"User {user} has GRANTs on more than one server")

    return users, grants, {user: found.pop() for user, found in services.items()}


def read_password(secrets_dir, placeholder):
    path = Path(secrets_dir) / placeholder.lower()

    try:
        value = path.read_text("ascii").strip()
    except (OSError, UnicodeDecodeError):
        raise PlanError(
            f"Missing or unreadable deploy/secrets/{path.name} "
            "(run make_secrets.sh)"
        ) from None

    if not PASSWORD_PATTERN.fullmatch(value):
        raise PlanError(
            f"deploy/secrets/{path.name} is not a strong URL-safe password"
        )

    return value


def check(roles_path, secrets_dir):
    users, _, _ = parse(roles_path)

    for match in users.values():
        read_password(secrets_dir, match["placeholder"])


def targets(roles_path):
    _, grants, _ = parse(roles_path)
    seen = []

    for grant in grants:
        line = f"{SERVICES[grant['db']]} {grant['db']} {grant['table']}"
        if line not in seen:
            seen.append(line)

    return seen


def render(roles_path, secrets_dir, service, skip=""):
    if service not in SERVICES.values():
        raise PlanError(f"Unknown database service: {service}")

    users, grants, user_service = parse(roles_path)
    skipped = set(skip.split())
    database = next(db for db, name in SERVICES.items() if name == service)
    lines = [f"CREATE DATABASE IF NOT EXISTS {database};"]

    for user, match in users.items():
        if user_service.get(user) != service:
            continue

        account = f"'{user}'@'{match['host']}'"
        password = read_password(secrets_dir, match["placeholder"])

        # ALTER keeps the password in step after make_secrets.sh --force.
        lines.append(
            f"CREATE USER IF NOT EXISTS {account} IDENTIFIED BY '{password}';"
        )
        lines.append(f"ALTER USER {account} IDENTIFIED BY '{password}';")

    for grant in grants:
        if SERVICES[grant["db"]] != service:
            continue
        if f"{grant['db']}.{grant['table']}" in skipped:
            continue

        privileges = ", ".join(
            part.strip().upper() for part in grant["privileges"].split(",")
        )
        lines.append(
            f"GRANT {privileges} ON {grant['db']}.{grant['table']} "
            f"TO '{grant['user']}'@'{grant['host']}';"
        )

    lines.append("FLUSH PRIVILEGES;")

    return "\n".join(lines) + "\n"


def main(arguments):
    try:
        if arguments[:1] == ["check"] and len(arguments) == 3:
            check(*arguments[1:])
        elif arguments[:1] == ["targets"] and len(arguments) == 2:
            print("\n".join(targets(arguments[1])))
        elif arguments[:1] == ["render"] and len(arguments) in (4, 5):
            sys.stdout.write(render(*arguments[1:]))
        else:
            print("Usage: roles_plan.py check|targets|render ...",
                  file=sys.stderr)
            return 2
    except PlanError as error:
        print(error, file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
