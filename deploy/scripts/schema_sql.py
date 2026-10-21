"""
SR-20: MySQL DDL for the identity and audit tables, run as root.

The app accounts in deploy/db/roles.sql hold data privileges
only (no CREATE), so apply_db_security.sh creates these tables
as root before it applies the GRANTs and triggers. The DDL is
generated from the owners' own SQLAlchemy models (Workstream
A's records.py, Workstream B's admin and audit models), so it
always matches the code. Called by apply_db_security.sh; not
meant to be run directly.

Commands:
  tables         print "<service> <db> <table>" in creation order
  create TABLE   print the CREATE TABLE and CREATE INDEX statements

Security controls:
- App accounts never need CREATE, INDEX or ALTER privileges
- Only the listed tables can be rendered; ballot tables
  (Workstream C) are never created here
- Prints SQL only; holds no passwords or keys

Local academic prototype.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy.dialects import mysql  # noqa: E402
from sqlalchemy.schema import CreateIndex, CreateTable  # noqa: E402

from admin.models import (  # noqa: E402
    Candidate,
    ElevationGrant,
    PendingOperation,
    StaffAccount,
)
from audit.models import AuditEntry  # noqa: E402
from records import AddressRecord, EnrolmentRecord  # noqa: E402


# (service, database, model) in foreign-key order.
TABLES = (
    ("db-identity", "identity_db", EnrolmentRecord),
    ("db-identity", "identity_db", AddressRecord),
    ("db-identity", "identity_db", StaffAccount),
    ("db-identity", "identity_db", ElevationGrant),
    ("db-identity", "identity_db", Candidate),
    ("db-identity", "identity_db", PendingOperation),
    ("db-audit", "audit_db", AuditEntry),
)


def tables():
    return [
        f"{service} {database} {model.__table__.name}"
        for service, database, model in TABLES
    ]


def create(name):
    for _, database, model in TABLES:
        table = model.__table__

        if table.name != name:
            continue

        dialect = mysql.dialect()
        statements = [f"USE {database}"]
        statements.append(str(CreateTable(table).compile(dialect=dialect)))
        statements.extend(
            str(CreateIndex(index).compile(dialect=dialect))
            for index in sorted(table.indexes, key=lambda index: index.name)
        )

        return ";\n".join(statement.strip() for statement in statements) + ";\n"

    raise KeyError(name)


def main(arguments):
    if arguments == ["tables"]:
        print("\n".join(tables()))
        return 0

    if len(arguments) == 2 and arguments[0] == "create":
        try:
            sys.stdout.write(create(arguments[1]))
        except KeyError:
            print("Unknown table", file=sys.stderr)
            return 1
        return 0

    print("Usage: schema_sql.py tables | create TABLE", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
