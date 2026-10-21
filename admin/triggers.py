"""
SR-06: Database trigger backstop for the two-person rule.

Security controls:
- Independent of the Python code: the database itself
  refuses to store an operation as EXECUTED unless two
  distinct officers are recorded (approver_id set and
  different from proposer_id), on INSERT and UPDATE
- An EXECUTED operation can never be changed or
  deleted afterwards (no replay, no rewriting history)
- SQLite triggers are created with the table and can be
  re-installed idempotently at start-up; the MySQL
  equivalent is deploy/db/dual_authorisation_triggers.sql

Local academic prototype.
"""

from sqlalchemy import DDL, event

from .models import PendingOperation


TWO_PERSON_MESSAGE = "two distinct officers required"
EXECUTED_FINAL_MESSAGE = "executed operations are final"

ONE_OFFICER = (
    "NEW.status = 'EXECUTED' AND "
    "(NEW.approver_id IS NULL OR NEW.approver_id = NEW.proposer_id)"
)

SQLITE_TRIGGERS = (
    ("pending_operations_two_person_insert", "BEFORE INSERT",
     ONE_OFFICER, TWO_PERSON_MESSAGE),
    ("pending_operations_two_person_update", "BEFORE UPDATE",
     ONE_OFFICER, TWO_PERSON_MESSAGE),
    ("pending_operations_executed_no_update", "BEFORE UPDATE",
     "OLD.status = 'EXECUTED'", EXECUTED_FINAL_MESSAGE),
    ("pending_operations_executed_no_delete", "BEFORE DELETE",
     "OLD.status = 'EXECUTED'", EXECUTED_FINAL_MESSAGE),
)


def _sqlite_trigger(name, timing, condition, message) -> DDL:
    return DDL(
        f"CREATE TRIGGER IF NOT EXISTS {name} {timing} "
        f"ON {PendingOperation.__tablename__} "
        f"WHEN {condition} "
        f"BEGIN SELECT RAISE(ABORT, '{message}'); END"
    ).execute_if(dialect="sqlite")


for _definition in SQLITE_TRIGGERS:
    event.listen(
        PendingOperation.__table__,
        "after_create",
        _sqlite_trigger(*_definition),
    )


def ensure_dual_authorisation_triggers(engine) -> None:
    """Re-create the SQLite triggers on an existing table."""

    if engine.dialect.name != "sqlite":
        return

    with engine.begin() as connection:
        for definition in SQLITE_TRIGGERS:
            connection.execute(_sqlite_trigger(*definition))
