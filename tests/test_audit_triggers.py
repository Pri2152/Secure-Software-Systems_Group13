"""
SR-17: Database trigger tests (append-only audit table).
"""

from pathlib import Path

import pytest
from sqlalchemy import create_engine, text, update
from sqlalchemy.exc import DatabaseError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from audit.log import AuditLog
from audit.models import APPEND_ONLY_MESSAGE, AuditEntry
from crypto_agility import CryptoService, DEFAULT_POLICY, default_registry
from crypto_agility.keys import KeyStore


REPO_ROOT = Path(__file__).resolve().parent.parent
MYSQL_TRIGGERS = REPO_ROOT / "deploy" / "db" / "audit_triggers.sql"


@pytest.fixture
def audit_log():
    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    log = AuditLog(
        engine,
        crypto=CryptoService(
            default_registry(), DEFAULT_POLICY, KeyStore.ephemeral()
        ),
    )
    log.create_schema()

    for _ in range(3):
        log.record_event("AUTH_FAILURE", stream="identity",
                         actor_type="anonymous", actor_id=None,
                         outcome="failure")

    return log


def run_sql(audit_log, statement):
    with audit_log.engine.begin() as connection:
        connection.execute(text(statement))


def count_rows(audit_log):
    with audit_log.engine.connect() as connection:
        return connection.execute(
            text("SELECT COUNT(*) FROM audit_log")
        ).scalar()


def trigger_names(audit_log):
    with audit_log.engine.connect() as connection:
        return {
            name for (name,) in connection.execute(text(
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"
            ))
        }


# Test 1: Both triggers exist after schema creation
def test_triggers_are_installed(audit_log):
    assert trigger_names(audit_log) == {
        "audit_log_no_update", "audit_log_no_delete"
    }


# Test 2: Direct SQL UPDATE is blocked
def test_sql_update_is_blocked(audit_log):
    with pytest.raises(DatabaseError, match=APPEND_ONLY_MESSAGE):
        run_sql(audit_log, "UPDATE audit_log SET outcome = 'success' "
                           "WHERE seq = 2")

    assert audit_log.verify_chain("identity").ok is True


# Test 3: Direct SQL DELETE is blocked
def test_sql_delete_is_blocked(audit_log):
    with pytest.raises(DatabaseError, match=APPEND_ONLY_MESSAGE):
        run_sql(audit_log, "DELETE FROM audit_log WHERE seq = 2")

    assert count_rows(audit_log) == 3


# Test 4: Deleting the whole log is blocked
def test_delete_all_is_blocked(audit_log):
    with pytest.raises(DatabaseError):
        run_sql(audit_log, "DELETE FROM audit_log")

    assert count_rows(audit_log) == 3


# Test 5: ORM updates are blocked too
def test_orm_update_is_blocked(audit_log):
    with pytest.raises(DatabaseError):
        with Session(audit_log.engine) as db_session, db_session.begin():
            db_session.execute(
                update(AuditEntry)
                .where(AuditEntry.seq == 1)
                .values(actor_id="voter-999")
            )

    assert audit_log.verify_chain("identity").ok is True


# Test 6: ORM deletes are blocked too
def test_orm_delete_is_blocked(audit_log):
    with pytest.raises(DatabaseError):
        with Session(audit_log.engine) as db_session, db_session.begin():
            db_session.delete(db_session.get(AuditEntry, 1))

    assert count_rows(audit_log) == 3


# Test 7: Appending still works (insert-only, not read-only)
def test_insert_still_allowed(audit_log):
    audit_log.record_event("AUTH_SUCCESS", stream="identity",
                           actor_type="voter", actor_id="voter-001",
                           outcome="success")

    assert count_rows(audit_log) == 4
    assert audit_log.verify_chain("identity").checked == 4


# Test 8: Triggers are restored on an existing table at start-up
def test_create_schema_restores_missing_triggers(audit_log):
    run_sql(audit_log, "DROP TRIGGER audit_log_no_update")
    run_sql(audit_log, "DROP TRIGGER audit_log_no_delete")

    audit_log.create_schema()

    assert len(trigger_names(audit_log)) == 2

    with pytest.raises(DatabaseError):
        run_sql(audit_log, "DELETE FROM audit_log")


# Test 9: MySQL deployment script defines both blocking triggers
def test_mysql_trigger_script():
    script = MYSQL_TRIGGERS.read_text(encoding="utf-8")

    for name, operation in (("audit_log_no_update", "UPDATE"),
                            ("audit_log_no_delete", "DELETE")):
        assert f"CREATE TRIGGER {name}" in script
        assert f"BEFORE {operation} ON audit_log" in script

    assert script.count("SIGNAL SQLSTATE '45000'") == 2
    assert APPEND_ONLY_MESSAGE in script
    assert "USE audit_db;" in script
