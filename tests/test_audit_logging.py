"""
SR-17: Master logging routine and sensitive-data filter tests.

Uses an isolated in-memory SQLite audit database
and an injected clock.
"""

import json

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.pool import StaticPool

import audit
import crypto_agility
from audit import AuditNotConfigured, record_event
from audit.filters import MAX_DETAILS_BYTES, REDACTED, sanitize_details
from audit.log import AuditLog
from crypto_agility import CryptoService, DEFAULT_POLICY, default_registry
from crypto_agility.keys import KeyStore


START = datetime(2026, 10, 20, 9, 0, 0, tzinfo=timezone.utc)


def new_crypto():
    return CryptoService(
        default_registry(), DEFAULT_POLICY, KeyStore.ephemeral()
    )


def memory_engine():
    return create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )


@pytest.fixture
def clock():
    now = [START]

    def tick():
        now[0] += timedelta(seconds=1)
        return now[0]

    return tick


@pytest.fixture
def audit_log(clock):
    log = AuditLog(memory_engine(), crypto=new_crypto(), clock=clock)
    log.create_schema()

    return log


@pytest.fixture
def configured(audit_log):
    audit.configure(audit_log)

    yield audit_log

    audit.configure(None)


def stored_rows(audit_log):
    with audit_log.engine.connect() as connection:
        return connection.execute(
            text("SELECT * FROM audit_log ORDER BY id")
        ).mappings().all()


def record(audit_log, **overrides):
    event = {
        "event_type": "AUTH_FAILURE",
        "stream": "identity",
        "actor_type": "anonymous",
        "actor_id": None,
        "outcome": "failure",
        "details": None,
        "source_ip": "203.0.113.10",
    }
    event.update(overrides)
    event_type = event.pop("event_type")

    audit_log.record_event(event_type, **event)


# Test 1: An event is stored with actor, outcome and server UTC time
def test_event_is_stored_with_actor_and_utc_time(audit_log):
    record(
        audit_log,
        event_type="AUTH_SUCCESS",
        actor_type="voter",
        actor_id="voter-001",
        outcome="success",
    )

    row = stored_rows(audit_log)[0]

    assert row["event_type"] == "AUTH_SUCCESS"
    assert row["actor_id"] == "voter-001"
    assert row["outcome"] == "success"
    assert row["timestamp_utc"] == "2026-10-20T09:00:01.000000Z"


# Test 2: Sequence numbers are per stream
def test_sequence_numbers_are_per_stream(audit_log):
    record(audit_log)
    record(audit_log)
    record(audit_log, stream="admin", actor_type="staff",
           actor_id="officer-jane-citizen")

    seqs = [(row["stream"], row["seq"]) for row in stored_rows(audit_log)]

    assert seqs == [("identity", 1), ("identity", 2), ("admin", 1)]


# Test 3: Passwords, TOTP codes, tokens and ballot content are never stored
def test_secrets_are_never_stored(audit_log):
    record(audit_log, details={
        "password": "CorrectPassword123!",
        "TOTP_Code": "123456",
        "csrf_token": "csrf-abc",
        "Session-ID": "sess-xyz",
        "nested": {"api_key": "k-123", "Preferences": [2, 1, 3]},
        "items": [{"ballot": "ciphertext-blob"}],
        "reason": "invalid_credentials",
    })

    stored = stored_rows(audit_log)[0]["details_json"]

    for secret in ("CorrectPassword123!", "123456", "csrf-abc",
                   "sess-xyz", "k-123", "ciphertext-blob", "[2,1,3]"):
        assert secret not in stored

    assert json.loads(stored)["reason"] == "invalid_credentials"
    assert json.loads(stored)["password"] == REDACTED


# Test 4: Ballot stream rejects an actor ID (SR-08)
def test_ballot_stream_rejects_actor_id(audit_log):
    with pytest.raises(ValueError):
        record(audit_log, stream="ballot", event_type="BALLOT_ACCEPTED",
               actor_id="voter-001", source_ip=None)

    assert stored_rows(audit_log) == []


# Test 5: Ballot stream rejects a source IP (SR-08)
def test_ballot_stream_rejects_source_ip(audit_log):
    with pytest.raises(ValueError):
        record(audit_log, stream="ballot", event_type="BALLOT_ACCEPTED",
               source_ip="203.0.113.10")


# Test 6: Anonymous ballot events are accepted
def test_anonymous_ballot_event_is_accepted(audit_log):
    record(audit_log, stream="ballot", event_type="BALLOT_ACCEPTED",
           actor_type="anonymous", outcome="success", source_ip=None)

    row = stored_rows(audit_log)[0]

    assert row["actor_id"] is None
    assert row["source_ip"] is None


# Test 7: Invalid events are rejected and nothing is stored
@pytest.mark.parametrize("overrides", [
    {"event_type": "auth failure"},
    {"event_type": "X"},
    {"event_type": None},
    {"stream": "voting"},
    {"actor_type": "root"},
    {"outcome": "ok"},
    {"actor_id": ""},
    {"actor_id": "a" * 200},
    {"actor_id": 42},
    {"source_ip": "not-an-ip"},
    {"source_ip": "203.0.113.10; DROP TABLE audit_log"},
    {"details": "free text"},
])
def test_invalid_event_is_rejected(audit_log, overrides):
    with pytest.raises(ValueError):
        record(audit_log, **overrides)

    assert stored_rows(audit_log) == []


# Test 8: Oversized details are replaced by a marker
def test_oversized_details_are_capped():
    details = sanitize_details({"note": ["x" * 200] * 40})

    assert details == {"details_truncated": True}
    assert len(json.dumps(details)) < MAX_DETAILS_BYTES


# Test 9: Long strings, deep nesting and odd types are made safe
def test_details_are_normalised():
    details = sanitize_details({
        "long": "y" * 1000,
        "deep": {"a": {"b": {"c": {"d": {"e": 1}}}}},
        "object": object(),
        "nan": float("nan"),
    })

    assert len(details["long"]) == 256
    assert details["deep"]["a"]["b"]["c"] == "[DEPTH-LIMIT]"
    assert details["object"] == "[UNSUPPORTED]"
    assert details["nan"] == "[UNSUPPORTED]"


# Test 10: Naive clock values are refused (UTC is mandatory)
def test_naive_clock_is_refused():
    log = AuditLog(
        memory_engine(),
        crypto=new_crypto(),
        clock=lambda: datetime(2026, 1, 1),
    )
    log.create_schema()

    with pytest.raises(ValueError):
        record(log)


# Test 11: Readers get newest entries first with parsed details
def test_list_events_newest_first(audit_log):
    record(audit_log, details={"reason": "first"})
    record(audit_log, details={"reason": "second"})

    events = audit_log.list_events("identity", limit=1)

    assert len(events) == 1
    assert events[0]["seq"] == 2
    assert events[0]["details"] == {"reason": "second"}


# Test 12: Reader validates stream and limit
@pytest.mark.parametrize("stream, limit", [
    ("other", 10), ("identity", 0), ("identity", 500),
    ("identity", True), ("identity", "10"),
])
def test_list_events_validates_input(audit_log, stream, limit):
    with pytest.raises(ValueError):
        audit_log.list_events(stream, limit)


# Test 13: Module-level record_event uses the configured log
def test_module_record_event(configured):
    record_event(
        "AUTHZ_DENIED",
        stream="identity",
        actor_type="voter",
        actor_id="voter-001",
        outcome="denied",
        details={"permission": "records.read_own"},
    )

    assert stored_rows(configured)[0]["event_type"] == "AUTHZ_DENIED"


# Test 14: Unconfigured audit log fails closed
def test_unconfigured_audit_fails_closed(monkeypatch):
    monkeypatch.delenv("EVP_AUDIT_DB_URL", raising=False)
    audit.configure(None)

    with pytest.raises(AuditNotConfigured):
        record_event("AUTH_SUCCESS", stream="identity",
                     actor_type="voter", actor_id="v", outcome="success")


# Test 15: EVP_AUDIT_DB_URL configures the audit database
def test_env_database_url_configures_audit(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "EVP_AUDIT_DB_URL", f"sqlite:///{tmp_path / 'audit.db'}"
    )
    audit.configure(None)
    crypto_agility.configure(new_crypto())

    try:
        record_event("CONFIG_CHANGED", stream="admin",
                     actor_type="system", actor_id=None, outcome="success")

        events = audit.get_audit_log().list_events("admin")

        assert events[0]["event_type"] == "CONFIG_CHANGED"

    finally:
        audit.get_audit_log().engine.dispose()
        audit.configure(None)
        crypto_agility.configure(None)
