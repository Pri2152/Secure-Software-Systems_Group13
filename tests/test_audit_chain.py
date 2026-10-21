"""
SR-17: Hash-chain tamper detection tests.

Each attack runs raw SQL against the audit database,
as an insider with database access would. Triggers
(once present) are dropped first to simulate a fully
privileged attacker; the chain must still expose the
change at the exact sequence number.
"""

import json

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.pool import StaticPool

from audit.chain import (
    REASON_BROKEN_LINK,
    REASON_DUPLICATE,
    REASON_INVALID_MAC,
    REASON_MISSING,
    canonical_json,
    chain_message,
    genesis_hash,
)
from audit.log import AuditLog
from audit.models import AuditEntry
from crypto_agility import CryptoService, DEFAULT_POLICY, default_registry
from crypto_agility.algorithms import MAC
from crypto_agility.keys import KeyStore


ENTRIES = 5


def new_crypto():
    return CryptoService(
        default_registry(), DEFAULT_POLICY, KeyStore.ephemeral()
    )


@pytest.fixture
def audit_log():
    now = [datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc)]

    def clock():
        now[0] += timedelta(seconds=1)
        return now[0]

    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    log = AuditLog(engine, crypto=new_crypto(), clock=clock)
    log.create_schema()

    return log


@pytest.fixture
def filled(audit_log):
    for number in range(ENTRIES):
        audit_log.record_event(
            "AUTH_FAILURE",
            stream="identity",
            actor_type="anonymous",
            actor_id=None,
            outcome="failure",
            details={"attempt": number + 1},
            source_ip="203.0.113.10",
        )

    return audit_log


def attacker_sql(audit_log, statement, **params):
    """Run SQL with every audit trigger removed first."""

    with audit_log.engine.begin() as connection:
        for name in ("audit_log_no_update", "audit_log_no_delete"):
            connection.execute(text(f"DROP TRIGGER IF EXISTS {name}"))

        connection.execute(text(statement), params)


def row(audit_log, seq, stream="identity"):
    with audit_log.engine.connect() as connection:
        return connection.execute(
            text("SELECT * FROM audit_log WHERE stream = :s AND seq = :q"),
            {"s": stream, "q": seq},
        ).mappings().one()


def assert_broken(result, seq, reason):
    assert result.ok is False
    assert result.broken_at_seq == seq
    assert result.reason == reason


# Test 1: Untouched chain verifies
def test_intact_chain_verifies(filled):
    result = filled.verify_chain("identity")

    assert result.ok is True
    assert result.checked == ENTRIES
    assert result.broken_at_seq is None


# Test 2: Every stream has its own genesis and chain
def test_streams_have_independent_genesis(filled):
    filled.record_event("CONFIG_CHANGED", stream="admin",
                        actor_type="staff", actor_id="admin-ada-lovelace",
                        outcome="success")
    filled.record_event("BALLOT_ACCEPTED", stream="ballot",
                        actor_type="anonymous", actor_id=None,
                        outcome="success")

    assert row(filled, 1)["prev_hash"] == genesis_hash("identity")
    assert row(filled, 1, "admin")["prev_hash"] == genesis_hash("admin")
    assert row(filled, 1, "ballot")["prev_hash"] == genesis_hash("ballot")

    for stream in ("identity", "admin", "ballot"):
        assert filled.verify_chain(stream).ok is True


# Test 3: Each entry links to the previous entry's hash
def test_entries_are_linked(filled):
    assert row(filled, 3)["prev_hash"] == row(filled, 2)["entry_hash"]


# Test 4: Stored hash is a self-describing MAC envelope
def test_entry_hash_records_algorithm_and_key(filled):
    envelope = json.loads(row(filled, 1)["entry_hash"])

    assert envelope["alg"] == "hmac-sha256"
    assert envelope["kid"] == "audit.hmac-sha256.v1"


# Test 5: Edited details are detected at the exact seq
def test_edited_details_detected(filled):
    attacker_sql(filled, "UPDATE audit_log SET details_json = :d "
                 "WHERE stream = 'identity' AND seq = 3", d='{"attempt":99}')

    assert_broken(filled.verify_chain("identity"), 3, REASON_INVALID_MAC)


# Test 6: Edited actor, outcome or timestamp is detected
@pytest.mark.parametrize("column, value", [
    ("actor_id", "voter-002"),
    ("outcome", "success"),
    ("timestamp_utc", "2026-10-19T00:00:00.000000Z"),
    ("event_type", "AUTH_SUCCESS"),
    ("source_ip", "198.51.100.7"),
])
def test_edited_columns_detected(filled, column, value):
    attacker_sql(filled, f"UPDATE audit_log SET {column} = :v "
                 "WHERE stream = 'identity' AND seq = 2", v=value)

    assert_broken(filled.verify_chain("identity"), 2, REASON_INVALID_MAC)


# Test 7: Deleted entry is detected as a gap
def test_deleted_entry_detected(filled):
    attacker_sql(filled, "DELETE FROM audit_log "
                 "WHERE stream = 'identity' AND seq = 3")

    assert_broken(filled.verify_chain("identity"), 3, REASON_MISSING)


# Test 8: Deleting the first entry is detected
def test_deleted_first_entry_detected(filled):
    attacker_sql(filled, "DELETE FROM audit_log "
                 "WHERE stream = 'identity' AND seq = 1")

    assert_broken(filled.verify_chain("identity"), 1, REASON_MISSING)


# Test 9: Reordered entries (swapped seq numbers) are detected
def test_reordered_entries_detected(filled):
    attacker_sql(filled, "UPDATE audit_log SET seq = -1 "
                 "WHERE stream = 'identity' AND seq = 2")
    attacker_sql(filled, "UPDATE audit_log SET seq = 2 "
                 "WHERE stream = 'identity' AND seq = 4")
    attacker_sql(filled, "UPDATE audit_log SET seq = 4 "
                 "WHERE stream = 'identity' AND seq = -1")

    assert_broken(filled.verify_chain("identity"), 2, REASON_BROKEN_LINK)


# Test 10: Forged entry with a made-up MAC is detected
def test_forged_entry_detected(filled):
    last = row(filled, ENTRIES)
    attacker = new_crypto()

    forged = AuditEntry(
        stream="identity", seq=ENTRIES + 1,
        timestamp_utc="2026-10-20T09:00:10.000000Z",
        event_type="AUTH_SUCCESS", actor_type="voter",
        actor_id="voter-001", source_ip=None, outcome="success",
        details_json="{}",
    )
    # Attacker's own key, but a correct-looking key ID
    envelope = attacker.mac("audit", chain_message(last["entry_hash"], forged))

    attacker_sql(
        filled,
        "INSERT INTO audit_log (stream, seq, timestamp_utc, event_type, "
        "actor_type, actor_id, source_ip, outcome, details_json, "
        "prev_hash, entry_hash) VALUES ('identity', :seq, :ts, "
        "'AUTH_SUCCESS', 'voter', 'voter-001', NULL, 'success', '{}', "
        ":prev, :hash)",
        seq=ENTRIES + 1, ts=forged.timestamp_utc,
        prev=last["entry_hash"], hash=canonical_json(envelope),
    )

    assert_broken(
        filled.verify_chain("identity"), ENTRIES + 1, REASON_INVALID_MAC
    )


# Test 11: Rewriting an entry and relinking the next one is still detected
def test_rewritten_and_relinked_entry_detected(filled):
    attacker_sql(filled, "UPDATE audit_log SET entry_hash = :h "
                 "WHERE stream = 'identity' AND seq = 3",
                 h='{"alg":"hmac-sha256","kid":"audit.hmac-sha256.v1",'
                   '"sig":"AAAA","v":1}')
    attacker_sql(filled, "UPDATE audit_log SET prev_hash = :h "
                 "WHERE stream = 'identity' AND seq = 4",
                 h=row(filled, 3)["entry_hash"])

    assert_broken(filled.verify_chain("identity"), 3, REASON_INVALID_MAC)


# Test 12: Moving an entry to another stream breaks both chains
def test_entry_moved_between_streams_detected(filled):
    attacker_sql(filled, "UPDATE audit_log SET stream = 'admin' "
                 "WHERE stream = 'identity' AND seq = 1")

    assert_broken(filled.verify_chain("identity"), 1, REASON_MISSING)
    assert_broken(filled.verify_chain("admin"), 1, REASON_BROKEN_LINK)


# Test 13: Duplicate seq after dropping the unique index is detected
def test_duplicate_entry_detected(filled):
    attacker_sql(filled, "DROP INDEX IF EXISTS uq_audit_stream_seq")
    attacker_sql(filled, "CREATE TABLE copy AS SELECT * FROM audit_log")
    attacker_sql(filled, "DROP TABLE audit_log")
    attacker_sql(filled, "CREATE TABLE audit_log AS SELECT * FROM copy")
    attacker_sql(filled, "INSERT INTO audit_log SELECT * FROM copy "
                 "WHERE seq = 2")

    assert_broken(filled.verify_chain("identity"), 2, REASON_DUPLICATE)


# Test 14: Garbage in entry_hash is reported, not raised
def test_garbage_entry_hash_detected(filled):
    attacker_sql(filled, "UPDATE audit_log SET entry_hash = 'nonsense' "
                 "WHERE stream = 'identity' AND seq = 5")

    assert_broken(filled.verify_chain("identity"), 5, REASON_INVALID_MAC)


# Test 15: Old entries verify after the MAC algorithm changes (SR-14)
def test_chain_survives_mac_algorithm_change(filled):
    filled.crypto = filled.crypto.with_policy(
        DEFAULT_POLICY.with_default(MAC, "hmac-sha3-256")
    )

    filled.record_event("AUTH_SUCCESS", stream="identity",
                        actor_type="voter", actor_id="voter-001",
                        outcome="success")

    newest = json.loads(row(filled, ENTRIES + 1)["entry_hash"])
    oldest = json.loads(row(filled, 1)["entry_hash"])

    assert newest["alg"] == "hmac-sha3-256"
    assert oldest["alg"] == "hmac-sha256"
    assert filled.verify_chain("identity").ok is True


# Test 16: A retired MAC algorithm makes its entries fail verification
def test_retired_mac_algorithm_fails(filled):
    filled.crypto = filled.crypto.with_policy(
        DEFAULT_POLICY.with_default(MAC, "hmac-sha3-256")
        .with_allowed(MAC, {"hmac-sha3-256"})
    )

    assert_broken(filled.verify_chain("identity"), 1, REASON_INVALID_MAC)


# Test 17: Verifying with another deployment's key fails
def test_chain_with_wrong_key_fails(filled):
    filled.crypto = new_crypto()

    assert_broken(filled.verify_chain("identity"), 1, REASON_INVALID_MAC)


# Test 18: Empty stream verifies with nothing checked
def test_empty_stream_verifies(audit_log):
    result = audit_log.verify_chain("ballot")

    assert result.ok is True
    assert result.checked == 0


# Test 19: MAC failure stores nothing (fail closed)
def test_mac_failure_stores_nothing(audit_log):
    class BrokenCrypto:
        def mac(self, purpose, data):
            raise RuntimeError("crypto unavailable")

    audit_log.crypto = BrokenCrypto()

    with pytest.raises(RuntimeError):
        audit_log.record_event("AUTH_SUCCESS", stream="identity",
                               actor_type="voter", actor_id="voter-001",
                               outcome="success")

    with audit_log.engine.connect() as connection:
        count = connection.execute(
            text("SELECT COUNT(*) FROM audit_log")
        ).scalar()

    assert count == 0


# Test 20: Unknown stream is refused by the verifier
def test_verify_unknown_stream_is_refused(audit_log):
    with pytest.raises(ValueError):
        audit_log.verify_chain("voting")


# Test 21: Result serialises for the auditor endpoint
def test_chain_result_to_dict(filled):
    assert filled.verify_chain("identity").to_dict() == {
        "stream": "identity", "ok": True, "checked": ENTRIES,
        "broken_at_seq": None, "reason": None,
    }
