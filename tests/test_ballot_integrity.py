"""SR-10 mandatory full-chain and AEAD verification before tally."""

import pytest
from sqlalchemy import create_engine, update

import audit
import ballot_integrity
from audit import AuditLog
from ballot_chain import append_ballot
from ballot_integrity import BallotIntegrityError, verified_candidate_ids_for_tally, verify_ballot_chain
from ballot_models import AnonymousBallot, BallotChainState
from records import db
from test_ballot_models import db_app


@pytest.fixture
def integrity_chain(db_app, ballot_crypto, monkeypatch):
    audit_log = AuditLog(create_engine("sqlite:///:memory:"), crypto=ballot_crypto)
    audit_log.create_schema()
    monkeypatch.setattr(audit, "record_event", audit_log.record_event)
    for candidate in (7, 8, 7):
        append_ballot("election-2026", "Melbourne", "opaque", candidate)
        db.session.commit()
    yield audit_log
    audit_log.engine.dispose()


def tally():
    return verified_candidate_ids_for_tally("election-2026", "Melbourne")


def assert_event(audit_log):
    entries = audit_log.list_events(stream="ballot")
    assert len(entries) == 1
    entry = entries[0]
    assert entry["event_type"] == "BALLOT_INTEGRITY_FAILURE"
    assert entry["actor_id"] is None
    assert entry["source_ip"] is None
    assert entry["actor_type"] == "anonymous"
    assert entry["outcome"] == "failure"
    assert entry["details"] == {}


def test_trusted_tally_receives_only_fully_verified_selections(integrity_chain):
    assert verify_ballot_chain("election-2026", "Melbourne") is True
    assert tally() == (7, 8, 7)
    assert integrity_chain.list_events(stream="ballot") == []


def test_last_record_failure_returns_no_partial_tally_and_emits_event(integrity_chain):
    db.session.execute(update(AnonymousBallot).where(AnonymousBallot.chain_index == 3)
                       .values(record_hash="sha256:" + "f" * 64))
    db.session.commit()
    received = []
    with pytest.raises(BallotIntegrityError, match="^Ballot integrity verification failed$"):
        received.append(tally())
    assert received == []
    assert_event(integrity_chain)


def test_missing_checkpoint_is_not_an_empty_valid_election(integrity_chain):
    db.session.delete(BallotChainState.query.one())
    db.session.commit()
    with pytest.raises(BallotIntegrityError):
        tally()
    assert_event(integrity_chain)


def test_decryption_key_failure_is_integrity_failure(integrity_chain, ballot_crypto, monkeypatch):
    from crypto_agility import KeyNotFound

    def fail(*args, **kwargs):
        raise KeyNotFound("private key diagnostic")

    monkeypatch.setattr(ballot_crypto, "decrypt", fail)
    with pytest.raises(BallotIntegrityError):
        tally()
    assert_event(integrity_chain)


def test_audit_unavailability_still_fails_closed_with_generic_signal(integrity_chain, monkeypatch, caplog):
    def fail(*args, **kwargs):
        raise RuntimeError("private audit diagnostic")

    monkeypatch.setattr(audit, "record_event", fail)
    db.session.execute(update(AnonymousBallot).values(record_hash="sha256:" + "f" * 64))
    db.session.commit()
    with pytest.raises(BallotIntegrityError):
        tally()
    assert [record.getMessage() for record in caplog.records] == [
        "BALLOT_INTEGRITY_FAILURE audit_unavailable"
    ]
