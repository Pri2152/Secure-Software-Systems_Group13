"""SR-10 encrypted append construction, checkpoint and database constraints."""

import pytest
from sqlalchemy import event, select, update
from sqlalchemy.exc import IntegrityError

from ballot_chain import (
    BallotChainError, append_ballot, authenticate_state, compute_record_hash,
    genesis_hash, record_metadata,
)
from ballot_models import AnonymousBallot, BallotChainState
from ballot_protection import _open_ballot
from records import db
from test_ballot_models import db_app


def append(candidate_id=7, payload="opaque"):
    append_ballot("election-2026", "Melbourne", payload, candidate_id)
    db.session.commit()


def test_encrypted_records_link_to_authenticated_count_and_head(db_app):
    append(7)
    append(8)
    records = db.session.execute(select(AnonymousBallot).order_by(AnonymousBallot.chain_index)).scalars().all()
    assert [row.chain_index for row in records] == [1, 2]
    assert records[0].previous_hash == genesis_hash("election-2026", "Melbourne")
    assert records[1].previous_hash == records[0].record_hash
    assert all(row.record_hash == compute_record_hash(row) for row in records)
    state = BallotChainState.query.one()
    authenticate_state(state)
    assert state.record_count == 2
    assert state.head_hash == records[-1].record_hash
    assert [_open_ballot(row.encrypted_ballot_json, record_metadata(row))["candidate_id"]
            for row in records] == [7, 8]


def test_chain_partition_has_independent_genesis_and_count(db_app):
    append()
    append_ballot("election-2027", "Sydney", "opaque", 8)
    db.session.commit()
    assert BallotChainState.query.count() == 2
    states = BallotChainState.query.all()
    assert all(state.record_count == 1 for state in states)
    assert genesis_hash("election-2026", "Melbourne") != genesis_hash("election-2027", "Sydney")


def test_duplicate_chain_position_is_rejected_by_database(db_app):
    append()
    row = AnonymousBallot.query.one()
    db.session.add(AnonymousBallot(
        ballot_id="b" * 64, election_id=row.election_id, electoral_division=row.electoral_division,
        chain_index=row.chain_index, previous_hash=row.previous_hash,
        record_hash=row.record_hash, encrypted_ballot_json=row.encrypted_ballot_json,
    ))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()
    assert AnonymousBallot.query.count() == 1


def test_existing_ballots_without_checkpoint_cannot_bootstrap(db_app):
    append()
    db.session.delete(BallotChainState.query.one())
    db.session.commit()
    with pytest.raises(BallotChainError):
        append_ballot("election-2026", "Melbourne", "opaque", 8)
    db.session.rollback()
    assert AnonymousBallot.query.count() == 1


def test_forged_checkpoint_prevents_append(db_app):
    append()
    db.session.execute(update(BallotChainState).values(record_count=0))
    db.session.commit()
    with pytest.raises(BallotChainError):
        append_ballot("election-2026", "Melbourne", "opaque", 8)
    db.session.rollback()
    assert AnonymousBallot.query.count() == 1


def test_conditional_chain_claim_refuses_changed_state(db_app):
    append()
    engine = db.engine
    changed = []

    def change_before_claim(connection, cursor, statement, parameters, context, many):
        if statement.upper().startswith("UPDATE BALLOT_CHAIN_STATE") and not changed:
            changed.append(True)
            connection.execute(update(BallotChainState).values(record_count=99))

    event.listen(engine, "before_cursor_execute", change_before_claim)
    try:
        with pytest.raises(BallotChainError):
            append_ballot("election-2026", "Melbourne", "opaque", 8)
    finally:
        event.remove(engine, "before_cursor_execute", change_before_claim)
        db.session.rollback()
    assert changed == [True]
    assert AnonymousBallot.query.count() == 1
    assert BallotChainState.query.one().record_count == 1
