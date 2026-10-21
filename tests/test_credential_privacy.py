"""SR-08 retained-state inspection and transactional privacy failure paths."""

import inspect as python_inspect

import pytest
from sqlalchemy import event, inspect, select
from sqlalchemy.exc import IntegrityError, OperationalError

import audit
import ballot_credentials
import ballot_storage
from ballot_models import AnonymousBallot, BallotCredential, VotingEligibility
from records import db
from test_ballot_credentials import credential_app, issue, seed_voter
from test_credential_acceptance import (
    PAYLOAD, assert_state, credential_ballot, submit,
)
from ballot_credentials import CredentialError


def test_database_schema_has_no_identity_ballot_link(credential_app):
    schema = inspect(db.engine)
    ballot_columns = {column["name"] for column in schema.get_columns("anonymous_ballots")}
    assert ballot_columns == {
        "ballot_id", "election_id", "electoral_division", "encrypted_ballot_json",
        "chain_index", "previous_hash", "record_hash"
    }
    assert schema.get_foreign_keys("anonymous_ballots") == []
    assert {column["name"] for column in schema.get_columns("ballot_credentials")} == {
        "verifier", "voter_id", "election_id", "expires_at"
    }
    for table in schema.get_table_names():
        if table != "anonymous_ballots":
            assert "ballot_id" not in {c["name"] for c in schema.get_columns(table)}
            assert all(
                fk["referred_table"] != "anonymous_ballots"
                for fk in schema.get_foreign_keys(table)
            )


def test_retained_state_has_no_individual_join_or_secrets(credential_ballot, caplog, monkeypatch):
    credential, candidate_id = credential_ballot
    verifier = ballot_credentials.credential_verifier(credential)
    seed_voter("voter-002")
    second = issue("voter-002")
    second_verifier = ballot_credentials.credential_verifier(second)
    caplog.clear()

    def forbid_audit(*args, **kwargs):
        pytest.fail("SR-08 must not emit correlatable ballot audit events")

    monkeypatch.setattr(audit, "record_event", forbid_audit)
    submit(credential, candidate_id)
    submit(second, candidate_id)
    db.session.remove()
    assert BallotCredential.query.count() == 0
    assert all(row.has_voted for row in VotingEligibility.query.all())
    assert AnonymousBallot.query.count() == 2

    schema = inspect(db.engine)
    retained = {}
    for table in db.metadata.sorted_tables:
        if schema.has_table(table.name):
            retained[table.name] = [dict(row) for row in db.session.execute(
                select(table)
            ).mappings()]
    snapshot = str(retained)
    for secret in (credential, second, verifier, second_verifier):
        assert secret not in snapshot
        assert secret not in caplog.text
    ballots = retained["anonymous_ballots"]
    for ballot in ballots:
        assert PAYLOAD not in ballot["encrypted_ballot_json"]
        assert "voter-001" not in str(ballot)
        assert "voter-002" not in str(ballot)
        assert ballot["ballot_id"] not in str({
            name: rows for name, rows in retained.items() if name not in {"anonymous_ballots", "ballot_chain_state"}
        })
    # Election/division identify a cohort, not a unique individual credential.
    assert set(retained["voting_eligibility"][0]) & set(ballots[0]) == {
        "election_id", "electoral_division"
    }
    assert len({ballot["ballot_id"] for ballot in ballots}) == 2
    assert caplog.records == []
    with pytest.raises(CredentialError):
        submit(credential, candidate_id)


def test_storage_interface_never_receives_identity(credential_ballot, monkeypatch):
    calls = []
    original = ballot_credentials.store_anonymous_ballot

    def observe(election_id, electoral_division, encrypted_ballot_json, candidate_id):
        calls.append((election_id, electoral_division, encrypted_ballot_json, candidate_id))
        original(election_id, electoral_division, encrypted_ballot_json, candidate_id)

    monkeypatch.setattr(ballot_credentials, "store_anonymous_ballot", observe)
    submit(*credential_ballot)
    assert calls == [("election-2026", "Melbourne", PAYLOAD, credential_ballot[1])]
    assert list(python_inspect.signature(ballot_storage.store_anonymous_ballot).parameters) == [
        "election_id", "electoral_division", "encrypted_ballot_json", "candidate_id"
    ]
    assert "voter_id" not in python_inspect.signature(
        ballot_credentials.accept_ballot_with_credential
    ).parameters


def test_insert_failure_restores_consumed_credential(credential_ballot):
    observed = []

    def fail(mapper, connection, target):
        observed.append((
            connection.execute(select(VotingEligibility.has_voted)).scalar_one(),
            connection.execute(select(BallotCredential.verifier)).all(),
        ))
        raise IntegrityError("synthetic private database error", {}, Exception())

    event.listen(AnonymousBallot, "before_insert", fail)
    try:
        with pytest.raises(CredentialError, match="^Credential authorisation failed$"):
            submit(*credential_ballot)
    finally:
        event.remove(AnonymousBallot, "before_insert", fail)
    assert observed == [(True, [])]
    assert_state()
    submit(*credential_ballot)
    assert_state(True, 1, 0)


def test_commit_failure_restores_all_three_changes(credential_ballot, monkeypatch):
    session = db.session()
    observed = []

    def fail():
        session.flush()
        observed.append((
            session.execute(select(VotingEligibility.has_voted)).scalar_one(),
            session.query(BallotCredential).count(),
            session.query(AnonymousBallot).count(),
        ))
        raise OperationalError("synthetic private commit error", {}, Exception())

    monkeypatch.setattr(session, "commit", fail)
    with pytest.raises(CredentialError, match="^Credential authorisation failed$"):
        submit(*credential_ballot)
    assert observed == [(True, 0, 1)]
    assert_state()
    submit(*credential_ballot)
    assert_state(True, 1, 0)


def test_credential_delete_failure_rolls_back_status(credential_ballot):
    engine = db.engine
    observed = []

    def fail(connection, cursor, statement, parameters, context, many):
        if statement.lstrip().upper().startswith("DELETE FROM BALLOT_CREDENTIALS"):
            observed.append(connection.execute(
                select(VotingEligibility.has_voted)
            ).scalar_one())
            raise OperationalError("synthetic delete failure", {}, Exception())

    event.listen(engine, "before_cursor_execute", fail)
    try:
        with pytest.raises(CredentialError):
            submit(*credential_ballot)
    finally:
        event.remove(engine, "before_cursor_execute", fail)
    assert observed == [True]
    assert_state()
    submit(*credential_ballot)
    assert_state(True, 1, 0)


def test_expiry_during_validation_rolls_back_claim(credential_ballot):
    from datetime import timedelta
    from test_ballot_credentials import NOW

    moments = iter([NOW, NOW + timedelta(seconds=600)])
    with pytest.raises(CredentialError):
        ballot_credentials.accept_ballot_with_credential(
            *credential_ballot, PAYLOAD, clock=lambda: next(moments)
        )
    assert_state()


def test_failed_replacement_preserves_previous_credential(credential_ballot, monkeypatch):
    session = db.session()

    def fail():
        session.flush()
        raise OperationalError("synthetic issue commit failure", {}, Exception())

    monkeypatch.setattr(session, "commit", fail)
    with pytest.raises(CredentialError):
        issue()
    assert_state()
    submit(*credential_ballot)
    assert_state(True, 1, 0)
