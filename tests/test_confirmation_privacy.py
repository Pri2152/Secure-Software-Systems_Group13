"""SR-09 retained-state, response and log inspection with distinct preferences."""

import pytest
from sqlalchemy import MetaData, event, inspect, select

import audit
import ballot_credentials
from admin.candidates import add_draft_candidate
from ballot_confirmation import is_confirmation_reference
from ballot_models import AnonymousBallot, BallotCredential, VotingEligibility
from records import db
from test_ballot_credentials import NOW, credential_app, issue, seed_voter


def retained_snapshot():
    metadata = MetaData()
    metadata.reflect(bind=db.engine)
    return {
        name: [dict(row) for row in db.session.execute(select(table)).mappings()]
        for name, table in metadata.tables.items()
    }


@pytest.fixture
def different_preferences(credential_app):
    seed_voter("voter-002")
    candidates = [
        add_draft_candidate(
            db.session, division="Melbourne", name=name,
            party=party, position_in_group=position,
        )
        for name, party, position in (
            ("Candidate Alpha", "Alpha Party", 1),
            ("Candidate Beta", "Beta Party", 2),
        )
    ]
    for candidate in candidates:
        candidate.status = "FINAL"
    db.session.commit()
    ids = [candidate.id for candidate in candidates]
    credentials = [issue("voter-001"), issue("voter-002")]
    payloads = ['{"alg":"test","ct":"opaque-alpha"}',
                '{"alg":"test","ct":"opaque-beta"}']
    return credentials, ids, payloads


def vote_different_preferences(setup):
    credentials, candidate_ids, payloads = setup
    return [
        ballot_credentials.accept_ballot_with_credential(
            credential, candidate_id, payload, clock=lambda: NOW
        )
        for credential, candidate_id, payload in zip(credentials, candidate_ids, payloads)
    ]


def test_different_preferences_return_unmapped_nonpreference_references(different_preferences):
    credentials, candidate_ids, payloads = different_preferences
    references = vote_different_preferences(different_preferences)
    assert references[0] != references[1]
    assert all(type(value) is str and is_confirmation_reference(value) for value in references)
    db.session.remove()
    ballots = AnonymousBallot.query.all()
    assert len(ballots) == 2
    assert {ballot.encrypted_ballot_json for ballot in ballots} == set(payloads)
    assert all(row.has_voted for row in VotingEligibility.query.all())
    assert BallotCredential.query.count() == 0
    snapshot = str(retained_snapshot())
    for reference in references:
        assert reference not in snapshot
        assert db.session.get(AnonymousBallot, reference) is None
        for private_value in (
            *credentials, *payloads, "voter-001", "voter-002", "Candidate Alpha",
            "Candidate Beta", "Alpha Party", "Beta Party",
            *(ballot.ballot_id for ballot in ballots),
        ):
            assert private_value not in reference
        # Numeric IDs can coincidentally occur in random text; no choice field is returned.
        assert reference not in {str(value) for value in candidate_ids}


def test_actual_schema_has_no_confirmation_column_table_or_foreign_key(credential_app):
    schema = inspect(db.engine)
    for table in schema.get_table_names():
        assert "confirm" not in table.casefold()
        assert "receipt" not in table.casefold()
        for column in schema.get_columns(table):
            assert "confirm" not in column["name"].casefold()
            assert "receipt" not in column["name"].casefold()
        for foreign_key in schema.get_foreign_keys(table):
            assert "confirm" not in foreign_key["referred_table"].casefold()
    assert {column["name"] for column in schema.get_columns("anonymous_ballots")} == {
        "ballot_id", "election_id", "electoral_division", "encrypted_ballot_json"
    }


def test_references_never_enter_sql_logs_or_audit(different_preferences, caplog, monkeypatch):
    statements = []
    engine = db.engine

    def observe(connection, cursor, statement, parameters, context, many):
        statements.append((statement, parameters))

    def forbid_event(*args, **kwargs):
        pytest.fail("No correlatable confirmation audit event is permitted")

    monkeypatch.setattr(audit, "record_event", forbid_event)
    monkeypatch.setattr(audit.AuditLog, "record_event", forbid_event)
    caplog.clear()
    event.listen(engine, "before_cursor_execute", observe)
    try:
        references = vote_different_preferences(different_preferences)
        snapshot = str(retained_snapshot())
    finally:
        event.remove(engine, "before_cursor_execute", observe)
    for reference in references:
        assert reference not in str(statements)
        assert reference not in snapshot
        assert reference not in caplog.text
    assert caplog.records == []


def test_confirmation_never_crosses_ballot_storage_boundary(different_preferences, monkeypatch):
    received = []
    writer = ballot_credentials.store_anonymous_ballot

    def observe(election_id, division, payload):
        received.append((election_id, division, payload))
        writer(election_id, division, payload)

    monkeypatch.setattr(ballot_credentials, "store_anonymous_ballot", observe)
    references = vote_different_preferences(different_preferences)
    assert received == [
        ("election-2026", "Melbourne", payload) for payload in different_preferences[2]
    ]
    assert all(reference not in str(received) for reference in references)
