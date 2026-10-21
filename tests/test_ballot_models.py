"""
Tests for Workstream C ballot models.

SR-03: Eligibility and single-vote enforcement
"""

import pytest

from flask import Flask
from sqlalchemy.exc import IntegrityError

from records import db
from ballot_models import (
    AnonymousBallot,
    VotingEligibility,
)


@pytest.fixture
def db_app(ballot_crypto):
    app = Flask(__name__)

    app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    db.init_app(app)

    with app.app_context():
        db.create_all()

        yield app

        db.session.remove()
        db.drop_all()


def test_new_voter_has_not_voted_by_default(db_app):
    record = VotingEligibility(
        voter_id="voter-001",
        election_id="election-2026",
        electoral_division="Melbourne",
        state_code="VIC",
        eligible=True,
    )

    db.session.add(record)
    db.session.commit()

    assert record.has_voted is False


def test_duplicate_voter_election_is_rejected(db_app):
    first_record = VotingEligibility(
        voter_id="voter-001",
        election_id="election-2026",
        electoral_division="Melbourne",
        state_code="VIC",
        eligible=True,
    )

    duplicate_record = VotingEligibility(
        voter_id="voter-001",
        election_id="election-2026",
        electoral_division="Melbourne",
        state_code="VIC",
        eligible=True,
    )

    db.session.add(first_record)
    db.session.commit()

    db.session.add(duplicate_record)

    # The same voter cannot have two records
    # for the same election.
    with pytest.raises(IntegrityError):
        db.session.commit()

    db.session.rollback()


def test_same_voter_can_exist_in_different_elections(db_app):
    first_election = VotingEligibility(
        voter_id="voter-001",
        election_id="election-2026",
        electoral_division="Melbourne",
        state_code="VIC",
        eligible=True,
    )

    second_election = VotingEligibility(
        voter_id="voter-001",
        election_id="election-2029",
        electoral_division="Melbourne",
        state_code="VIC",
        eligible=True,
    )

    db.session.add_all([
        first_election,
        second_election,
    ])

    db.session.commit()

    records = VotingEligibility.query.all()

    assert len(records) == 2


def test_different_voters_can_use_same_election(db_app):
    voter_one = VotingEligibility(
        voter_id="voter-001",
        election_id="election-2026",
        electoral_division="Melbourne",
        state_code="VIC",
        eligible=True,
    )

    voter_two = VotingEligibility(
        voter_id="voter-002",
        election_id="election-2026",
        electoral_division="Melbourne",
        state_code="VIC",
        eligible=True,
    )

    db.session.add_all([
        voter_one,
        voter_two,
    ])

    db.session.commit()

    records = VotingEligibility.query.all()

    assert len(records) == 2


def test_anonymous_ballot_can_be_stored(db_app):
    ballot = AnonymousBallot(
        ballot_id="ballot-random-001",
        chain_index=1, previous_hash="sha256:" + "0" * 64,
        record_hash="sha256:" + "1" * 64,
        election_id="election-2026",
        electoral_division="Melbourne",
        encrypted_ballot_json='{"alg":"aes-256-gcm","ct":"test"}',
    )
    db.session.add(ballot)
    db.session.commit()
    saved = AnonymousBallot.query.one()
    assert saved.ballot_id == "ballot-random-001"
    assert saved.election_id == "election-2026"
    assert saved.electoral_division == "Melbourne"


def test_anonymous_ballot_has_no_voter_identity_fields(db_app):
    column_names = {
        column.name
        for column in AnonymousBallot.__table__.columns
    }

    assert "voter_id" not in column_names
    assert "owner_voter_id" not in column_names
    assert "source_ip" not in column_names
    assert "state_code" not in column_names
    assert "timestamp" not in column_names
