"""
Tests for Workstream C ballot models.

SR-03: Eligibility and single-vote enforcement
"""

import pytest

from flask import Flask
from sqlalchemy.exc import IntegrityError

from records import db
from ballot_models import VotingEligibility


@pytest.fixture
def db_app():
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
