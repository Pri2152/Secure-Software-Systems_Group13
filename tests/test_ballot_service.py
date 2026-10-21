"""
Tests for Workstream C ballot service.

SR-03: Eligibility and single-vote enforcement
"""

import pytest

from flask import Flask

from ballot_models import VotingEligibility
from ballot_service import (
    EligibilityError,
    get_voting_eligibility,
)
from records import EnrolmentRecord, db


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


def add_enrolment(
    voter_id="voter-001",
    status="enrolled",
):
    record = EnrolmentRecord(
        owner_voter_id=voter_id,
        enrolment_status=status,
        contact_email="voter@example.test",
    )

    db.session.add(record)
    db.session.commit()

    return record


def add_eligibility(
    voter_id="voter-001",
    election_id="election-2026",
    eligible=True,
    has_voted=False,
    enrolment_status="enrolled",
):
    add_enrolment(
        voter_id,
        status=enrolment_status,
    )

    record = VotingEligibility(
        voter_id=voter_id,
        election_id=election_id,
        electoral_division="Melbourne",
        state_code="VIC",
        eligible=eligible,
        has_voted=has_voted,
    )

    db.session.add(record)
    db.session.commit()

    return record


def test_eligible_voter_is_returned(db_app):
    add_eligibility()

    record = get_voting_eligibility(
        "voter-001",
        "election-2026",
    )

    assert record.voter_id == "voter-001"
    assert record.eligible is True
    assert record.has_voted is False


def test_missing_eligibility_is_rejected(db_app):
    add_enrolment("voter-999")

    with pytest.raises(
        EligibilityError,
        match="Voting eligibility not found",
    ):
        get_voting_eligibility(
            "voter-999",
            "election-2026",
        )


def test_missing_enrolment_is_rejected(db_app):
    record = VotingEligibility(
        voter_id="voter-001",
        election_id="election-2026",
        electoral_division="Melbourne",
        state_code="VIC",
        eligible=True,
        has_voted=False,
    )

    db.session.add(record)
    db.session.commit()

    with pytest.raises(
        EligibilityError,
        match="Voter is not enrolled",
    ):
        get_voting_eligibility(
            "voter-001",
            "election-2026",
        )


@pytest.mark.parametrize(
    "enrolment_status",
    [
        "suspended",
        "removed",
    ],
)
def test_inactive_enrolment_is_rejected(
    db_app,
    enrolment_status,
):
    add_eligibility(
        enrolment_status=enrolment_status,
    )

    with pytest.raises(
        EligibilityError,
        match="Voter is not enrolled",
    ):
        get_voting_eligibility(
            "voter-001",
            "election-2026",
        )


def test_ineligible_voter_is_rejected(db_app):
    add_eligibility(
        eligible=False,
    )

    with pytest.raises(
        EligibilityError,
        match="Voter is not eligible",
    ):
        get_voting_eligibility(
            "voter-001",
            "election-2026",
        )


def test_voter_who_already_voted_is_rejected(db_app):
    add_eligibility(
        has_voted=True,
    )

    with pytest.raises(
        EligibilityError,
        match="Vote already accepted",
    ):
        get_voting_eligibility(
            "voter-001",
            "election-2026",
        )


@pytest.mark.parametrize(
    "voter_id,election_id",
    [
        ("", "election-2026"),
        ("   ", "election-2026"),
        (None, "election-2026"),
        ("voter-001", ""),
        ("voter-001", "   "),
        ("voter-001", None),
    ],
)
def test_invalid_identifiers_are_rejected(
    db_app,
    voter_id,
    election_id,
):
    with pytest.raises(
        EligibilityError,
        match="Invalid voter or election",
    ):
        get_voting_eligibility(
            voter_id,
            election_id,
        )