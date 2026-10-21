"""
Tests for Workstream C ballot service.

SR-03: Eligibility and single-vote enforcement
"""

import pytest

from flask import Flask

from ballot_models import (
    AnonymousBallot,
    VotingEligibility,
)
from ballot_service import (
    BallotAcceptanceError,
    accept_ballot,
    EligibilityError,
    get_ballot_candidates,
    get_voting_eligibility,
    validate_ballot_assignment,
)
from records import EnrolmentRecord, db
from admin.candidates import add_draft_candidate
from admin.models import Candidate


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

def add_candidates(
    division="Melbourne",
    count=3,
):
    candidates = [
        add_draft_candidate(
            db.session,
            division=division,
            name=f"Candidate {chr(65 + i)}",
            party="Independent",
            position_in_group=i + 1,
        )
        for i in range(count)
    ]

    db.session.commit()

    return candidates
def finalise_candidates(
    division="Melbourne",
):
    for candidate in db.session.query(
        Candidate
    ).filter_by(
        division=division
    ):
        candidate.status = "FINAL"

    db.session.commit()
def test_ballot_uses_final_candidate_list(db_app):
    record = add_eligibility()

    add_candidates()
    finalise_candidates()

    candidates = get_ballot_candidates(record)

    assert isinstance(candidates, tuple)
    assert [
        candidate.position_in_group
        for candidate in candidates
    ] == [1, 2, 3]
def test_ballot_rejects_draft_candidate_list(db_app):
    record = add_eligibility()

    add_candidates()

    with pytest.raises(
        EligibilityError,
        match="Candidate list is not final",
    ):
        get_ballot_candidates(record)
def test_ballot_omits_excluded_candidate(db_app):
    record = add_eligibility()

    candidates = add_candidates()
    finalise_candidates()

    candidates[1].status = "EXCLUDED"
    db.session.commit()

    ballot_candidates = get_ballot_candidates(record)

    assert [
        candidate.position_in_group
        for candidate in ballot_candidates
    ] == [1, 3]

def test_eligible_voter_is_returned(db_app):
    add_eligibility()

    record = get_voting_eligibility(
        "voter-001",
        "election-2026",
    )

    assert record.voter_id == "voter-001"
    assert record.eligible is True
    assert record.has_voted is False
def test_valid_ballot_assignment_is_allowed(db_app):
    record = add_eligibility()

    validate_ballot_assignment(record)


def test_invalid_ballot_assignment_is_rejected(db_app):
    record = add_eligibility()
    record.state_code = "NSW"

    with pytest.raises(
        EligibilityError,
        match="Invalid electoral assignment",
    ):
        validate_ballot_assignment(record)
def test_eligibility_rejects_invalid_assignment(db_app):
    record = add_eligibility()
    record.state_code = "NSW"
    db.session.commit()

    with pytest.raises(
        EligibilityError,
        match="Invalid electoral assignment",
    ):
        get_voting_eligibility(
            "voter-001",
            "election-2026",
        )


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


OPAQUE_BALLOT = '{"alg":"test","ct":"opaque"}'


@pytest.fixture
def acceptance_candidate(db_app):
    add_eligibility()
    candidates = add_candidates()
    finalise_candidates()
    return candidates[0].id


def submit(candidate_id):
    accept_ballot(
        "voter-001", "election-2026", candidate_id, OPAQUE_BALLOT
    )


def assert_acceptance_state(voted, count):
    db.session.remove()
    assert VotingEligibility.query.one().has_voted is voted
    assert AnonymousBallot.query.count() == count


def test_acceptance_commits_ballot_and_status(acceptance_candidate):
    submit(acceptance_candidate)
    assert_acceptance_state(True, 1)
    ballot = AnonymousBallot.query.one()
    assert OPAQUE_BALLOT not in ballot.encrypted_ballot_json
    assert ballot.electoral_division == "Melbourne"
    assert ballot.election_id == "election-2026"
    assert len(bytes.fromhex(ballot.ballot_id)) == 32


def test_repeated_acceptance_leaves_one_ballot(acceptance_candidate):
    submit(acceptance_candidate)
    with pytest.raises(BallotAcceptanceError, match="already accepted"):
        submit(acceptance_candidate)
    assert_acceptance_state(True, 1)


def test_database_claim_rejects_stale_precheck(
    acceptance_candidate, monkeypatch
):
    import ballot_service

    stale_record = get_voting_eligibility("voter-001", "election-2026")
    submit(acceptance_candidate)
    # Simulate a request that passed its pre-check before the winner committed.
    monkeypatch.setattr(
        ballot_service, "get_voting_eligibility", lambda *args: stale_record
    )
    with pytest.raises(BallotAcceptanceError, match="already accepted"):
        submit(acceptance_candidate)
    assert_acceptance_state(True, 1)


@pytest.mark.parametrize("candidate_id", [None, True, "1", 1.0, [], 0, -1, 99999])
def test_acceptance_rejects_invalid_selection(
    acceptance_candidate, candidate_id
):
    with pytest.raises(BallotAcceptanceError, match="Invalid candidate"):
        submit(candidate_id)
    assert_acceptance_state(False, 0)


@pytest.mark.parametrize(
    "payload", [None, {}, "", "  ", "x" * 65537],
    ids=["none", "mapping", "empty", "whitespace", "oversized"],
)
def test_acceptance_rejects_invalid_payload(acceptance_candidate, payload):
    with pytest.raises(BallotAcceptanceError, match="Invalid opaque"):
        accept_ballot("voter-001", "election-2026", acceptance_candidate, payload)
    assert_acceptance_state(False, 0)


def test_acceptance_rejects_other_division(acceptance_candidate):
    candidates = add_candidates(division="Sydney")
    finalise_candidates("Sydney")
    with pytest.raises(BallotAcceptanceError, match="Invalid candidate"):
        submit(candidates[0].id)
    assert_acceptance_state(False, 0)


def test_acceptance_rejects_excluded_candidate(acceptance_candidate):
    candidate = db.session.get(Candidate, acceptance_candidate)
    candidate.status = "EXCLUDED"
    db.session.commit()
    with pytest.raises(BallotAcceptanceError, match="Invalid candidate"):
        submit(acceptance_candidate)
    assert_acceptance_state(False, 0)


def test_acceptance_rejects_draft_list(db_app):
    add_eligibility()
    candidates = add_candidates()
    with pytest.raises(BallotAcceptanceError, match="not final"):
        submit(candidates[0].id)
    assert_acceptance_state(False, 0)


@pytest.mark.parametrize("change", ["removed", "suspended", "ineligible", "assignment"])
def test_acceptance_enforces_eligibility(acceptance_candidate, change):
    if change in {"removed", "suspended"}:
        EnrolmentRecord.query.one().enrolment_status = change
    elif change == "ineligible":
        VotingEligibility.query.one().eligible = False
    else:
        VotingEligibility.query.one().state_code = "NSW"
    db.session.commit()
    with pytest.raises(BallotAcceptanceError):
        submit(acceptance_candidate)
    assert_acceptance_state(False, 0)


def test_insert_failure_rolls_back_claim(acceptance_candidate):
    from sqlalchemy import event
    from sqlalchemy.exc import IntegrityError

    claims_seen = []

    def fail_insert(mapper, connection, target):
        claims_seen.append(connection.execute(
            db.select(VotingEligibility.has_voted)
        ).scalar_one())
        raise IntegrityError("synthetic insert failure", {}, Exception())

    event.listen(AnonymousBallot, "before_insert", fail_insert)
    try:
        with pytest.raises(BallotAcceptanceError, match="acceptance failed"):
            submit(acceptance_candidate)
    finally:
        event.remove(AnonymousBallot, "before_insert", fail_insert)
    assert claims_seen == [True]
    assert_acceptance_state(False, 0)
    submit(acceptance_candidate)
    assert_acceptance_state(True, 1)


def test_commit_failure_rolls_back_flushed_ballot(
    acceptance_candidate, monkeypatch
):
    from sqlalchemy.exc import OperationalError

    session = db.session()
    observed = []

    def fail_commit():
        session.flush()
        observed.append((
            session.execute(db.select(VotingEligibility.has_voted)).scalar_one(),
            session.query(AnonymousBallot).count(),
        ))
        raise OperationalError("synthetic commit failure", {}, Exception())

    monkeypatch.setattr(session, "commit", fail_commit)
    with pytest.raises(BallotAcceptanceError, match="acceptance failed"):
        submit(acceptance_candidate)
    assert observed == [(True, 1)]
    assert_acceptance_state(False, 0)
