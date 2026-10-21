"""
Workstream C ballot service.

SR-03: Eligibility and single-vote enforcement
"""

from sqlalchemy import select

from admin.candidates import (
    CandidateListNotFinal,
    final_candidate_list,
)
from ballot_models import VotingEligibility
from records import EnrolmentRecord, db


PROTOTYPE_DIVISION_STATES = {
    "Melbourne": "VIC",
}


class EligibilityError(Exception):
    pass


def validate_ballot_assignment(eligibility_record):
    """
    Check that the stored division and state match.
    """

    expected_state = PROTOTYPE_DIVISION_STATES.get(
        eligibility_record.electoral_division
    )

    if (
        expected_state is None
        or eligibility_record.state_code != expected_state
    ):
        raise EligibilityError(
            "Invalid electoral assignment"
        )


def get_voting_eligibility(voter_id, election_id):
    """
    Get the voter eligibility record for an election.
    """

    if (
        not isinstance(voter_id, str)
        or not voter_id.strip()
        or not isinstance(election_id, str)
        or not election_id.strip()
    ):
        raise EligibilityError(
            "Invalid voter or election"
        )
    enrolment_statement = select(EnrolmentRecord.id).where(
        EnrolmentRecord.owner_voter_id == voter_id,
        EnrolmentRecord.enrolment_status == "enrolled",
    ).limit(1)

    enrolled = db.session.execute(
        enrolment_statement
    ).scalar_one_or_none()

    if enrolled is None:
        raise EligibilityError("Voter is not enrolled")

    statement = select(VotingEligibility).where(
        VotingEligibility.voter_id == voter_id,
        VotingEligibility.election_id == election_id,
    )

    record = db.session.execute(
        statement
    ).scalar_one_or_none()

    if record is None:
        raise EligibilityError(
            "Voting eligibility not found"
        )

    if record.eligible is not True:
        raise EligibilityError(
            "Voter is not eligible"
        )

    if record.has_voted is True:
        raise EligibilityError(
            "Vote already accepted"
        )

    validate_ballot_assignment(record)

    return record


def get_ballot_candidates(eligibility_record):
    """
    Get the final candidate list for the voter's division.
    """

    try:
        return final_candidate_list(
            eligibility_record.electoral_division
        )

    except CandidateListNotFinal as exc:
        raise EligibilityError(
            "Candidate list is not final"
        ) from exc
