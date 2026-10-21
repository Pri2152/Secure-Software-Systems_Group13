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
from records import db


class EligibilityError(Exception):
    pass


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
