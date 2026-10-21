"""
Workstream C ballot service.

SR-03: Eligibility and single-vote enforcement
"""

from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError

from admin.candidates import (
    CandidateListNotFinal,
    final_candidate_list,
)
from ballot_models import VotingEligibility
from ballot_chain import BallotChainError
from ballot_protection import BallotProtectionError
from crypto_agility import CryptoError
from ballot_storage import store_anonymous_ballot
from records import EnrolmentRecord, db


PROTOTYPE_DIVISION_STATES = {
    "Melbourne": "VIC",
}


class EligibilityError(Exception):
    pass


class BallotAcceptanceError(EligibilityError):
    """The ballot could not be accepted safely."""


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


def accept_ballot(
    voter_id, election_id, candidate_id, encrypted_ballot_json
):
    """
    Validate a single choice and atomically accept an opaque ballot.

    voter_id must come from the authenticated server-side identity.
    The caller supplies an opaque storage payload, not plaintext choices.
    This SR-03 service does not encrypt or verify that payload (SR-10).
    Owns commit/rollback of the current session; call without pending writes.
    """

    try:
        record = _validate_ballot(
            voter_id, election_id, candidate_id, encrypted_ballot_json
        )
        _claim_eligibility(record, voter_id, election_id)
        store_anonymous_ballot(
            election_id, record.electoral_division, encrypted_ballot_json, candidate_id
        )
        db.session.commit()

    except EligibilityError as error:
        db.session.rollback()
        raise BallotAcceptanceError(str(error)) from None
    except (SQLAlchemyError, CryptoError, BallotProtectionError, BallotChainError):
        db.session.rollback()
        raise BallotAcceptanceError("Ballot acceptance failed") from None
    except Exception:
        db.session.rollback()
        raise


def _validate_ballot(voter_id, election_id, candidate_id, encrypted_ballot_json):
    if (
        not isinstance(candidate_id, int)
        or isinstance(candidate_id, bool)
        or candidate_id <= 0
    ):
        raise BallotAcceptanceError("Invalid candidate selection")

    if (
        not isinstance(encrypted_ballot_json, str)
        or not encrypted_ballot_json.strip()
        or len(encrypted_ballot_json) > 65536
    ):
        raise BallotAcceptanceError("Invalid opaque ballot payload")

    record = get_voting_eligibility(voter_id, election_id)
    candidates = get_ballot_candidates(record)

    if candidate_id not in {
        candidate.candidate_id for candidate in candidates
    }:
        raise BallotAcceptanceError("Invalid candidate selection")

    return record


def _claim_eligibility(record, voter_id, election_id):
    # Claim the eligibility row before storing the ballot.
    claimed = db.session.execute(
        update(VotingEligibility)
        .where(
            VotingEligibility.id == record.id,
            VotingEligibility.voter_id == voter_id,
            VotingEligibility.election_id == election_id,
            VotingEligibility.eligible.is_(True),
            VotingEligibility.has_voted.is_(False),
            VotingEligibility.electoral_division
            == record.electoral_division,
            VotingEligibility.state_code == record.state_code,
            select(EnrolmentRecord.id).where(
                EnrolmentRecord.owner_voter_id == voter_id,
                EnrolmentRecord.enrolment_status == "enrolled",
            ).exists(),
        )
        .values(has_voted=True)
        .execution_options(synchronize_session=False)
    ).rowcount

    if claimed != 1:
        raise BallotAcceptanceError(
            "Vote already accepted or eligibility changed"
        )
