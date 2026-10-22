"""
SR-18: count only ballots that passed the integrity check.

Workstream C already checks the whole ballot chain before it gives us
any choice. If that check fails, we stop. No partial count is made.
"""

import logging

from collections import Counter

import audit

from ballot_integrity import (
    BallotIntegrityError,
    verified_candidate_ids_for_tally,
)


logger = logging.getLogger("evp.tally")


class TallyRefused(RuntimeError):
    """The ballots could not be trusted, so nothing was counted."""


def _record_refusal(division):
    try:
        audit.record_event(
            "TALLY_REFUSED",
            stream="admin",
            actor_type="system",
            actor_id="tally",
            outcome="failure",
            details={"division": division},
        )
    except Exception:
        # The refusal must still happen if the audit log is down
        logger.error("TALLY_REFUSED audit_unavailable")


def count_division(election_id, division):
    """Return {candidate_id: votes} for one division."""

    try:
        candidate_ids = verified_candidate_ids_for_tally(election_id, division)
    except BallotIntegrityError:
        _record_refusal(division)
        raise TallyRefused("Tally refused: ballot check failed") from None

    return dict(sorted(Counter(candidate_ids).items()))


def count_election(election_id, divisions):
    """
    Return {division: {candidate_id: votes}}.
    If one division fails, the whole count is refused.
    """

    if not divisions:
        raise TallyRefused("Tally refused: no divisions given")

    return {
        division: count_division(election_id, division)
        for division in divisions
    }
