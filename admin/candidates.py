"""
SR-06: Candidate lists and their read-only final state.

Security controls:
- A candidate list becomes FINAL only through a
  dual-authorised FINALISE_CANDIDATE_LIST operation
- Once a division has FINAL (or EXCLUDED) candidates
  its list is read-only at the ORM level: no new
  candidates, no edits, no deletions, and the only
  status change allowed is FINAL -> EXCLUDED (a
  dual-authorised, court-ordered exclusion)
- Workstream C reads the ballot's candidates through
  final_candidate_list(), which returns immutable
  values and refuses a division that is not final
- Input is validated against allow-list patterns

Local academic prototype.
"""

import re

from dataclasses import dataclass

from sqlalchemy import event, inspect, select

from records import db

from .models import (
    CANDIDATE_NAME_MAX_LENGTH,
    DIVISION_MAX_LENGTH,
    PARTY_MAX_LENGTH,
    Candidate,
)


STATUS_DRAFT = "DRAFT"
STATUS_FINAL = "FINAL"
STATUS_EXCLUDED = "EXCLUDED"

LOCKED_STATUSES = frozenset({STATUS_FINAL, STATUS_EXCLUDED})

DIVISION_PATTERN = re.compile(r"[A-Za-z][A-Za-z' -]{1,63}")
NAME_PATTERN = re.compile(r"[A-Za-z][A-Za-z' .-]{1,127}")
MAX_POSITION = 1000


class CandidateListLocked(Exception):
    """The division's candidate list is final and read-only."""


class CandidateListNotFinal(LookupError):
    """No finalised candidate list exists for the division."""


@dataclass(frozen=True)
class FinalCandidate:
    candidate_id: int
    name: str
    party: str
    position_in_group: int


def valid_division(division) -> bool:
    return (
        isinstance(division, str)
        and len(division) <= DIVISION_MAX_LENGTH
        and DIVISION_PATTERN.fullmatch(division) is not None
    )


def _valid_name(value, max_length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= max_length
        and NAME_PATTERN.fullmatch(value) is not None
    )


def division_is_locked(connection_or_session, division: str) -> bool:
    return connection_or_session.execute(
        select(Candidate.id)
        .where(
            Candidate.division == division,
            Candidate.status.in_(LOCKED_STATUSES),
        )
        .limit(1)
    ).first() is not None


def add_draft_candidate(
    db_session, *, division, name, party, position_in_group
) -> Candidate:
    """Add a DRAFT candidate to a division that is not yet final."""

    if (
        not valid_division(division)
        or not _valid_name(name, CANDIDATE_NAME_MAX_LENGTH)
        or not _valid_name(party, PARTY_MAX_LENGTH)
        or isinstance(position_in_group, bool)
        or not isinstance(position_in_group, int)
        or not 1 <= position_in_group <= MAX_POSITION
    ):
        raise ValueError("Invalid candidate details")

    candidate = Candidate(
        division=division,
        name=name,
        party=party,
        position_in_group=position_in_group,
        status=STATUS_DRAFT,
    )
    db_session.add(candidate)
    db_session.flush()

    return candidate


def draft_candidate_ids(db_session, division: str) -> list[int]:
    return sorted(db_session.scalars(
        select(Candidate.id).where(
            Candidate.division == division,
            Candidate.status == STATUS_DRAFT,
        )
    ))


def final_candidate_list(division: str) -> tuple[FinalCandidate, ...]:
    """
    The finalised candidates of a division, in ballot
    order, for Workstream C. Excluded candidates are
    left out. Raises CandidateListNotFinal otherwise.
    """

    if not valid_division(division) or not division_is_locked(
        db.session, division
    ):
        raise CandidateListNotFinal("Candidate list is not final")

    candidates = db.session.scalars(
        select(Candidate)
        .where(
            Candidate.division == division,
            Candidate.status == STATUS_FINAL,
        )
        .order_by(Candidate.position_in_group)
    )

    return tuple(
        FinalCandidate(
            candidate_id=candidate.id,
            name=candidate.name,
            party=candidate.party,
            position_in_group=candidate.position_in_group,
        )
        for candidate in candidates
    )


# ORM guards: a final list cannot be changed by any code path
# that goes through the ORM.

@event.listens_for(Candidate, "before_insert")
def _refuse_insert_into_final_list(mapper, connection, target):
    if division_is_locked(connection, target.division):
        raise CandidateListLocked("Candidate list is final")


@event.listens_for(Candidate, "before_update")
def _refuse_change_to_final_list(mapper, connection, target):
    # Read the stored status: attribute history is empty
    # for values that were expired after a commit.
    previous = connection.execute(
        select(Candidate.status).where(Candidate.id == target.id)
    ).scalar_one_or_none()

    if previous not in LOCKED_STATUSES:
        return

    changed = {
        attribute.key
        for attribute in inspect(target).attrs
        if attribute.history.has_changes()
    }

    if (
        changed == {"status"}
        and previous == STATUS_FINAL
        and target.status == STATUS_EXCLUDED
    ):
        return

    raise CandidateListLocked("Candidate list is final")


@event.listens_for(Candidate, "before_delete")
def _refuse_delete_from_final_list(mapper, connection, target):
    if target.status in LOCKED_STATUSES:
        raise CandidateListLocked("Candidate list is final")
