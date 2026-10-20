"""
SR-06: Execution of approved dual-authorised operations.

Security controls:
- Each operation re-validates its stored payload
  against the current database before changing
  anything, so a stale approval cannot apply to data
  that has changed since it was reviewed (e.g. a
  candidate added after the finalisation proposal)
- All changes of one operation run in the caller's
  single transaction: all rows change, or none do
- Candidate changes go through the ORM, so the
  read-only final-list guards always apply
- Roll updates change Workstream A's EnrolmentRecord
  through the ORM only, never with raw SQL

Local academic prototype.
"""

from records import EnrolmentRecord

from .candidates import (
    STATUS_EXCLUDED,
    STATUS_FINAL,
    division_is_locked,
    draft_candidate_ids,
)
from .models import Candidate
from .operations import (
    OP_BULK_ROLL,
    OP_EXCLUDE,
    OP_FINALISE,
    InvalidOperation,
)


def _finalise_candidate_list(db_session, payload: dict) -> None:
    division = payload["division"]

    if division_is_locked(db_session, division):
        raise InvalidOperation("Candidate list is already final")

    if draft_candidate_ids(db_session, division) != payload["candidate_ids"]:
        raise InvalidOperation("Candidate list changed since proposal")

    for candidate_id in payload["candidate_ids"]:
        db_session.get(Candidate, candidate_id).status = STATUS_FINAL


def _exclude_candidate(db_session, payload: dict) -> None:
    candidate = db_session.get(Candidate, payload["candidate_id"])

    if (
        candidate is None
        or candidate.division != payload["division"]
        or candidate.status != STATUS_FINAL
    ):
        raise InvalidOperation("Candidate cannot be excluded")

    candidate.status = STATUS_EXCLUDED


def _bulk_roll_update(db_session, payload: dict) -> None:
    for row in payload["changes"]:
        record = db_session.get(EnrolmentRecord, row["record_id"])

        if record is None:
            raise InvalidOperation("Roll record no longer exists")

        record.enrolment_status = row["enrolment_status"]


EXECUTORS = {
    OP_FINALISE: _finalise_candidate_list,
    OP_EXCLUDE: _exclude_candidate,
    OP_BULK_ROLL: _bulk_roll_update,
}


def execute_operation(db_session, op_type: str, payload: dict) -> None:
    """Apply an approved operation inside the current transaction."""

    EXECUTORS[op_type](db_session, payload)
    db_session.flush()
