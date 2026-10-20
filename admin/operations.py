"""
SR-06: Dual-authorised operation types and payload digests.

Security controls:
- Only three critical operations exist, each with its
  own propose and approve permission from the SR-04
  matrix (Workstream E)
- Payloads are validated strictly (exact fields, types,
  ranges, existing records) and completed with a
  server-side snapshot of what will change, e.g. the
  exact candidate IDs being finalised
- The payload is stored as canonical JSON and bound to
  a self-describing digest made by crypto_agility
  (SR-14); approval and execution re-check that digest,
  so the operation cannot be swapped after proposal
- Court-ordered exclusions require a court order
  reference
- Roll updates touch Workstream A's EnrolmentRecord
  through the ORM only

Local academic prototype.
"""

import json
import re

from dataclasses import dataclass

from sqlalchemy import select

from records import EnrolmentRecord

from .candidates import (
    STATUS_FINAL,
    division_is_locked,
    draft_candidate_ids,
    valid_division,
)
from .models import COURT_ORDER_REF_MAX_LENGTH, Candidate


OP_FINALISE = "FINALISE_CANDIDATE_LIST"
OP_EXCLUDE = "EXCLUDE_CANDIDATE"
OP_BULK_ROLL = "BULK_ROLL_UPDATE"

PROPOSAL_LIFETIME_SECONDS = 24 * 60 * 60

MAX_BULK_ROWS = 200
ROLL_STATUSES = frozenset({"enrolled", "removed", "suspended"})

COURT_ORDER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9/ .-]{2,63}")


@dataclass(frozen=True)
class OperationType:
    name: str
    propose_permission: str
    approve_permission: str


OPERATION_TYPES = {
    OP_FINALISE: OperationType(
        OP_FINALISE,
        "candidates.propose_finalise",
        "candidates.approve_finalise",
    ),
    OP_EXCLUDE: OperationType(
        OP_EXCLUDE,
        "candidates.propose_exclusion",
        "candidates.approve_exclusion",
    ),
    OP_BULK_ROLL: OperationType(
        OP_BULK_ROLL,
        "roll.propose_bulk",
        "roll.approve_bulk",
    ),
}


class InvalidOperation(ValueError):
    """The operation or its payload is not acceptable."""


def canonical_payload(payload: dict) -> str:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def payload_digest(crypto, payload_json: str) -> str:
    """Self-describing digest, e.g. "sha256:<hex>" (SR-14)."""

    return crypto.hash(payload_json.encode("ascii"))


def payload_matches(crypto, payload_json, payload_hash) -> bool:
    if not isinstance(payload_json, str) or not isinstance(payload_hash, str):
        return False

    return crypto.verify_hash(payload_json.encode("ascii"), payload_hash)


def _positive_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _require_fields(payload, fields: frozenset) -> None:
    if not isinstance(payload, dict) or set(payload) != fields:
        raise InvalidOperation("Payload fields are invalid")


def _prepare_finalise(db_session, payload) -> dict:
    _require_fields(payload, frozenset({"division"}))
    division = payload["division"]

    if not valid_division(division):
        raise InvalidOperation("Invalid division")

    if division_is_locked(db_session, division):
        raise InvalidOperation("Candidate list is already final")

    candidate_ids = draft_candidate_ids(db_session, division)

    if not candidate_ids:
        raise InvalidOperation("Division has no draft candidates")

    return {"division": division, "candidate_ids": candidate_ids}


def _prepare_exclusion(db_session, payload) -> dict:
    _require_fields(payload, frozenset({"candidate_id", "court_order_ref"}))
    candidate_id = payload["candidate_id"]
    court_order_ref = payload["court_order_ref"]

    if (
        not isinstance(court_order_ref, str)
        or len(court_order_ref) > COURT_ORDER_REF_MAX_LENGTH
        or not COURT_ORDER_PATTERN.fullmatch(court_order_ref)
    ):
        raise InvalidOperation("A valid court order reference is required")

    if not _positive_int(candidate_id):
        raise InvalidOperation("Invalid candidate")

    candidate = db_session.get(Candidate, candidate_id)

    if candidate is None or candidate.status != STATUS_FINAL:
        raise InvalidOperation("Only a finalised candidate can be excluded")

    return {
        "candidate_id": candidate_id,
        "division": candidate.division,
        "court_order_ref": court_order_ref,
    }


def _prepare_bulk_roll(db_session, payload) -> dict:
    _require_fields(payload, frozenset({"changes"}))
    changes = payload["changes"]

    if not isinstance(changes, list) or not 1 <= len(changes) <= MAX_BULK_ROWS:
        raise InvalidOperation("Roll update needs 1 to 200 rows")

    rows = []

    for row in changes:
        _require_fields(row, frozenset({"record_id", "enrolment_status"}))

        if (
            not _positive_int(row["record_id"])
            or row["enrolment_status"] not in ROLL_STATUSES
        ):
            raise InvalidOperation("Invalid roll update row")

        rows.append({
            "record_id": row["record_id"],
            "enrolment_status": row["enrolment_status"],
        })

    record_ids = [row["record_id"] for row in rows]

    if len(set(record_ids)) != len(record_ids):
        raise InvalidOperation("Duplicate roll records")

    found = set(db_session.scalars(
        select(EnrolmentRecord.id).where(EnrolmentRecord.id.in_(record_ids))
    ))

    if found != set(record_ids):
        raise InvalidOperation("Unknown roll record")

    return {"changes": sorted(rows, key=lambda row: row["record_id"])}


PREPARERS = {
    OP_FINALISE: _prepare_finalise,
    OP_EXCLUDE: _prepare_exclusion,
    OP_BULK_ROLL: _prepare_bulk_roll,
}


def prepare_payload(db_session, op_type, payload) -> dict:
    """
    Validate a proposal and return the complete payload
    that will be stored, digested and later executed.
    """

    if op_type not in OPERATION_TYPES:
        raise InvalidOperation("Unknown operation type")

    return PREPARERS[op_type](db_session, payload)
