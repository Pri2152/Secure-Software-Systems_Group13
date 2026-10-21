"""
SR-06: Maker-checker workflow for critical electoral operations.

Security controls:
- PROPOSE -> APPROVE by a different named officer
  (two-person rule); the proposer can never approve
  their own operation
- The approver must submit the payload digest they
  reviewed; it must equal the stored digest, and the
  stored payload must still match it (no swap between
  review and approval, no edit in the database)
- Only PROPOSED, unexpired operations can be approved
  or rejected; proposals expire after 24 hours
- Approval executes the operation atomically in one
  transaction: the row is claimed with a conditional
  update (PROPOSED -> APPROVED), the change is applied
  and the row set to EXECUTED; any failure rolls all of
  it back, so an operation runs at most once (no
  replay, no double execution under concurrency)
- Database triggers (admin/triggers.py) refuse EXECUTED
  without two distinct officers, as a backstop
- Every proposal, approval, rejection and refusal is
  audited on the admin stream with both officers' IDs
- Role and elevation checks (SR-02, SR-04) happen in
  the routes before this service is called

Local academic prototype.
"""

import hmac
import json

from collections.abc import Callable

from sqlalchemy import update
from sqlalchemy.exc import SQLAlchemyError

from . import triggers  # noqa: F401  (registers the trigger backstop)
from .candidates import CandidateListLocked
from .execution import execute_operation
from .models import PendingOperation
from .operations import (
    InvalidOperation,
    OP_EXCLUDE,
    PROPOSAL_LIFETIME_SECONDS,
    canonical_payload,
    payload_digest,
    payload_matches,
    prepare_payload,
)


STATUS_PROPOSED = "PROPOSED"
STATUS_APPROVED = "APPROVED"
STATUS_EXECUTED = "EXECUTED"
STATUS_REJECTED = "REJECTED"
STATUS_EXPIRED = "EXPIRED"

MAX_REJECT_REASON_LENGTH = 200

REFUSED_SELF_APPROVAL = "self_approval"
REFUSED_NOT_PENDING = "not_pending"
REFUSED_DIGEST_MISMATCH = "digest_mismatch"
REFUSED_PAYLOAD_TAMPERED = "payload_tampered"
REFUSED_EXPIRED = "expired"
REFUSED_EXECUTION_FAILED = "execution_failed"

EXECUTION_FAILURES = (InvalidOperation, CandidateListLocked, SQLAlchemyError)


class OperationRefused(Exception):
    """The request breaks a dual-authorisation rule."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def operation_view(operation: PendingOperation) -> dict:
    """What officers see when reviewing an operation."""

    return {
        "id": operation.id,
        "op_type": operation.op_type,
        "payload": json.loads(operation.payload_json),
        "payload_hash": operation.payload_hash,
        "proposer_id": operation.proposer_id,
        "approver_id": operation.approver_id,
        "status": operation.status,
        "court_order_ref": operation.court_order_ref,
        "created_at": operation.created_at,
        "expires_at": operation.expires_at,
        "decided_at": operation.decided_at,
        "executed_at": operation.executed_at,
    }


class DualAuthorisationService:
    """Stores and decides dual-authorised operations."""

    def __init__(
        self,
        *,
        db_session: Callable,
        crypto,
        audit: Callable,
        clock: Callable[[], float],
    ):
        self.db_session = db_session
        self.crypto = crypto
        self.audit = audit
        self.clock = clock

    def get(self, operation_id: int) -> PendingOperation | None:
        operation = self.db_session().get(PendingOperation, operation_id)

        if operation is not None:
            self._expire_if_due(operation)

        return operation

    def _expire_if_due(self, operation: PendingOperation) -> bool:
        """Mark an overdue proposal EXPIRED (audited once)."""

        if (
            operation.status != STATUS_PROPOSED
            or self.clock() < operation.expires_at
        ):
            return False

        operation.status = STATUS_EXPIRED
        operation.decided_at = self.clock()
        self.db_session().commit()

        self._audit(
            "OPERATION_EXPIRED", "success", operation.proposer_id, operation
        )

        return True

    def propose(self, proposer_id: str, op_type: str, payload) -> PendingOperation:
        """Validate and store a proposal (raises InvalidOperation)."""

        db_session = self.db_session()
        prepared = prepare_payload(db_session, op_type, payload)
        payload_json = canonical_payload(prepared)
        now = self.clock()

        operation = PendingOperation(
            op_type=op_type,
            payload_json=payload_json,
            payload_hash=payload_digest(self.crypto, payload_json),
            proposer_id=proposer_id,
            status=STATUS_PROPOSED,
            created_at=now,
            expires_at=now + PROPOSAL_LIFETIME_SECONDS,
            court_order_ref=(
                prepared["court_order_ref"] if op_type == OP_EXCLUDE else None
            ),
        )
        db_session.add(operation)
        db_session.commit()

        self._audit("OPERATION_PROPOSED", "success", proposer_id, operation)

        return operation

    def approve(
        self, operation: PendingOperation, approver_id: str, reviewed_hash
    ) -> PendingOperation:
        """
        Second-officer approval of exactly the reviewed
        payload, executed atomically.
        """

        self._check_decidable(operation, approver_id, reviewed_hash)

        db_session = self.db_session()
        now = self.clock()

        try:
            claimed = db_session.execute(
                update(PendingOperation)
                .where(
                    PendingOperation.id == operation.id,
                    PendingOperation.status == STATUS_PROPOSED,
                )
                .values(
                    status=STATUS_APPROVED,
                    approver_id=approver_id,
                    decided_at=now,
                )
            ).rowcount

            if claimed != 1:
                db_session.rollback()
                self._refuse(operation, approver_id, REFUSED_NOT_PENDING)

            execute_operation(
                db_session, operation.op_type,
                json.loads(operation.payload_json),
            )

            db_session.execute(
                update(PendingOperation)
                .where(
                    PendingOperation.id == operation.id,
                    PendingOperation.status == STATUS_APPROVED,
                )
                .values(status=STATUS_EXECUTED, executed_at=now)
            )
            db_session.commit()

        except EXECUTION_FAILURES as error:
            db_session.rollback()
            self._audit(
                "OPERATION_EXECUTION_FAILED", "failure", approver_id,
                operation, {"reason": type(error).__name__},
            )
            raise OperationRefused(REFUSED_EXECUTION_FAILED) from None

        db_session.refresh(operation)

        self._audit("OPERATION_APPROVED", "success", approver_id, operation)
        self._audit("OPERATION_EXECUTED", "success", approver_id, operation)

        return operation

    def reject(
        self, operation: PendingOperation, staff_id: str, reason: str | None
    ) -> PendingOperation:
        if self._expire_if_due(operation):
            self._refuse(operation, staff_id, REFUSED_EXPIRED)

        if operation.status != STATUS_PROPOSED:
            self._refuse(operation, staff_id, REFUSED_NOT_PENDING)

        operation.status = STATUS_REJECTED
        operation.decided_at = self.clock()
        self.db_session().commit()

        self._audit(
            "OPERATION_REJECTED", "success", staff_id, operation,
            {"reason": reason} if reason else None,
        )

        return operation

    def _check_decidable(self, operation, approver_id, reviewed_hash) -> None:
        if self._expire_if_due(operation):
            self._refuse(operation, approver_id, REFUSED_EXPIRED)

        if operation.status != STATUS_PROPOSED:
            self._refuse(operation, approver_id, REFUSED_NOT_PENDING)

        if approver_id == operation.proposer_id:
            self._refuse(operation, approver_id, REFUSED_SELF_APPROVAL)

        if not isinstance(reviewed_hash, str) or not hmac.compare_digest(
            reviewed_hash.encode("utf-8"),
            operation.payload_hash.encode("utf-8"),
        ):
            self._refuse(operation, approver_id, REFUSED_DIGEST_MISMATCH)

        if not payload_matches(
            self.crypto, operation.payload_json, operation.payload_hash
        ):
            self._refuse(operation, approver_id, REFUSED_PAYLOAD_TAMPERED)

    def _refuse(self, operation, staff_id, reason: str) -> None:
        self._audit(
            "OPERATION_REFUSED", "denied", staff_id, operation,
            {"reason": reason},
        )
        raise OperationRefused(reason)

    def _audit(self, event_type, outcome, actor_id, operation, extra=None):
        details = {
            "operation_id": operation.id,
            "op_type": operation.op_type,
            "proposer_id": operation.proposer_id,
            "approver_id": operation.approver_id,
            "payload_hash": operation.payload_hash,
            "status": operation.status,
        }
        details.update(extra or {})

        self.audit(
            event_type,
            stream="admin",
            actor_type="staff",
            actor_id=actor_id,
            outcome=outcome,
            details=details,
        )
