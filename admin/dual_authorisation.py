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
- Only PROPOSED operations can be approved or
  rejected; decisions are final
- Every proposal, approval, rejection and refusal is
  audited on the admin stream with both officers' IDs
- Role and elevation checks (SR-02, SR-04) happen in
  the routes before this service is called

Local academic prototype.
"""

import hmac
import json

from collections.abc import Callable

from .models import PendingOperation
from .operations import (
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
        return self.db_session().get(PendingOperation, operation_id)

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
        """Second-officer approval of exactly the reviewed payload."""

        self._check_decidable(operation, approver_id, reviewed_hash)

        operation.status = STATUS_APPROVED
        operation.approver_id = approver_id
        operation.decided_at = self.clock()
        self.db_session().commit()

        self._audit("OPERATION_APPROVED", "success", approver_id, operation)

        return operation

    def reject(
        self, operation: PendingOperation, staff_id: str, reason: str | None
    ) -> PendingOperation:
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
