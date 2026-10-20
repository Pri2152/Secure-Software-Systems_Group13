"""
SR-06: Dual-authorisation endpoints.

Security controls:
- Every endpoint needs a valid staff session (SR-02)
- Proposing needs the operation's propose permission
  and approving or rejecting its approve permission
  (SR-04 matrix), each with an active SR-02 elevation
  for exactly that permission (403 otherwise)
- Viewing an operation needs either permission for its
  type, so officers outside that duty cannot read it
- Officer identity comes only from the server-side
  session, never from the request body
- Strict JSON bodies; unknown fields refused; refusals
  map to generic status codes (403 self-approval, 409
  for state or digest conflicts)
- CSRF protection from Flask-WTF (app-wide)

Local academic prototype.
"""

from flask import Blueprint, jsonify, session

from .dual_authorisation import (
    REFUSED_SELF_APPROVAL,
    DualAuthorisationService,
    OperationRefused,
    MAX_REJECT_REASON_LENGTH,
    operation_view,
)
from .elevation import ElevationService
from .operations import OPERATION_TYPES, InvalidOperation
from .routes import read_json_fields
from .sessions import StaffSessions


PROPOSE_FIELDS = frozenset({"op_type", "payload"})
APPROVE_FIELDS = frozenset({"payload_hash"})
REJECT_FIELDS = frozenset({"reason"})

REFUSAL_STATUS = {REFUSED_SELF_APPROVAL: 403}
CONFLICT_STATUS = 409


def _error(message: str, status: int):
    return jsonify({"error": message}), status


def _refused(error: OperationRefused):
    status = REFUSAL_STATUS.get(error.reason, CONFLICT_STATUS)

    return _error("Operation refused", status)


def create_operations_blueprint(
    *,
    sessions: StaffSessions,
    elevation: ElevationService,
    service: DualAuthorisationService,
) -> Blueprint:
    blueprint = Blueprint("operations", __name__)
    require_staff_session = sessions.require_staff_session

    def load(operation_id):
        operation = service.get(operation_id)

        if operation is None:
            return None, _error("Not found", 404)

        return operation, None

    @blueprint.post("/admin/operations")
    @require_staff_session
    def propose_operation():
        data = read_json_fields(PROPOSE_FIELDS, PROPOSE_FIELDS)

        if data is None or data["op_type"] not in OPERATION_TYPES:
            return _error("Invalid request", 400)

        operation_type = OPERATION_TYPES[data["op_type"]]
        refusal = elevation.refusal(operation_type.propose_permission)

        if refusal is not None:
            return refusal

        try:
            operation = service.propose(
                session["staff_id"], data["op_type"], data["payload"]
            )
        except InvalidOperation as error:
            return _error(str(error), 400)

        return jsonify(operation_view(operation)), 201

    @blueprint.get("/admin/operations/<int:operation_id>")
    @require_staff_session
    def view_operation(operation_id):
        operation, error = load(operation_id)

        if error:
            return error

        operation_type = OPERATION_TYPES[operation.op_type]
        role = session.get("role")

        if not (
            elevation.role_allows(role, operation_type.propose_permission)
            or elevation.role_allows(role, operation_type.approve_permission)
        ):
            return _error("Forbidden", 403)

        return jsonify(operation_view(operation)), 200

    @blueprint.post("/admin/operations/<int:operation_id>/approve")
    @require_staff_session
    def approve_operation(operation_id):
        data = read_json_fields(APPROVE_FIELDS, APPROVE_FIELDS)

        if data is None:
            return _error("Invalid request", 400)

        operation, error = load(operation_id)

        if error:
            return error

        refusal = elevation.refusal(
            OPERATION_TYPES[operation.op_type].approve_permission
        )

        if refusal is not None:
            return refusal

        try:
            operation = service.approve(
                operation, session["staff_id"], data["payload_hash"]
            )
        except OperationRefused as refused:
            return _refused(refused)

        return jsonify(operation_view(operation)), 200

    @blueprint.post("/admin/operations/<int:operation_id>/reject")
    @require_staff_session
    def reject_operation(operation_id):
        data = read_json_fields(REJECT_FIELDS, frozenset())
        reason = data.get("reason") if data is not None else None

        if data is None or (reason is not None and (
            not isinstance(reason, str)
            or len(reason) > MAX_REJECT_REASON_LENGTH
        )):
            return _error("Invalid request", 400)

        operation, error = load(operation_id)

        if error:
            return error

        refusal = elevation.refusal(
            OPERATION_TYPES[operation.op_type].approve_permission
        )

        if refusal is not None:
            return refusal

        try:
            operation = service.reject(operation, session["staff_id"], reason)
        except OperationRefused as refused:
            return _refused(refused)

        return jsonify(operation_view(operation)), 200

    return blueprint
