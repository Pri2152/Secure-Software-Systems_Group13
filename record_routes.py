
"""
SR-05: Protected voter record HTTP endpoints.

Security controls:
- Authentication required
- Server-side record ownership checks
- Only authorised address updates, checked by the central SR-15
  validator (verification/validation.py)
- No voter-controlled ownership changes
- CSRF protection supplied by Flask application
"""

from flask import Blueprint, jsonify, request, session

from verification.validation import ValidationError, validate_address_update
from records import (
    db,
    EnrolmentRecord,
    AddressRecord,
    find_owned_record,
)


def create_record_blueprint(require_active_session):
    """
    Create protected routes using the application's
    existing SR-16 authentication decorator.
    """

    bp = Blueprint(
        "voter_records",
        __name__,
        url_prefix="/records"
    )

    @bp.get("/enrolments/<int:record_id>")
    @require_active_session
    def view_enrolment(record_id):
        voter_id = session.get("voter_id")

        record = find_owned_record(
            EnrolmentRecord,
            record_id,
            voter_id
        )

        if record is None:
            return jsonify(
                error="Record not found"
            ), 404

        return jsonify(
            id=record.id,
            enrolment_status=record.enrolment_status,
            contact_email=record.contact_email
        ), 200

    @bp.get("/addresses/<int:record_id>")
    @require_active_session
    def view_address(record_id):
        voter_id = session.get("voter_id")

        record = find_owned_record(
            AddressRecord,
            record_id,
            voter_id
        )

        if record is None:
            return jsonify(
                error="Record not found"
            ), 404

        return jsonify(
            id=record.id,
            address_text=record.address_text
        ), 200

    @bp.patch("/addresses/<int:record_id>")
    @require_active_session
    def update_address(record_id):
        voter_id = session.get("voter_id")

        # Ownership must be checked before changes.
        record = find_owned_record(
            AddressRecord,
            record_id,
            voter_id
        )

        if record is None:
            return jsonify(
                error="Record not found"
            ), 404

        if not request.is_json:
            return jsonify(
                error="JSON request required"
            ), 415

        data = request.get_json(silent=True)

        # SR-15: the central validator allows only address_text, as
        # plain text. This also means no changes to record ID or owner ID.
        try:
            new_address = validate_address_update(data)
        except ValidationError as problem:
            if problem.field is None:
                return jsonify(
                    error="Invalid update fields"
                ), 400

            return jsonify(
                error="Invalid address"
            ), 400

        record.address_text = new_address
        db.session.commit()

        return jsonify(
            message="Address updated",
            id=record.id,
            address_text=record.address_text
        ), 200

    return bp
