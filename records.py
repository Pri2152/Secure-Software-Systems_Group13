
"""
SR-05: Object-level authorization.

Protects enrolment and address records through
server-side voter ownership checks.

Prototype models for controlled testing.
"""

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select


db = SQLAlchemy()


class EnrolmentRecord(db.Model):
    __tablename__ = "enrolment_records"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    owner_voter_id = db.Column(
        db.String(128),
        nullable=False,
        index=True
    )

    enrolment_status = db.Column(
        db.String(32),
        nullable=False
    )

    contact_email = db.Column(
        db.String(254),
        nullable=False
    )


class AddressRecord(db.Model):
    __tablename__ = "address_records"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    owner_voter_id = db.Column(
        db.String(128),
        nullable=False,
        index=True
    )

    address_text = db.Column(
        db.String(255),
        nullable=False
    )


ALLOWED_RECORD_MODELS = (
    EnrolmentRecord,
    AddressRecord,
)


def find_owned_record(
    model,
    record_id,
    authenticated_voter_id
):
    """
    Return a record only when it belongs to
    the authenticated voter.

    The authenticated voter ID must come from
    a verified server-side session.

    Never accept it from user-controlled JSON
    or query parameters.
    """

    if model not in ALLOWED_RECORD_MODELS:
        raise ValueError(
            "Unsupported protected record type"
        )

    if (
        not isinstance(record_id, int)
        or isinstance(record_id, bool)
        or record_id <= 0
    ):
        return None

    if (
        not isinstance(authenticated_voter_id, str)
        or not authenticated_voter_id.strip()
    ):
        return None

    statement = select(model).where(
        model.id == record_id,
        model.owner_voter_id == authenticated_voter_id
    )

    return db.session.execute(
        statement
    ).scalar_one_or_none()
