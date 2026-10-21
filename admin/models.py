"""
SR-02: Staff account storage.

Security controls:
- One account per named person: staff_id is unique and
  person-linked (generic names are refused in
  accounts.py)
- One client certificate per person: the SHA-256
  certificate fingerprint column is UNIQUE, so a
  certificate cannot be shared between accounts
- Passwords stored only as Argon2id hashes
  (crypto_agility.passwords, SR-14)
- Elevation grants are stored server-side with an
  expiry, so a client cannot create or extend one
- SR-06: every critical change is a PendingOperation
  bound to a digest of its exact payload and to two
  named officers (proposer and approver)
- Lives on the identity (default) database with the
  other identity records, never on the ballot bind

Local academic prototype.
"""

from records import db


STAFF_ID_MAX_LENGTH = 64
FULL_NAME_MAX_LENGTH = 128
ROLE_MAX_LENGTH = 32
FINGERPRINT_LENGTH = 64
PASSWORD_HASH_MAX_LENGTH = 255
PERMISSION_MAX_LENGTH = 64

DIVISION_MAX_LENGTH = 64
CANDIDATE_NAME_MAX_LENGTH = 128
PARTY_MAX_LENGTH = 128
OP_TYPE_MAX_LENGTH = 32
STATUS_MAX_LENGTH = 16
PAYLOAD_HASH_MAX_LENGTH = 128
COURT_ORDER_REF_MAX_LENGTH = 64


class StaffAccount(db.Model):
    __tablename__ = "staff_accounts"

    id = db.Column(db.Integer, primary_key=True)

    staff_id = db.Column(
        db.String(STAFF_ID_MAX_LENGTH),
        unique=True,
        nullable=False,
    )

    full_name = db.Column(
        db.String(FULL_NAME_MAX_LENGTH),
        nullable=False,
    )

    role = db.Column(
        db.String(ROLE_MAX_LENGTH),
        nullable=False,
    )

    password_hash = db.Column(
        db.String(PASSWORD_HASH_MAX_LENGTH),
        nullable=False,
    )

    cert_fingerprint = db.Column(
        db.String(FINGERPRINT_LENGTH),
        unique=True,
        nullable=False,
    )

    is_active = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
    )


class ElevationGrant(db.Model):
    """One time-boxed privileged permission for one person."""

    __tablename__ = "staff_elevation_grants"

    id = db.Column(db.Integer, primary_key=True)

    staff_id = db.Column(
        db.String(STAFF_ID_MAX_LENGTH),
        db.ForeignKey("staff_accounts.staff_id"),
        nullable=False,
        index=True,
    )

    permission = db.Column(
        db.String(PERMISSION_MAX_LENGTH),
        nullable=False,
    )

    granted_at = db.Column(db.Float, nullable=False)
    expires_at = db.Column(db.Float, nullable=False)

    revoked = db.Column(db.Boolean, nullable=False, default=False)
    revoked_at = db.Column(db.Float)

    # Set once the expiry has been written to the audit log
    expiry_recorded = db.Column(db.Boolean, nullable=False, default=False)


class Candidate(db.Model):
    """A candidate in one division (SR-06 candidate lists)."""

    __tablename__ = "candidates"
    __table_args__ = (
        db.UniqueConstraint(
            "division", "position_in_group",
            name="uq_candidate_division_position",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)

    division = db.Column(
        db.String(DIVISION_MAX_LENGTH), nullable=False, index=True
    )
    name = db.Column(db.String(CANDIDATE_NAME_MAX_LENGTH), nullable=False)
    party = db.Column(db.String(PARTY_MAX_LENGTH), nullable=False)
    position_in_group = db.Column(db.Integer, nullable=False)

    # DRAFT -> FINAL (dual-authorised) -> EXCLUDED (court order)
    status = db.Column(
        db.String(STATUS_MAX_LENGTH), nullable=False, default="DRAFT"
    )


class PendingOperation(db.Model):
    """A critical operation awaiting a second officer (maker-checker)."""

    __tablename__ = "pending_operations"

    id = db.Column(db.Integer, primary_key=True)

    op_type = db.Column(db.String(OP_TYPE_MAX_LENGTH), nullable=False)
    payload_json = db.Column(db.Text, nullable=False)
    payload_hash = db.Column(
        db.String(PAYLOAD_HASH_MAX_LENGTH), nullable=False
    )

    proposer_id = db.Column(
        db.String(STAFF_ID_MAX_LENGTH),
        db.ForeignKey("staff_accounts.staff_id"),
        nullable=False,
    )
    approver_id = db.Column(
        db.String(STAFF_ID_MAX_LENGTH),
        db.ForeignKey("staff_accounts.staff_id"),
    )

    # PROPOSED -> APPROVED -> EXECUTED, or REJECTED / EXPIRED
    status = db.Column(
        db.String(STATUS_MAX_LENGTH), nullable=False, default="PROPOSED"
    )

    created_at = db.Column(db.Float, nullable=False)
    expires_at = db.Column(db.Float, nullable=False)
    decided_at = db.Column(db.Float)
    executed_at = db.Column(db.Float)

    court_order_ref = db.Column(db.String(COURT_ORDER_REF_MAX_LENGTH))
