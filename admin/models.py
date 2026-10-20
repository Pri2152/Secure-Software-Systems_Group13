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
