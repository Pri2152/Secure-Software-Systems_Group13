"""
SR-02: Staff account rules (no shared or generic accounts).

Uses an isolated in-memory SQLite database.
"""

import pytest
from flask import Flask
from sqlalchemy.exc import IntegrityError

from admin import StaffAccountError, create_staff_account, find_staff_account
from admin.accounts import is_generic_name
from admin.models import StaffAccount
from crypto_agility.passwords import verify_and_upgrade
from records import db
from staff_support import make_certificate


PASSWORD = "Staff-Password-2026!"


@pytest.fixture
def database():
    app = Flask(__name__)
    app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )
    db.init_app(app)

    with app.app_context():
        db.create_all()
        yield db.session
        db.session.remove()
        db.drop_all()


def create(db_session, **overrides):
    values = {
        "staff_id": "officer-jane-citizen",
        "full_name": "Jane Citizen",
        "role": "officer",
        "password": PASSWORD,
        "cert_fingerprint": make_certificate("Jane Citizen")[1],
    }
    values.update(overrides)

    return create_staff_account(db_session, **values)


# Test 1: A person-linked account is created
def test_person_linked_account_is_created(database):
    account = create(database)

    assert account.staff_id == "officer-jane-citizen"
    assert account.role == "officer"
    assert account.is_active is True


# Test 2: Password is stored only as an Argon2id hash
def test_password_is_hashed_with_argon2id(database):
    account = create(database)

    assert account.password_hash.startswith("$argon2id$")
    assert PASSWORD not in account.password_hash
    assert verify_and_upgrade(account.password_hash, PASSWORD)[0] is True


# Test 3: Generic and shared names are rejected
@pytest.mark.parametrize("staff_id", [
    "admin", "Administrator", "officer", "delegate", "auditor", "test",
    "shared", "root", "user", "staff", "admin1", "officer-01",
    "officer_2", "test-user", "shared.staff", "root-admin", "staff99",
    "sysadmin", "guest-1",
])
def test_generic_names_are_rejected(database, staff_id):
    with pytest.raises(StaffAccountError):
        create(database, staff_id=staff_id)


# Test 4: Names that contain a role but identify a person are allowed
@pytest.mark.parametrize("staff_id", [
    "officer-jane-citizen", "delegate-li-wei", "jsmith2",
])
def test_person_linked_names_are_allowed(staff_id):
    assert is_generic_name(staff_id) is False


# Test 5: Malformed staff IDs are rejected
@pytest.mark.parametrize("staff_id", [
    None, "", "ab", "jane citizen", "jane;drop", "-jane", "a" * 65, 42,
])
def test_malformed_staff_ids_are_rejected(database, staff_id):
    with pytest.raises(StaffAccountError):
        create(database, staff_id=staff_id)


# Test 6: Duplicate staff ID is rejected
def test_duplicate_staff_id_is_rejected(database):
    create(database)

    with pytest.raises(StaffAccountError):
        create(database, staff_id="Officer-Jane-Citizen",
               cert_fingerprint=make_certificate("Other")[1])


# Test 7: One certificate per person (duplicate fingerprint rejected)
def test_duplicate_certificate_is_rejected(database):
    fingerprint = make_certificate("Shared Card")[1]
    create(database, cert_fingerprint=fingerprint)

    with pytest.raises(StaffAccountError):
        create(database, staff_id="delegate-li-wei", full_name="Li Wei",
               role="delegate", cert_fingerprint=fingerprint.upper())


# Test 8: Database also enforces one certificate per account
def test_unique_constraint_backs_up_certificate_rule(database):
    fingerprint = make_certificate("Card")[1]

    database.add_all([
        StaffAccount(staff_id="jane-citizen", full_name="Jane Citizen",
                     role="officer", password_hash="x",
                     cert_fingerprint=fingerprint),
        StaffAccount(staff_id="li-wei", full_name="Li Wei",
                     role="officer", password_hash="x",
                     cert_fingerprint=fingerprint),
    ])

    with pytest.raises(IntegrityError):
        database.flush()


# Test 9: Only staff roles from the RBAC matrix are accepted
@pytest.mark.parametrize("role", ["voter", "superuser", "", None, "Officer"])
def test_invalid_roles_are_rejected(database, role):
    with pytest.raises(StaffAccountError):
        create(database, role=role)


# Test 10: Fingerprint must be SHA-256 hex
@pytest.mark.parametrize("fingerprint", [
    None, "", "abc", "z" * 64, "a" * 63, "a" * 65,
])
def test_invalid_fingerprints_are_rejected(database, fingerprint):
    with pytest.raises(StaffAccountError):
        create(database, cert_fingerprint=fingerprint)


# Test 11: Colon-separated fingerprints are normalised
def test_colon_fingerprint_is_normalised(database):
    fingerprint = make_certificate("Jane")[1]
    colon_form = ":".join(
        fingerprint[i:i + 2] for i in range(0, 64, 2)
    ).upper()

    assert create(database, cert_fingerprint=colon_form).cert_fingerprint == (
        fingerprint
    )


# Test 12: Short passwords and generic full names are rejected
@pytest.mark.parametrize("overrides", [
    {"password": "short"},
    {"password": None},
    {"full_name": ""},
    {"full_name": "   "},
    {"full_name": "Administrator"},
])
def test_weak_details_are_rejected(database, overrides):
    with pytest.raises(StaffAccountError) as error:
        create(database, **overrides)

    assert PASSWORD not in str(error.value)


# Test 13: Lookup is case-insensitive and refuses malformed IDs
def test_find_staff_account(database):
    create(database)

    assert find_staff_account(database, "OFFICER-JANE-CITIZEN") is not None
    assert find_staff_account(database, "officer-jane") is None
    assert find_staff_account(database, "' OR 1=1 --") is None
