
"""
SR-05: Object-level authorization tests.

Uses synthetic voter records and an isolated
in-memory SQLite database.
"""

import pytest
from flask import Flask

from records import (
    db,
    EnrolmentRecord,
    AddressRecord,
    find_owned_record,
)


@pytest.fixture
def database(pii_provider):
    test_app = Flask(__name__)

    test_app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    db.init_app(test_app)

    with test_app.app_context():
        db.create_all()

        db.session.add_all([
            EnrolmentRecord(
                id=101,
                owner_voter_id="voter-001",
                enrolment_status="enrolled",
                contact_email="voter1@example.test",
            ),
            EnrolmentRecord(
                id=102,
                owner_voter_id="voter-002",
                enrolment_status="enrolled",
                contact_email="voter2@example.test",
            ),
            AddressRecord(
                id=201,
                owner_voter_id="voter-001",
                address_text="Test Address One",
            ),
            AddressRecord(
                id=202,
                owner_voter_id="voter-002",
                address_text="Test Address Two",
            ),
        ])

        db.session.commit()

        yield

        db.session.remove()
        db.drop_all()


def test_owner_can_view_own_enrolment(database):
    record = find_owned_record(
        EnrolmentRecord, 101, "voter-001"
    )

    assert record is not None
    assert record.contact_email == "voter1@example.test"


def test_other_voter_enrolment_denied(database):
    record = find_owned_record(
        EnrolmentRecord, 102, "voter-001"
    )

    assert record is None


def test_owner_can_view_own_address(database):
    record = find_owned_record(
        AddressRecord, 201, "voter-001"
    )

    assert record is not None
    assert record.address_text == "Test Address One"


def test_other_voter_address_denied(database):
    record = find_owned_record(
        AddressRecord, 202, "voter-001"
    )

    assert record is None


def test_missing_record_denied(database):
    record = find_owned_record(
        EnrolmentRecord, 999, "voter-001"
    )

    assert record is None


@pytest.mark.parametrize(
    "invalid_id",
    [None, "101", -1]
)
def test_invalid_record_id_denied(
    database, invalid_id
):
    record = find_owned_record(
        EnrolmentRecord,
        invalid_id,
        "voter-001"
    )

    assert record is None


@pytest.mark.parametrize(
    "invalid_voter",
    [None, "", "   "]
)
def test_invalid_voter_id_denied(
    database, invalid_voter
):
    record = find_owned_record(
        EnrolmentRecord,
        101,
        invalid_voter
    )

    assert record is None


def test_unsupported_record_model_rejected(database):
    with pytest.raises(ValueError):
        find_owned_record(
            object,
            101,
            "voter-001"
        )
