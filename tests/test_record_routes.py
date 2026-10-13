
"""
SR-05: HTTP object-level authorization tests.

Uses synthetic voter accounts and an isolated
in-memory SQLite database.
"""

import time

import pytest
from cachelib import SimpleCache
from flask import Flask, jsonify
from flask_session import Session
from flask_wtf.csrf import CSRFProtect, generate_csrf

import app as application

from records import (
    db,
    EnrolmentRecord,
    AddressRecord,
)

from record_routes import create_record_blueprint


HTTPS_URL = "https://localhost"


@pytest.fixture
def client():
    test_app = Flask(__name__)

    test_app.config.update(
        TESTING=True,
        SECRET_KEY="synthetic-test-secret",
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_TYPE="cachelib",
        SESSION_CACHELIB=SimpleCache(),
        SESSION_PERMANENT=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        WTF_CSRF_ENABLED=True,
    )

    db.init_app(test_app)
    Session(test_app)
    CSRFProtect(test_app)

    test_app.register_blueprint(
        create_record_blueprint(
            application.require_active_session
        )
    )

    @test_app.get("/test-csrf")
    def test_csrf():
        return jsonify(
            csrf_token=generate_csrf()
        )

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
                address_text="Original Address One",
            ),
            AddressRecord(
                id=202,
                owner_voter_id="voter-002",
                address_text="Original Address Two",
            ),
        ])

        db.session.commit()

        with test_app.test_client() as test_client:
            yield test_client

        db.session.remove()
        db.drop_all()


def login_as(client, voter_id):
    """
    Simulate an already verified SR-16 session.
    Only used in automated tests.
    """

    with client.session_transaction(
        base_url=HTTPS_URL
    ) as active_session:
        active_session.clear()

        active_session["authenticated"] = True
        active_session["voter_id"] = voter_id
        active_session["last_activity"] = time.time()
        active_session.permanent = True


def csrf_headers(client):
    """
    Generate valid CSRF request headers.

    HTTPS requests require both a CSRF token
    and a same-origin Referer header.
    """

    response = client.get(
        "/test-csrf",
        base_url=HTTPS_URL
    )

    assert response.status_code == 200

    return {
        "X-CSRFToken": response.get_json()["csrf_token"],
        "Referer": HTTPS_URL + "/test-csrf",
    }


def patch_address(client, record_id, data):
    headers = csrf_headers(client)

    return client.patch(
        f"/records/addresses/{record_id}",
        base_url=HTTPS_URL,
        headers=headers,
        json=data,
    )


# Test 1: Unauthenticated read rejected
def test_unauthenticated_read_rejected(client):
    response = client.get(
        "/records/enrolments/101",
        base_url=HTTPS_URL
    )

    assert response.status_code == 401


# Test 2: Voter reads own enrolment
def test_owner_reads_enrolment(client):
    login_as(client, "voter-001")

    response = client.get(
        "/records/enrolments/101",
        base_url=HTTPS_URL
    )

    assert response.status_code == 200
    assert response.get_json()["contact_email"] == (
        "voter1@example.test"
    )


# Test 3: Other voter's enrolment denied
def test_other_enrolment_denied(client):
    login_as(client, "voter-001")

    response = client.get(
        "/records/enrolments/102",
        base_url=HTTPS_URL
    )

    assert response.status_code == 404


# Test 4: Voter reads own address
def test_owner_reads_address(client):
    login_as(client, "voter-001")

    response = client.get(
        "/records/addresses/201",
        base_url=HTTPS_URL
    )

    assert response.status_code == 200
    assert response.get_json()["address_text"] == (
        "Original Address One"
    )


# Test 5: Other voter's address denied
def test_other_address_denied(client):
    login_as(client, "voter-001")

    response = client.get(
        "/records/addresses/202",
        base_url=HTTPS_URL
    )

    assert response.status_code == 404


# Test 6: Voter updates own address
def test_owner_updates_address(client):
    login_as(client, "voter-001")

    response = patch_address(
        client,
        201,
        {"address_text": "Updated Test Address"}
    )

    assert response.status_code == 200

    read_back = client.get(
        "/records/addresses/201",
        base_url=HTTPS_URL
    )

    assert read_back.status_code == 200
    assert read_back.get_json()["address_text"] == (
        "Updated Test Address"
    )


# Test 7: Cannot update another voter's address
def test_other_voter_update_denied(client):
    login_as(client, "voter-001")

    response = patch_address(
        client,
        202,
        {"address_text": "Unauthorised Change"}
    )

    assert response.status_code == 404

    login_as(client, "voter-002")

    read_back = client.get(
        "/records/addresses/202",
        base_url=HTTPS_URL
    )

    assert read_back.status_code == 200
    assert read_back.get_json()["address_text"] == (
        "Original Address Two"
    )


# Test 8: Missing record rejected
def test_missing_record_denied(client):
    login_as(client, "voter-001")

    response = client.get(
        "/records/addresses/999",
        base_url=HTTPS_URL
    )

    assert response.status_code == 404


# Test 9: Unauthenticated address update rejected
def test_unauthenticated_update_denied(client):
    response = patch_address(
        client,
        201,
        {"address_text": "Unauthorised Change"}
    )

    assert response.status_code == 401


# Test 10: Update without CSRF token rejected
def test_update_without_csrf_denied(client):
    login_as(client, "voter-001")

    response = client.patch(
        "/records/addresses/201",
        base_url=HTTPS_URL,
        json={
            "address_text": "Unauthorised Change"
        },
    )

    assert response.status_code == 400


# Test 11: Ownership fields cannot be changed
def test_ownership_field_update_rejected(client):
    login_as(client, "voter-001")

    response = patch_address(
        client,
        201,
        {
            "address_text": "Changed Address",
            "owner_voter_id": "voter-002",
        }
    )

    assert response.status_code == 400


# Test 12: Enrolment status is read-only
def test_enrolment_status_update_denied(client):
    login_as(client, "voter-001")

    response = client.patch(
        "/records/enrolments/101",
        base_url=HTTPS_URL,
        headers=csrf_headers(client),
        json={
            "enrolment_status": "approved"
        },
    )

    assert response.status_code == 405


# Test 13: Invalid addresses rejected
@pytest.mark.parametrize(
    "invalid_address",
    [
        None,
        "",
        "   ",
        123,
        "x" * 256,
    ]
)
def test_invalid_addresses_rejected(
    client, invalid_address
):
    login_as(client, "voter-001")

    response = patch_address(
        client,
        201,
        {"address_text": invalid_address}
    )

    assert response.status_code == 400


# Test 14: Invalid JSON structure rejected
def test_invalid_json_structure_rejected(client):
    login_as(client, "voter-001")

    response = patch_address(
        client,
        201,
        ["invalid", "request"]
    )

    assert response.status_code == 400


# Test 15: Non-JSON update rejected
def test_non_json_update_rejected(client):
    login_as(client, "voter-001")

    response = client.patch(
        "/records/addresses/201",
        base_url=HTTPS_URL,
        headers=csrf_headers(client),
        data="address_text=Changed",
        content_type="text/plain",
    )

    assert response.status_code == 415
