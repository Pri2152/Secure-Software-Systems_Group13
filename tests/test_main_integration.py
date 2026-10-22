
"""
End-to-end tests for SR-01, SR-05 and SR-16.

Tests Flask HTTP requests against the main
Workstream A application using synthetic voters.
"""

import pytest
import pyotp

import app as application

from auth import hash_password
from login_flow import LoginCoordinator, VoterRecord
from rate_limit import LoginRateLimiter

from records import (
    db,
    EnrolmentRecord,
    AddressRecord,
)


HTTPS_URL = "https://localhost"
TEST_PASSWORD = "CorrectPassword123!"
TEST_SECRET = "JBSWY3DPEHPK3PXP"


@pytest.fixture
def environment(monkeypatch, pii_provider):
    now = [1700000000.0]

    voters = {
        "voter-001": VoterRecord(
            voter_id="voter-001",
            password_hash=hash_password(TEST_PASSWORD),
            totp_secret=TEST_SECRET,
        )
    }

    coordinator = LoginCoordinator(
        lookup_voter=lambda account: voters.get(account),
        rate_limiter=LoginRateLimiter(
            clock=lambda: now[0]
        ),
        clock=lambda: now[0],
    )

    monkeypatch.setitem(
        application.app.config,
        "TESTING",
        True
    )

    monkeypatch.setitem(
        application.app.config,
        "LOGIN_COORDINATOR",
        coordinator
    )

    # Create synthetic database records in a
    # temporary application context.
    with application.app.app_context():
        db.drop_all()
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

    # IMPORTANT:
    # Do not keep the setup application context
    # open while making HTTP requests.
    # Each request must have its own context,
    # allowing Flask-WTF to generate fresh tokens.
    with application.app.test_client() as client:
        yield client, now

    # Clean up using a separate application context.
    with application.app.app_context():
        db.session.remove()
        db.drop_all()


def csrf_headers(client):
    """
    Obtain a CSRF token from the current session
    with an appropriate HTTPS Referer header.
    """

    response = client.get(
        "/login/csrf",
        base_url=HTTPS_URL
    )

    assert response.status_code == 200

    return {
        "X-CSRFToken": response.get_json()["csrf_token"],
        "Referer": HTTPS_URL + "/login/csrf",
    }


def login(client, now, password=TEST_PASSWORD):
    code = pyotp.TOTP(TEST_SECRET).at(
        int(now[0])
    )

    return client.post(
        "/login",
        base_url=HTTPS_URL,
        headers=csrf_headers(client),
        environ_overrides={
            "REMOTE_ADDR": "203.0.113.10"
        },
        json={
            "account_id": "voter-001",
            "password": password,
            "totp_code": code,
        },
    )


def read(client, path):
    return client.get(
        path,
        base_url=HTTPS_URL
    )


def update_address(client, record_id, address):
    return client.patch(
        f"/records/addresses/{record_id}",
        base_url=HTTPS_URL,
        headers=csrf_headers(client),
        json={
            "address_text": address
        },
    )


# Test 1: Successful MFA login allows own records.
def test_login_allows_own_record_access(environment):
    client, now = environment

    before_login = read(
        client, "/records/enrolments/101"
    )

    assert before_login.status_code == 401

    result = login(client, now)

    assert result.status_code == 200

    enrolment = read(
        client, "/records/enrolments/101"
    )

    address = read(
        client, "/records/addresses/201"
    )

    assert enrolment.status_code == 200
    assert address.status_code == 200


# Test 2: MFA login cannot access another voter.
def test_other_voter_records_denied(environment):
    client, now = environment

    assert login(client, now).status_code == 200

    enrolment = read(
        client, "/records/enrolments/102"
    )

    address = read(
        client, "/records/addresses/202"
    )

    assert enrolment.status_code == 404
    assert address.status_code == 404


# Test 3: Authenticated voter updates own address.
def test_owner_updates_address_after_login(environment):
    client, now = environment

    assert login(client, now).status_code == 200

    response = update_address(
        client,
        201,
        "Updated Address One"
    )

    assert response.status_code == 200

    saved = read(
        client, "/records/addresses/201"
    )

    assert saved.status_code == 200
    assert saved.get_json()["address_text"] == (
        "Updated Address One"
    )


# Test 4: Cannot modify another voter's address.
def test_other_voter_address_update_blocked(environment):
    client, now = environment

    assert login(client, now).status_code == 200

    response = update_address(
        client,
        202,
        "Unauthorised Change"
    )

    assert response.status_code == 404

    # Direct database access requires an explicit
    # Flask application context.
    with application.app.app_context():
        record = db.session.get(
            AddressRecord,
            202
        )

        assert record is not None

        assert record.address_text == (
            "Original Address Two"
        )


# Test 5: Address update requires CSRF.
def test_address_update_requires_csrf(environment):
    client, now = environment

    assert login(client, now).status_code == 200

    response = client.patch(
        "/records/addresses/201",
        base_url=HTTPS_URL,
        json={
            "address_text": "Unprotected Change"
        },
    )

    assert response.status_code == 400


# Test 6: Failed login cannot access records.
def test_failed_login_cannot_read_records(environment):
    client, now = environment

    response = login(
        client,
        now,
        password="IncorrectPassword!"
    )

    assert response.status_code == 401

    protected = read(
        client,
        "/records/addresses/201"
    )

    assert protected.status_code == 401


# Test 7: Logout revokes protected record access.
def test_logout_revokes_record_access(environment):
    client, now = environment

    assert login(client, now).status_code == 200

    before_logout = read(
        client,
        "/records/addresses/201"
    )

    assert before_logout.status_code == 200

    logout_response = client.post(
        "/logout",
        base_url=HTTPS_URL,
        headers=csrf_headers(client),
    )

    assert logout_response.status_code == 200

    after_logout = read(
        client,
        "/records/addresses/201"
    )

    assert after_logout.status_code == 401


# Test 8: CSRF token alone does not grant access.
def test_unauthenticated_address_update_denied(
    environment
):
    client, _ = environment

    response = update_address(
        client,
        201,
        "Unauthorised Change"
    )

    assert response.status_code == 401
