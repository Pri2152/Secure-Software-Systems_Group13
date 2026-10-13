
import pytest
import pyotp

import app as application

from auth import hash_password
from login_flow import LoginCoordinator, VoterRecord
from rate_limit import LoginRateLimiter


HTTPS_URL = "https://localhost"
TEST_PASSWORD = "CorrectPassword123!"
TEST_SECRET = "JBSWY3DPEHPK3PXP"


@pytest.fixture
def environment(monkeypatch):

    clock = [1700000000.0]

    voter = VoterRecord(
        voter_id="voter-001",
        password_hash=hash_password(TEST_PASSWORD),
        totp_secret=TEST_SECRET,
    )

    coordinator = LoginCoordinator(
        lookup_voter=lambda account: (
            voter if account == "voter-001" else None
        ),
        rate_limiter=LoginRateLimiter(
            clock=lambda: clock[0]
        ),
        clock=lambda: clock[0],
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

    with application.app.test_client() as client:
        yield client, clock


def login_request(
    client,
    clock,
    account="voter-001",
    password=TEST_PASSWORD,
    code=None,
    source="203.0.113.10",
    extra_headers=None,
):
    if code is None:
        code = pyotp.TOTP(TEST_SECRET).at(
            int(clock[0])
        )

    csrf_response = client.get(
        "/login/csrf",
        base_url=HTTPS_URL
    )

    assert csrf_response.status_code == 200

    token = csrf_response.get_json()["csrf_token"]

    headers = {
        "X-CSRFToken": token,
        "Referer": HTTPS_URL + "/login/csrf",
    }

    if extra_headers:
        headers.update(extra_headers)

    return client.post(
        "/login",
        base_url=HTTPS_URL,
        headers=headers,
        environ_overrides={
            "REMOTE_ADDR": source
        },
        json={
            "account_id": account,
            "password": password,
            "totp_code": code,
        },
    )


def test_csrf_token_issued(environment):
    client, _ = environment

    response = client.get(
        "/login/csrf",
        base_url=HTTPS_URL
    )

    assert response.status_code == 200
    assert response.get_json()["csrf_token"]


def test_correct_password_and_mfa_login(environment):
    client, clock = environment

    response = login_request(client, clock)

    assert response.status_code == 200

    status = client.get(
        "/session-status",
        base_url=HTTPS_URL
    )

    assert status.status_code == 200
    assert status.get_json()["authenticated"] is True


def test_wrong_password_rejected(environment):
    client, clock = environment

    response = login_request(
        client,
        clock,
        password="WrongPassword123!"
    )

    assert response.status_code == 401

    status = client.get(
        "/session-status",
        base_url=HTTPS_URL
    )

    assert status.status_code == 401


def test_wrong_mfa_rejected(environment):
    client, clock = environment

    correct = pyotp.TOTP(TEST_SECRET).at(
        int(clock[0])
    )

    wrong = str(
        (int(correct) + 1) % 1000000
    ).zfill(6)

    response = login_request(
        client,
        clock,
        code=wrong
    )

    assert response.status_code == 401


def test_login_without_csrf_rejected(environment):
    client, clock = environment

    code = pyotp.TOTP(TEST_SECRET).at(
        int(clock[0])
    )

    response = client.post(
        "/login",
        base_url=HTTPS_URL,
        json={
            "account_id": "voter-001",
            "password": TEST_PASSWORD,
            "totp_code": code,
        },
    )

    assert response.status_code == 400


def test_malformed_json_rejected(environment):
    client, _ = environment

    csrf_response = client.get(
        "/login/csrf",
        base_url=HTTPS_URL
    )

    token = csrf_response.get_json()["csrf_token"]

    response = client.post(
        "/login",
        base_url=HTTPS_URL,
        headers={
            "X-CSRFToken": token,
            "Referer": HTTPS_URL + "/login/csrf",
        },
        json=["invalid", "request"],
    )

    assert response.status_code == 400


def test_five_failures_block_next_login(environment):
    client, clock = environment

    for index in range(5):
        response = login_request(
            client,
            clock,
            password="WrongPassword123!",
            source=f"203.0.113.{index + 1}",
        )

        assert response.status_code == 401

    blocked = login_request(
        client,
        clock,
        source="198.51.100.20",
    )

    assert blocked.status_code == 429


def test_login_requires_configured_service(
    environment, monkeypatch
):
    client, clock = environment

    monkeypatch.setitem(
        application.app.config,
        "LOGIN_COORDINATOR",
        None
    )

    response = login_request(client, clock)

    assert response.status_code == 503


def test_untrusted_forwarded_header_ignored(environment):
    client, clock = environment

    for index in range(5):
        response = login_request(
            client,
            clock,
            account=f"unknown-{index}",
            source="203.0.113.50",
        )

        assert response.status_code == 401

    response = login_request(
        client,
        clock,
        source="203.0.113.50",
        extra_headers={
            "X-Forwarded-For": "198.51.100.25"
        },
    )

    assert response.status_code == 429
