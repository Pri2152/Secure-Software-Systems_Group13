"""
SR-02: Staff login tests (client certificate + Argon2id password).

Requests arrive as from the Nginx mTLS gateway
(loopback peer, X-EVP-* headers); certificates are
throwaway ones generated in memory.
"""

import pytest

from admin import find_staff_account
from crypto_agility.passwords import Argon2idAlgorithm, Argon2Parameters
from records import db
from staff_support import (
    PASSWORD,
    csrf_headers,
    make_certificate,
    staff_environment,
    staff_request,
)


GENERIC_401 = {"error": "Invalid authentication credentials"}


@pytest.fixture
def env():
    with staff_environment() as environment:
        yield {
            "client": environment.client,
            "audit": environment.audit,
            "clock": environment.clock,
            "app": environment.app,
            "jane_pem": environment.pems["jane"],
            "li_pem": environment.pems["li"],
        }


def login(env, staff_id="officer-jane-citizen", password=PASSWORD,
          pem="jane", **kwargs):
    if isinstance(pem, str):
        pem = env[f"{pem}_pem"]

    return staff_request(
        env["client"], "post", "/staff/login",
        {"staff_id": staff_id, "password": password}, pem=pem, **kwargs,
    )


# Test 1: Certificate + password logs in
def test_valid_certificate_and_password_succeed(env):
    response = login(env)

    assert response.status_code == 200
    assert response.get_json()["role"] == "officer"


# Test 2: Password without a client certificate -> 401
def test_missing_certificate_is_rejected(env):
    response = login(env, pem=None)

    assert response.status_code == 401
    assert response.get_json() == GENERIC_401


# Test 3: Another staff member's certificate -> 401
def test_other_staff_certificate_is_rejected(env):
    response = login(env, pem="li")

    assert response.status_code == 401
    assert response.get_json() == GENERIC_401


# Test 4: Correct certificate, wrong password -> same 401
def test_wrong_password_gives_same_error(env):
    response = login(env, password="Wrong-Password-2026!")

    assert response.status_code == 401
    assert response.get_json() == GENERIC_401


# Test 5: Unknown account -> same 401
def test_unknown_account_gives_same_error(env):
    response = login(env, staff_id="officer-nobody-here")

    assert response.status_code == 401
    assert response.get_json() == GENERIC_401


# Test 6: Unregistered (self-made) certificate -> 401
def test_unregistered_certificate_is_rejected(env):
    response = login(env, pem=make_certificate("Jane Citizen")[0])

    assert response.status_code == 401


# Test 7: Headers sent straight to the backend (not via gateway) -> 401
def test_forged_gateway_headers_are_not_trusted(env):
    response = login(env, peer="198.51.100.9")

    assert response.status_code == 401
    assert env["audit"].events[-1]["details"] == {
        "reason": "untrusted_gateway"
    }


# Test 8: A gateway claiming a failed verification is refused
def test_unverified_certificate_status_is_rejected(env):
    response = env["client"].post(
        "/staff/login", base_url="https://localhost",
        json={"staff_id": "officer-jane-citizen", "password": PASSWORD},
        headers={"X-EVP-Source-IP": "203.0.113.10",
                 "X-EVP-Client-Verify": "FAILED:certificate expired",
                 **csrf_headers(env["client"])},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 401


# Test 9: Five failures lock the account -> 429, even with valid factors
def test_rate_limit_blocks_after_five_failures(env):
    for _ in range(5):
        assert login(env, password="Wrong-Password-2026!").status_code == 401

    response = login(env)

    assert response.status_code == 429
    assert response.get_json() == {"error": "Too many authentication attempts"}


# Test 10: Rate limit window ends after 15 minutes (injected clock)
def test_rate_limit_expires(env):
    for _ in range(5):
        login(env, password="Wrong-Password-2026!")

    env["clock"][0] += 15 * 60

    assert login(env).status_code == 200


# Test 11: Missing-certificate attempts also count towards the limit
def test_certificate_failures_count_towards_limit(env):
    for _ in range(5):
        login(env, pem=None)

    assert login(env).status_code == 429


# Test 12: Malformed input -> 400
@pytest.mark.parametrize("payload", [
    None,
    {},
    {"staff_id": "officer-jane-citizen"},
    {"staff_id": "officer-jane-citizen", "password": PASSWORD, "role": "x"},
    {"staff_id": 7, "password": PASSWORD},
    {"staff_id": "officer-jane-citizen", "password": ""},
    {"staff_id": "a" * 65, "password": PASSWORD},
])
def test_malformed_login_is_rejected(env, payload):
    response = staff_request(
        env["client"], "post", "/staff/login", payload, pem=env["jane_pem"]
    )

    assert response.status_code == 400


# Test 13: Login without a CSRF token is refused
def test_login_requires_csrf_token(env):
    response = env["client"].post(
        "/staff/login", base_url="https://localhost",
        json={"staff_id": "officer-jane-citizen", "password": PASSWORD},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 400


# Test 14: Success and failure are audited on the admin stream
def test_login_events_are_audited(env):
    login(env, password="Wrong-Password-2026!")
    login(env)

    failure, success = env["audit"].events

    assert failure["event_type"] == "STAFF_LOGIN_FAILURE"
    assert failure["details"] == {"reason": "wrong_password"}
    assert success["event_type"] == "STAFF_LOGIN_SUCCESS"
    assert success["actor_id"] == "officer-jane-citizen"
    assert success["source_ip"] == "203.0.113.10"

    for event in env["audit"].events:
        assert event["stream"] == "admin"
        assert event["actor_type"] == "staff"
        assert PASSWORD not in str(event)
        assert "Wrong-Password" not in str(event)


# Test 15: Specific failure reasons go to the audit log only
@pytest.mark.parametrize("kwargs, reason", [
    ({"pem": None}, "missing_certificate"),
    ({"pem": "li"}, "certificate_mismatch"),
    ({"staff_id": "officer-nobody-here"}, "unknown_account"),
])
def test_failure_reasons_are_audited(env, kwargs, reason):
    response = login(env, **kwargs)

    assert response.get_json() == GENERIC_401
    assert env["audit"].events[-1]["details"] == {"reason": reason}


# Test 16: Deactivated accounts cannot log in
def test_inactive_account_is_rejected(env):
    with env["app"].app_context():
        find_staff_account(db.session, "officer-jane-citizen").is_active = False
        db.session.commit()

    assert login(env).status_code == 401
    assert env["audit"].events[-1]["details"] == {
        "reason": "inactive_account"
    }


# Test 17: Outdated password hash is upgraded on login (SR-14 helper)
def test_outdated_password_hash_is_upgraded(env):
    weak = Argon2idAlgorithm(
        "argon2id-test-weak",
        Argon2Parameters(time_cost=1, memory_cost_kib=8192, parallelism=1),
    )
    with env["app"].app_context():
        account = find_staff_account(db.session, "officer-jane-citizen")
        account.password_hash = weak.hash(PASSWORD)
        db.session.commit()

    assert login(env).status_code == 200

    with env["app"].app_context():
        upgraded = find_staff_account(db.session, "officer-jane-citizen")

        assert upgraded.password_hash.startswith(
            "$argon2id$v=19$m=65536,t=3,p=4$"
        )


# SR-15: the central validator checks the staff login body
@pytest.mark.parametrize("staff_id", [
    "' OR 1=1--",
    "<script>alert(1)</script>",
    "officer jane",
])
def test_attack_text_as_staff_id_gets_a_plain_400(env, staff_id):
    response = login(env, staff_id=staff_id)

    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid request"}
    assert b"script" not in response.data


def test_staff_login_route_uses_the_central_validator():
    from pathlib import Path

    source = (
        Path(__file__).resolve().parent.parent / "admin" / "routes.py"
    ).read_text()

    assert "validate_staff_login_request" in source
