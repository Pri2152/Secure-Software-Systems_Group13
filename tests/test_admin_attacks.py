"""
SR-02: Elevation-protected routes and staff attack tests.

End-to-end scenarios through the HTTP endpoints:
stolen password, forged gateway headers, session
fixation, CSRF, privilege escalation, generic or
shared accounts, and the audit trail of it all.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from admin import find_staff_account
from audit.log import AuditLog
from audit.routes import create_audit_blueprint
from crypto_agility import CryptoService, DEFAULT_POLICY, default_registry
from crypto_agility.keys import KeyStore
from records import db
from staff_support import (
    HTTPS_URL,
    PASSWORD,
    login_as,
    make_certificate,
    staff_environment,
    staff_request,
)


NEW_PASSWORD = "New-Staff-Password-2026!"


@pytest.fixture
def env():
    with staff_environment() as environment:
        yield environment


def elevate(env, name, permission, password=PASSWORD):
    return staff_request(
        env.client, "post", "/staff/elevate",
        {"permission": permission, "password": password},
        pem=env.pems[name],
    )


def new_account(**overrides):
    payload = {
        "staff_id": "officer-sam-taylor",
        "full_name": "Sam Taylor",
        "role": "officer",
        "password": NEW_PASSWORD,
        "cert_fingerprint": make_certificate("Sam Taylor")[1],
    }
    payload.update(overrides)

    return payload


def create(env, payload):
    return staff_request(env.client, "post", "/staff/accounts", payload)


# Test 1: Administrator with elevation creates a person-linked account
def test_elevated_administrator_creates_account(env):
    login_as(env, "ada")
    elevate(env, "ada", "staff.manage")

    response = create(env, new_account())

    assert response.status_code == 201
    assert response.get_json() == {
        "staff_id": "officer-sam-taylor", "role": "officer"
    }
    assert env.audit.events[-1]["event_type"] == "STAFF_ACCOUNT_CREATED"
    assert env.audit.events[-1]["actor_id"] == "admin-ada-lovelace"


# Test 2: Same administrator without elevation -> 403
def test_account_creation_requires_elevation(env):
    login_as(env, "ada")

    assert create(env, new_account()).status_code == 403


# Test 3: Elevation expires -> account management refused again
def test_account_creation_after_elevation_expiry(env):
    login_as(env, "ada")
    elevate(env, "ada", "staff.manage")

    for _ in range(2):
        env.clock[0] += 450
        staff_request(env.client, "get", "/staff/session")

    assert create(env, new_account()).status_code == 403


# Test 4: Other roles cannot manage staff, even when elevated elsewhere
@pytest.mark.parametrize("name, permission", [
    ("jane", "roll.propose_bulk"),
    ("grace", "audit.read"),
    ("li", "candidates.enter"),
])
def test_other_roles_cannot_manage_staff(env, name, permission):
    login_as(env, name)
    elevate(env, name, permission)

    assert elevate(env, name, "staff.manage").status_code == 403
    assert create(env, new_account()).status_code == 403


# Test 5: Generic or shared account names are refused over HTTP
@pytest.mark.parametrize("staff_id", ["admin", "officer-01", "shared"])
def test_generic_account_names_refused_over_http(env, staff_id):
    login_as(env, "ada")
    elevate(env, "ada", "staff.manage")

    response = create(env, new_account(staff_id=staff_id))

    assert response.status_code == 400
    assert env.audit.events[-1]["event_type"] == (
        "STAFF_ACCOUNT_CREATE_REJECTED"
    )


# Test 6: A certificate already issued to someone cannot be reused
def test_shared_certificate_refused_over_http(env):
    login_as(env, "ada")
    elevate(env, "ada", "staff.manage")

    with env.app.app_context():
        janes = find_staff_account(
            db.session, "officer-jane-citizen"
        ).cert_fingerprint

    response = create(env, new_account(cert_fingerprint=janes))

    assert response.status_code == 400


# Test 7: Unknown fields (mass assignment) are refused
def test_account_creation_rejects_unknown_fields(env):
    login_as(env, "ada")
    elevate(env, "ada", "staff.manage")

    response = create(env, {**new_account(), "is_active": True})

    assert response.status_code == 400


# Test 8: A new account can log in with its own certificate only
def test_created_account_can_log_in(env):
    pem, fingerprint = make_certificate("Sam Taylor")
    login_as(env, "ada")
    elevate(env, "ada", "staff.manage")
    create(env, new_account(cert_fingerprint=fingerprint))

    def sam_login(certificate):
        return staff_request(
            env.client, "post", "/staff/login",
            {"staff_id": "officer-sam-taylor", "password": NEW_PASSWORD},
            pem=certificate,
        ).status_code

    assert sam_login(env.pems["jane"]) == 401
    assert sam_login(pem) == 200


# Test 9: Deactivated staff cannot log in and lose their grants
def test_deactivated_staff_lose_access(env):
    login_as(env, "grace")
    elevate(env, "grace", "audit.read")

    login_as(env, "ada")
    elevate(env, "ada", "staff.manage")
    response = staff_request(
        env.client, "post",
        "/staff/accounts/auditor-grace-hopper/deactivate",
    )

    assert response.status_code == 200
    assert login_as(env, "grace").status_code == 401

    with env.app.app_context():
        assert env.services.elevation.active_grant(
            "auditor-grace-hopper", "audit.read"
        ) is None


# Test 10: Administrators cannot deactivate themselves
def test_self_deactivation_refused(env):
    login_as(env, "ada")
    elevate(env, "ada", "staff.manage")

    response = staff_request(
        env.client, "post", "/staff/accounts/admin-ada-lovelace/deactivate"
    )

    assert response.status_code == 409


# Test 11: Phished password alone (no certificate) is useless
def test_phished_password_without_certificate_fails(env):
    response = login_as(env, "ada", pem=None)

    assert response.status_code == 401


# Test 12: Forged X-EVP headers sent straight to the backend fail
def test_forged_gateway_headers_fail(env):
    response = login_as(env, "ada", peer="203.0.113.99")

    assert response.status_code == 401


# Test 13: Session fixation: a pre-login session ID is not promoted
def test_pre_login_session_id_is_not_promoted(env):
    env.client.get("/staff/csrf", base_url=HTTPS_URL)
    planted = env.client.get_cookie("session", domain="localhost").value

    login_as(env, "ada")

    env.client.set_cookie("session", planted, domain="localhost")

    assert staff_request(env.client, "get", "/staff/session").status_code == 401


# Test 14: Elevation without a CSRF token is refused
def test_elevation_requires_csrf_token(env):
    login_as(env, "ada")

    response = env.client.post(
        "/staff/elevate", base_url=HTTPS_URL,
        json={"permission": "staff.manage", "password": PASSWORD},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 400


# Test 15: A voter session cannot reach staff management
def test_voter_session_cannot_manage_staff(env):
    with env.client.session_transaction() as current:
        current["authenticated"] = True
        current["voter_id"] = "voter-001"
        current["role"] = "voter"
        current["last_activity"] = env.clock[0]

    assert create(env, new_account()).status_code == 401


# Test 16: Session role tampering cannot bypass the database grant check
def test_role_tampering_does_not_bypass_elevation(env):
    login_as(env, "jane")

    with env.client.session_transaction() as current:
        current["role"] = "administrator"

    assert create(env, new_account()).status_code == 403


# Test 17: Audit endpoints can require elevation (auditor JIT access)
def test_audit_endpoints_behind_elevation():
    crypto = CryptoService(
        default_registry(), DEFAULT_POLICY, KeyStore.ephemeral()
    )
    audit_log = AuditLog(
        create_engine("sqlite://", poolclass=StaticPool,
                      connect_args={"check_same_thread": False}),
        crypto=crypto,
    )
    audit_log.create_schema()

    with staff_environment(audit=audit_log.record_event) as env:
        env.app.register_blueprint(create_audit_blueprint(
            env.services.elevation.require_elevated, audit_log,
        ))

        login_as(env, "grace")

        def read():
            return staff_request(
                env.client, "get", "/audit/events?stream=admin"
            )

        assert read().status_code == 403

        elevate(env, "grace", "audit.read")
        response = read()

        assert response.status_code == 200

        types = [e["event_type"] for e in response.get_json()["events"]]

        assert "STAFF_LOGIN_SUCCESS" in types
        assert "STAFF_ELEVATION_GRANTED" in types
        assert PASSWORD not in response.get_data(as_text=True)
        assert audit_log.verify_chain("admin").ok is True


# Test 18: The whole staff flow leaves a complete admin audit trail
def test_staff_flow_audit_trail(env):
    login_as(env, "ada", password="Wrong-Pass-2026!")
    login_as(env, "ada")
    elevate(env, "ada", "staff.manage")
    create(env, new_account())
    staff_request(env.client, "post", "/staff/logout")

    assert env.audit.types() == [
        "STAFF_LOGIN_FAILURE",
        "STAFF_LOGIN_SUCCESS",
        "STAFF_STEP_UP_SUCCESS",
        "STAFF_ELEVATION_GRANTED",
        "STAFF_ACCOUNT_CREATED",
        "STAFF_ELEVATION_REVOKED",
        "STAFF_LOGOUT",
    ]

    for event in env.audit.events:
        assert event["stream"] == "admin"
        assert PASSWORD not in str(event)
        assert NEW_PASSWORD not in str(event)
