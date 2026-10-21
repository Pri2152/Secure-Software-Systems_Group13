"""
SR-02: Just-in-time elevation tests.

Probe routes protected by require_elevated stand in for
privileged operations; the 15-minute window is tested
with an injected clock.
"""

import pytest
from flask import jsonify

from admin.elevation import ELEVATION_SECONDS
from admin.sessions import INACTIVITY_LIMIT_SECONDS
from staff_support import (
    PASSWORD,
    login_as,
    staff_environment,
    staff_request,
)


@pytest.fixture
def env():
    with staff_environment() as environment:
        require_elevated = environment.services.elevation.require_elevated

        @environment.app.get("/probe/audit-read")
        @require_elevated("audit.read")
        def probe_audit_read():
            return jsonify({"ok": True})

        @environment.app.get("/probe/audit-verify")
        @require_elevated("audit.verify")
        def probe_audit_verify():
            return jsonify({"ok": True})

        yield environment


def elevate(env, name, permission, password=PASSWORD, pem="own"):
    pem = env.pems[name] if pem == "own" else pem

    return staff_request(
        env.client, "post", "/staff/elevate",
        {"permission": permission, "password": password}, pem=pem,
    )


def probe(env, path="/probe/audit-read"):
    return staff_request(env.client, "get", path).status_code


def keep_alive(env, seconds):
    """Advance the clock while staying inside the idle limit."""

    step = INACTIVITY_LIMIT_SECONDS - 1

    while seconds > 0:
        env.clock[0] += min(step, seconds)
        seconds -= step
        staff_request(env.client, "get", "/staff/session")


# Test 1: Privileged route without elevation -> 403
def test_privileged_route_requires_elevation(env):
    login_as(env, "grace")

    response = staff_request(env.client, "get", "/probe/audit-read")

    assert response.status_code == 403
    assert response.get_json() == {"error": "Elevation required"}


# Test 2: After step-up elevation -> 200
def test_elevation_allows_privileged_route(env):
    login_as(env, "grace")

    response = elevate(env, "grace", "audit.read")

    assert response.status_code == 200
    assert response.get_json()["expires_in_seconds"] == ELEVATION_SECONDS
    assert probe(env) == 200


# Test 3: Still valid just before 15 minutes
def test_elevation_valid_until_window_ends(env):
    login_as(env, "grace")
    elevate(env, "grace", "audit.read")

    keep_alive(env, ELEVATION_SECONDS - 1)

    assert probe(env) == 200


# Test 4: After 15 minutes -> 403 and the expiry is audited
def test_elevation_expires_after_fifteen_minutes(env):
    login_as(env, "grace")
    elevate(env, "grace", "audit.read")

    keep_alive(env, ELEVATION_SECONDS)

    assert probe(env) == 403
    assert "STAFF_ELEVATION_EXPIRED" in env.audit.types()
    assert env.audit.types().count("STAFF_ELEVATION_EXPIRED") == 1


# Test 5: Elevation is per permission
def test_elevation_covers_only_its_permission(env):
    login_as(env, "grace")
    elevate(env, "grace", "audit.read")

    assert probe(env, "/probe/audit-read") == 200
    assert probe(env, "/probe/audit-verify") == 403


# Test 6: Elevation for a permission the role lacks -> 403, no grant
def test_elevation_for_unheld_permission_is_forbidden(env):
    login_as(env, "jane")

    response = elevate(env, "jane", "audit.read")

    assert response.status_code == 403
    assert probe(env) == 403
    assert env.audit.events[-1]["event_type"] == "STAFF_ELEVATION_DENIED"


# Test 7: Unknown permission -> 403
def test_elevation_for_unknown_permission_is_forbidden(env):
    login_as(env, "ada")

    assert elevate(env, "ada", "everything.all").status_code == 403


# Test 8: Wrong step-up password -> 401, no grant
def test_wrong_step_up_password_is_rejected(env):
    login_as(env, "grace")

    response = elevate(env, "grace", "audit.read", password="Wrong-Pass-2026!")

    assert response.status_code == 401
    assert response.get_json() == {
        "error": "Invalid authentication credentials"
    }
    assert probe(env) == 403


# Test 9: Step-up without the certificate -> 401
def test_step_up_without_certificate_is_rejected(env):
    login_as(env, "grace")

    assert elevate(env, "grace", "audit.read", pem=None).status_code == 401


# Test 10: Step-up with another person's certificate -> 401
def test_step_up_with_other_certificate_is_rejected(env):
    login_as(env, "grace")

    response = elevate(env, "grace", "audit.read", pem=env.pems["jane"])

    assert response.status_code == 401


# Test 11: Step-up guessing is rate limited -> 429
def test_step_up_guessing_is_rate_limited(env):
    login_as(env, "grace")

    for _ in range(5):
        elevate(env, "grace", "audit.read", password="Wrong-Pass-2026!")

    assert elevate(env, "grace", "audit.read").status_code == 429


# Test 12: Not logged in -> 401 on elevate and on the privileged route
def test_anonymous_cannot_elevate(env):
    assert elevate(env, "grace", "audit.read").status_code == 401
    assert probe(env) == 401


# Test 13: Voter session cannot elevate or call privileged routes
def test_voter_session_cannot_elevate(env):
    with env.client.session_transaction() as current:
        current["authenticated"] = True
        current["voter_id"] = "voter-001"
        current["role"] = "voter"
        current["last_activity"] = env.clock[0]

    assert elevate(env, "grace", "audit.read").status_code == 401
    assert probe(env) == 401


# Test 14: Revoking ends the elevation
def test_revoke_ends_elevation(env):
    login_as(env, "grace")
    elevate(env, "grace", "audit.read")

    response = staff_request(env.client, "post", "/staff/elevate/revoke",
                             {"permission": "audit.read"})

    assert response.get_json() == {"revoked": 1}
    assert probe(env) == 403
    assert "STAFF_ELEVATION_REVOKED" in env.audit.types()


# Test 15: Revoking one permission keeps the others
def test_revoke_one_permission_keeps_others(env):
    login_as(env, "grace")
    elevate(env, "grace", "audit.read")
    elevate(env, "grace", "audit.verify")

    staff_request(env.client, "post", "/staff/elevate/revoke",
                  {"permission": "audit.read"})

    assert probe(env, "/probe/audit-read") == 403
    assert probe(env, "/probe/audit-verify") == 200


# Test 16: Revoke with no permission revokes everything
def test_revoke_all(env):
    login_as(env, "grace")
    elevate(env, "grace", "audit.read")
    elevate(env, "grace", "audit.verify")

    response = staff_request(env.client, "post", "/staff/elevate/revoke", {})

    assert response.get_json() == {"revoked": 2}


# Test 17: Logout clears grants; a new login starts without privileges
def test_logout_clears_grants(env):
    login_as(env, "grace")
    elevate(env, "grace", "audit.read")

    staff_request(env.client, "post", "/staff/logout")
    login_as(env, "grace")

    assert probe(env) == 403


# Test 18: A fresh login revokes grants left by another session
def test_new_login_revokes_previous_grants(env):
    login_as(env, "grace")
    elevate(env, "grace", "audit.read")

    env.client.delete_cookie("session", domain="localhost")
    login_as(env, "grace")

    assert probe(env) == 403


# Test 19: Idle expiry also clears grants
def test_idle_expiry_clears_grants(env):
    login_as(env, "grace")
    elevate(env, "grace", "audit.read")

    env.clock[0] += INACTIVITY_LIMIT_SECONDS
    staff_request(env.client, "get", "/staff/session")
    login_as(env, "grace")

    assert probe(env) == 403


# Test 20: Grants live server-side; session tampering cannot add one
def test_session_tampering_cannot_grant_elevation(env):
    login_as(env, "grace")

    with env.client.session_transaction() as current:
        current["elevations"] = ["audit.read"]
        current["elevated"] = True

    assert probe(env) == 403


# Test 21: Grant of one person does not elevate another
def test_grants_are_per_person(env):
    login_as(env, "grace")
    elevate(env, "grace", "audit.read")

    with env.app.app_context():
        assert env.services.elevation.active_grant(
            "admin-ada-lovelace", "audit.read"
        ) is None


# Test 22: Session status lists active elevations
def test_session_status_lists_elevations(env):
    login_as(env, "grace")
    elevate(env, "grace", "audit.verify")

    status = staff_request(env.client, "get", "/staff/session").get_json()

    assert status["elevations"] == ["audit.verify"]


# Test 23: Re-elevating replaces the active grant
def test_re_elevation_replaces_grant(env):
    login_as(env, "grace")
    elevate(env, "grace", "audit.read")
    keep_alive(env, 300)
    elevate(env, "grace", "audit.read")

    keep_alive(env, ELEVATION_SECONDS - 1)

    assert probe(env) == 200


# Test 24: Malformed elevation requests -> 400
@pytest.mark.parametrize("payload", [
    {}, {"permission": "audit.read"},
    {"permission": "audit.read", "password": PASSWORD, "minutes": 60},
    {"permission": "AUDIT READ", "password": PASSWORD},
    {"permission": 5, "password": PASSWORD},
])
def test_malformed_elevation_request(env, payload):
    login_as(env, "grace")

    response = staff_request(env.client, "post", "/staff/elevate", payload,
                             pem=env.pems["grace"])

    assert response.status_code == 400


# Test 25: Elevation events are on the admin stream, without passwords
def test_elevation_events_are_audited_without_passwords(env):
    login_as(env, "grace")
    elevate(env, "grace", "audit.read", password="Wrong-Pass-2026!")
    elevate(env, "grace", "audit.read")
    staff_request(env.client, "post", "/staff/elevate/revoke", {})

    types = env.audit.types()

    for expected in ("STAFF_STEP_UP_FAILURE", "STAFF_STEP_UP_SUCCESS",
                     "STAFF_ELEVATION_GRANTED", "STAFF_ELEVATION_REVOKED"):
        assert expected in types

    for event in env.audit.events:
        assert event["stream"] == "admin"
        assert event["actor_type"] == "staff"
        assert PASSWORD not in str(event)
        assert "Wrong-Pass" not in str(event)


# Test 26: Decorator refuses an invalid permission name at start-up
def test_require_elevated_validates_permission(env):
    with pytest.raises(ValueError):
        env.services.elevation.require_elevated("not a permission")
