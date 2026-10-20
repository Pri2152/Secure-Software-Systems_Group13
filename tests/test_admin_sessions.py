"""
SR-02 (with SR-16): Staff session tests.

Checks session contents, fixation protection, idle
timeout (injected clock), voter/staff separation and
compatibility with Workstream E's SR-04 RBAC.
"""

import pytest
from flask import jsonify

from admin import find_staff_account
from admin.sessions import INACTIVITY_LIMIT_SECONDS
from records import db
from staff_support import (
    HTTPS_URL,
    PASSWORD,
    login_as,
    staff_environment,
    staff_request,
)


RBAC_SESSION_KEYS = {"staff_authenticated", "staff_id", "role"}


@pytest.fixture
def env():
    with staff_environment() as environment:
        yield environment


def session_keys(env):
    with env.client.session_transaction() as current:
        return dict(current)


def status(env):
    return staff_request(env.client, "get", "/staff/session").status_code


def session_cookie(env):
    cookie = env.client.get_cookie("session", domain="localhost")

    return cookie.value if cookie else None


# Test 1: Session holds exactly the RBAC keys plus last_activity
def test_session_has_exactly_rbac_keys(env):
    login_as(env, "jane")

    current = session_keys(env)
    stored = {key for key in current if not key.startswith("_")}

    assert stored == RBAC_SESSION_KEYS | {"last_activity"}
    assert current["staff_authenticated"] is True
    assert current["staff_id"] == "officer-jane-citizen"
    assert current["role"] == "officer"


# Test 2: Session ID changes at login (fixation protection)
def test_session_id_is_regenerated(env):
    env.client.get("/staff/csrf", base_url=HTTPS_URL)
    before = session_cookie(env)

    login_as(env, "jane")

    assert before is not None
    assert session_cookie(env) != before


# Test 3: Staff login replaces a voter session (no voter keys remain)
def test_voter_keys_are_removed_at_staff_login(env):
    with env.client.session_transaction() as current:
        current["authenticated"] = True
        current["voter_id"] = "voter-001"

    login_as(env, "jane")

    current = session_keys(env)

    assert "voter_id" not in current
    assert "authenticated" not in current


# Test 4: Session endpoint works only after login
def test_session_status_requires_login(env):
    assert status(env) == 401

    login_as(env, "jane")

    assert status(env) == 200


# Test 5: A voter session cannot call staff endpoints
@pytest.mark.parametrize("method, path", [
    ("get", "/staff/session"), ("post", "/staff/logout"),
])
def test_voter_session_cannot_use_staff_endpoints(env, method, path):
    with env.client.session_transaction() as current:
        current["authenticated"] = True
        current["voter_id"] = "voter-001"
        current["role"] = "voter"
        current["last_activity"] = env.clock[0]

    assert staff_request(env.client, method, path).status_code == 401


# Test 6: A session claiming both voter and staff login is refused
def test_ambiguous_session_is_refused(env):
    login_as(env, "jane")

    with env.client.session_transaction() as current:
        current["authenticated"] = True

    assert status(env) == 401
    assert session_keys(env).get("staff_authenticated") is None


# Test 7: A staff flag with a non-staff role is refused
@pytest.mark.parametrize("role", ["voter", "superuser", None])
def test_non_staff_role_is_refused(env, role):
    login_as(env, "jane")

    with env.client.session_transaction() as current:
        current["role"] = role

    assert status(env) == 401


# Test 8: 10 minutes of inactivity ends the session
def test_idle_session_expires(env):
    login_as(env, "jane")

    env.clock[0] += INACTIVITY_LIMIT_SECONDS

    response = staff_request(env.client, "get", "/staff/session")

    assert response.status_code == 401
    assert response.get_json() == {
        "error": "Session expired due to inactivity"
    }
    assert status(env) == 401


# Test 9: Activity keeps the session alive
def test_activity_refreshes_session(env):
    login_as(env, "jane")

    for _ in range(3):
        env.clock[0] += INACTIVITY_LIMIT_SECONDS - 1
        assert status(env) == 200


# Test 10: Tampered last_activity fails closed
@pytest.mark.parametrize("value", [None, "now", True, float("inf"), 9e12])
def test_invalid_last_activity_fails_closed(env, value):
    login_as(env, "jane")

    with env.client.session_transaction() as current:
        current["last_activity"] = value

    assert status(env) == 401


# Test 11: Logout clears the session and is audited
def test_logout_clears_session(env):
    login_as(env, "jane")

    response = staff_request(env.client, "post", "/staff/logout")

    assert response.status_code == 200
    assert status(env) == 401
    assert env.audit.events[-1]["event_type"] == "STAFF_LOGOUT"
    assert env.audit.events[-1]["actor_id"] == "officer-jane-citizen"


# Test 12: Idle expiry is audited on the admin stream
def test_idle_expiry_is_audited(env):
    login_as(env, "jane")
    env.clock[0] += INACTIVITY_LIMIT_SECONDS

    status(env)

    event = env.audit.events[-1]

    assert event["event_type"] == "STAFF_SESSION_EXPIRED"
    assert event["stream"] == "admin"
    assert event["actor_type"] == "staff"


# Test 13: Logging in as someone else replaces the whole session
def test_second_login_replaces_identity(env):
    login_as(env, "jane")
    login_as(env, "li")

    assert session_keys(env)["staff_id"] == "delegate-li-wei"
    assert session_keys(env)["role"] == "delegate"


# Test 14: Works with Workstream E's real SR-04 decorator when available
def test_session_is_accepted_by_workstream_e_rbac(env):
    rbac = pytest.importorskip("platform_security.rbac")

    @env.app.get("/rbac-probe")
    @rbac.require_permission("candidates.read")
    def rbac_probe():
        return jsonify({"ok": True})

    assert staff_request(env.client, "get", "/rbac-probe").status_code == 401

    login_as(env, "jane")
    assert staff_request(env.client, "get", "/rbac-probe").status_code == 200

    login_as(env, "li")
    assert staff_request(env.client, "get", "/rbac-probe").status_code == 403


# Test 15: Deactivating an account ends its open session
def test_deactivated_account_session_is_revoked(env):
    login_as(env, "jane")
    assert status(env) == 200

    with env.app.app_context():
        find_staff_account(db.session, "officer-jane-citizen").is_active = False
        db.session.commit()

    response = staff_request(env.client, "get", "/staff/session")

    assert response.status_code == 401
    assert response.get_json() == {"error": "Authentication required"}
    assert env.audit.events[-1]["event_type"] == "STAFF_SESSION_REVOKED"
    assert env.audit.events[-1]["actor_id"] == "officer-jane-citizen"
    assert session_keys(env).get("staff_id") is None


# Test 16: A session for an account that no longer exists is revoked
def test_missing_account_session_is_revoked(env):
    login_as(env, "jane")

    with env.client.session_transaction() as current:
        current["staff_id"] = "officer-ghost-person"

    assert status(env) == 401
    assert env.audit.events[-1]["event_type"] == "STAFF_SESSION_REVOKED"


# Test 17: Revocation also clears the account's elevations
def test_revoked_session_clears_elevations(env):
    login_as(env, "grace")
    staff_request(env.client, "post", "/staff/elevate",
                  {"permission": "audit.read", "password": PASSWORD},
                  pem=env.pems["grace"])

    with env.app.app_context():
        find_staff_account(db.session, "auditor-grace-hopper").is_active = False
        db.session.commit()

    status(env)

    with env.app.app_context():
        assert env.services.elevation.active_permissions(
            "auditor-grace-hopper"
        ) == []
