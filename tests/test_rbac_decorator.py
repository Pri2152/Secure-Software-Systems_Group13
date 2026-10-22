
"""
SR-04 tests for the require_permission decorator.

Uses a small Flask test app and a recording fake in
place of Workstream B's record_event() (SR-17), which
is not on main yet.
"""

import logging

import pytest
from flask import Flask, jsonify

from platform_security.rbac import require_permission


BODY_MARKER = "body-secret-7f3a"
QUERY_MARKER = "query-secret-91c2"


class RecordingAudit:
    """Test fake with the same call shape as record_event()."""

    def __init__(self):
        self.events = []

    def __call__(self, event_type, **fields):
        self.events.append((event_type, fields))


class FailingAudit:
    def __call__(self, event_type, **fields):
        raise RuntimeError("audit store unavailable")


def build_client(audit):
    test_app = Flask(__name__)
    test_app.config.update(
        SECRET_KEY="test-only-key",
        TESTING=True,
    )

    calls = []

    @test_app.post("/results/publish")
    @require_permission("results.publish", audit=audit)
    def publish_results():
        calls.append("publish_results")
        return jsonify(message="Published"), 200

    @test_app.post("/ballot/entitlement")
    @require_permission("ballot.request_entitlement", audit=audit)
    def request_entitlement():
        calls.append("request_entitlement")
        return jsonify(message="Entitled"), 200

    client = test_app.test_client()
    client.view_calls = calls

    return client


@pytest.fixture
def audit():
    return RecordingAudit()


@pytest.fixture
def client(audit):
    return build_client(audit)


def set_session(client, **values):
    with client.session_transaction() as test_session:
        test_session.clear()
        test_session.update(values)


def voter_session(client, role="voter"):
    set_session(
        client,
        authenticated=True,
        voter_id="voter-001",
        role=role,
    )


def staff_session(client, role):
    set_session(
        client,
        staff_authenticated=True,
        staff_id="staff-001",
        role=role,
    )


# Authentication

def test_no_session_returns_401(client, audit):
    response = client.post("/results/publish")

    assert response.status_code == 401
    assert response.get_json() == {"error": "Authentication required"}
    assert client.view_calls == []
    assert audit.events == []


@pytest.mark.parametrize("flag", ["authenticated", "staff_authenticated"])
@pytest.mark.parametrize("value", ["true", 1, "1", False, None])
def test_login_flag_must_be_exactly_true(client, flag, value):
    set_session(client, **{flag: value, "role": "administrator"})

    assert client.post("/results/publish").status_code == 401


def test_role_without_login_returns_401(client, audit):
    set_session(client, role="administrator")

    assert client.post("/results/publish").status_code == 401
    assert audit.events == []


# Wrong role and correct role

def test_voter_with_wrong_role_returns_403(client):
    voter_session(client)

    response = client.post("/results/publish")

    assert response.status_code == 403
    assert response.get_json() == {"error": "Forbidden"}
    assert client.view_calls == []


@pytest.mark.parametrize("role", ["auditor", "officer", "delegate"])
def test_staff_with_wrong_role_returns_403(client, role):
    staff_session(client, role)

    assert client.post("/results/publish").status_code == 403
    assert client.view_calls == []


def test_voter_with_correct_role_returns_200(client, audit):
    voter_session(client)

    response = client.post("/ballot/entitlement")

    assert response.status_code == 200
    assert client.view_calls == ["request_entitlement"]
    assert audit.events == []


def test_staff_with_correct_role_returns_200(client, audit):
    staff_session(client, "administrator")

    response = client.post("/results/publish")

    assert response.status_code == 200
    assert client.view_calls == ["publish_results"]
    assert audit.events == []


@pytest.mark.parametrize("role", [None, "", "superuser", "Administrator"])
def test_missing_or_unknown_session_role_returns_403(client, role):
    staff_session(client, role)

    assert client.post("/results/publish").status_code == 403


# Role must match the login type

def test_voter_login_cannot_hold_staff_role(client, audit):
    voter_session(client, role="administrator")

    assert client.post("/results/publish").status_code == 403
    assert client.view_calls == []
    assert audit.events[0][1]["stream"] == "identity"


def test_staff_login_cannot_hold_voter_role(client, audit):
    staff_session(client, "voter")

    assert client.post("/ballot/entitlement").status_code == 403
    assert client.view_calls == []
    assert audit.events[0][1]["stream"] == "admin"


def test_session_with_both_login_types_is_denied(client, audit):
    set_session(
        client,
        authenticated=True,
        staff_authenticated=True,
        voter_id="voter-001",
        staff_id="staff-001",
        role="administrator",
    )

    assert client.post("/results/publish").status_code == 403
    assert client.view_calls == []
    assert audit.events[0][1]["stream"] == "admin"


# Only the session role counts

def test_role_in_json_body_is_ignored(client):
    voter_session(client)

    response = client.post(
        "/results/publish",
        json={"role": "administrator"},
    )

    assert response.status_code == 403
    assert client.view_calls == []


def test_role_in_query_string_is_ignored(client):
    voter_session(client)

    response = client.post("/results/publish?role=administrator")

    assert response.status_code == 403


def test_request_role_cannot_replace_missing_session_role(client):
    set_session(client, authenticated=True, voter_id="voter-001")

    response = client.post(
        "/ballot/entitlement?role=voter",
        json={"role": "voter"},
    )

    assert response.status_code == 403


def test_request_role_cannot_authenticate(client):
    response = client.post(
        "/results/publish?role=administrator&authenticated=true",
        json={"role": "administrator", "staff_authenticated": True},
    )

    assert response.status_code == 401


def test_request_role_does_not_downgrade_session_role(client):
    staff_session(client, "administrator")

    response = client.post(
        "/results/publish?role=voter",
        json={"role": "voter"},
    )

    assert response.status_code == 200


# Audit events

def test_voter_denial_records_one_identity_event(client, audit):
    voter_session(client)

    client.post("/results/publish")

    assert audit.events == [(
        "AUTHZ_DENIED",
        {
            "stream": "identity",
            "actor_type": "voter",
            "actor_id": "voter-001",
            "outcome": "denied",
            "details": {"permission": "results.publish"},
        },
    )]


def test_staff_denial_records_one_admin_event(client, audit):
    staff_session(client, "auditor")

    client.post("/results/publish")

    assert audit.events == [(
        "AUTHZ_DENIED",
        {
            "stream": "admin",
            "actor_type": "staff",
            "actor_id": "staff-001",
            "outcome": "denied",
            "details": {"permission": "results.publish"},
        },
    )]


def test_each_denial_records_its_own_event(client, audit):
    voter_session(client)

    client.post("/results/publish")
    client.post("/results/publish")

    assert [event for event, _ in audit.events] == [
        "AUTHZ_DENIED",
        "AUTHZ_DENIED",
    ]


def test_audit_event_never_contains_request_data(client, audit):
    voter_session(client)

    client.post(
        f"/results/publish?note={QUERY_MARKER}",
        json={
            "role": "administrator",
            "note": BODY_MARKER,
        },
        headers={"X-Note": BODY_MARKER},
    )

    assert len(audit.events) == 1

    recorded = repr(audit.events)

    assert BODY_MARKER not in recorded
    assert QUERY_MARKER not in recorded
    assert "administrator" not in recorded
    assert audit.events[0][1]["details"] == {
        "permission": "results.publish"
    }


def test_audit_is_optional():
    client = build_client(audit=None)
    voter_session(client)

    assert client.post("/results/publish").status_code == 403


# Fail closed

def test_audit_failure_still_denies(caplog):
    client = build_client(FailingAudit())
    voter_session(client)

    with caplog.at_level(logging.ERROR, logger="evp.rbac"):
        response = client.post("/results/publish")

    assert response.status_code == 403
    assert response.get_json() == {"error": "Forbidden"}
    assert client.view_calls == []
    assert "authz_denied_audit_failed" in caplog.text


def test_audit_failure_does_not_affect_allowed_requests():
    client = build_client(FailingAudit())
    staff_session(client, "administrator")

    assert client.post("/results/publish").status_code == 200
