
"""
SR-04 tests for the deny-by-default RBAC skeleton.

Uses a small Flask test app so Workstream A's
application is not changed.
"""

import re
from pathlib import Path

import pytest
from flask import Flask, jsonify

from platform_security.rbac import (
    ROLE_PERMISSIONS,
    has_permission,
    require_permission,
)


MATRIX_PATH = (
    Path(__file__).resolve().parent.parent
    / "docs" / "RBAC_MATRIX.md"
)


@pytest.fixture
def audit_events():
    return []


@pytest.fixture
def client(audit_events):
    test_app = Flask(__name__)
    test_app.config.update(
        SECRET_KEY="test-only-key",
        TESTING=True,
    )

    def record(event, **fields):
        audit_events.append((event, fields))

    @test_app.post("/results/publish")
    @require_permission("results.publish", audit=record)
    def publish_results():
        return jsonify(message="Published"), 200

    @test_app.post("/ballot/entitlement")
    @require_permission("ballot.request_entitlement")
    def request_entitlement():
        return jsonify(message="Entitled"), 200

    return test_app.test_client()


def set_session(client, **values):
    with client.session_transaction() as test_session:
        test_session.clear()
        test_session.update(values)


# Permission matrix

def test_voter_can_request_ballot_entitlement():
    assert has_permission("voter", "ballot.request_entitlement")


def test_voter_cannot_publish_results():
    assert not has_permission("voter", "results.publish")


def test_administrator_can_publish_results():
    assert has_permission("administrator", "results.publish")


@pytest.mark.parametrize("role", [
    None,
    "",
    "superuser",
    "Voter",
    " voter",
    123,
    ["voter"],
])
def test_unknown_or_missing_role_is_denied(role):
    assert not has_permission(role, "ballot.request_entitlement")


@pytest.mark.parametrize("permission", [
    None,
    "",
    "results.publish_all",
    "*",
    ["results.publish"],
])
def test_unknown_permission_is_denied(permission):
    assert not has_permission("administrator", permission)


def test_matrix_cannot_be_changed_at_runtime():
    with pytest.raises(TypeError):
        ROLE_PERMISSIONS["voter"] = frozenset({"results.publish"})

    assert isinstance(ROLE_PERMISSIONS["voter"], frozenset)


# Decorator

def test_no_session_returns_401(client, audit_events):
    response = client.post("/results/publish")

    assert response.status_code == 401
    assert audit_events == []


def test_role_without_authentication_returns_401(client):
    set_session(client, role="administrator")

    response = client.post("/results/publish")

    assert response.status_code == 401


def test_wrong_role_returns_403_and_is_audited(client, audit_events):
    set_session(
        client,
        authenticated=True,
        voter_id="voter-001",
        role="voter",
    )

    response = client.post("/results/publish")

    assert response.status_code == 403
    assert response.get_json() == {"error": "Forbidden"}

    assert audit_events == [(
        "AUTHZ_DENIED",
        {
            "stream": "identity",
            "actor_type": "voter",
            "actor_id": "voter-001",
            "outcome": "denied",
            "details": {"permission": "results.publish"},
        },
    )]


def test_staff_denial_goes_to_admin_stream(client, audit_events):
    set_session(
        client,
        staff_authenticated=True,
        staff_id="staff-007",
        role="auditor",
    )

    response = client.post("/results/publish")

    assert response.status_code == 403
    assert audit_events[0][1]["stream"] == "admin"
    assert audit_events[0][1]["actor_id"] == "staff-007"


def test_authenticated_session_without_role_returns_403(client):
    set_session(client, authenticated=True, voter_id="voter-001")

    response = client.post("/ballot/entitlement")

    assert response.status_code == 403


def test_correct_role_returns_200(client, audit_events):
    set_session(
        client,
        staff_authenticated=True,
        staff_id="staff-001",
        role="administrator",
    )

    response = client.post("/results/publish")

    assert response.status_code == 200
    assert audit_events == []


def test_role_in_request_is_ignored(client):
    set_session(
        client,
        authenticated=True,
        voter_id="voter-001",
        role="voter",
    )

    response = client.post(
        "/results/publish?role=administrator",
        json={"role": "administrator"},
        headers={"X-Role": "administrator"},
    )

    assert response.status_code == 403


def test_audit_failure_still_denies():
    test_app = Flask(__name__)
    test_app.config["SECRET_KEY"] = "test-only-key"

    def broken_audit(event, **fields):
        raise RuntimeError("audit store unavailable")

    @test_app.post("/results/publish")
    @require_permission("results.publish", audit=broken_audit)
    def publish_results():
        return "Published", 200

    client = test_app.test_client()
    set_session(client, authenticated=True, role="voter")

    assert client.post("/results/publish").status_code == 403


def test_wrapper_records_required_permission(client):
    view = client.application.view_functions["publish_results"]

    assert view.required_permission == "results.publish"
    assert view.__name__ == "publish_results"


@pytest.mark.parametrize("permission", [None, "", 5])
def test_invalid_permission_name_is_rejected(permission):
    with pytest.raises(ValueError):
        require_permission(permission)


def test_non_callable_audit_is_rejected():
    with pytest.raises(TypeError):
        require_permission("audit.read", audit="not-callable")


# Documentation

def test_matrix_document_matches_code():
    text = MATRIX_PATH.read_text(encoding="utf-8")

    assert (
        "Draft: staff role permissions are awaiting "
        "Workstream B review (SR-06)." in text
    )

    rows = [
        line for line in text.splitlines()
        if line.startswith("|")
    ]
    header = [cell.strip() for cell in rows[0].strip("|").split("|")]
    roles = header[1:]

    assert set(roles) == set(ROLE_PERMISSIONS)

    documented = {role: set() for role in roles}

    for line in rows[2:]:
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        permission = re.fullmatch(r"`([^`]+)`", cells[0]).group(1)

        for role, cell in zip(roles, cells[1:]):
            if cell == "✓":
                documented[role].add(permission)

    assert documented == {
        role: set(permissions)
        for role, permissions in ROLE_PERMISSIONS.items()
    }
