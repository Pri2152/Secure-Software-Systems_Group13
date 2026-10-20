"""
SR-17: Auditor-only audit endpoint tests.

Uses a stand-in for Workstream E's SR-04
require_permission with the same behaviour (401 / 403,
roles from the server-side session). When E's real
decorator is available it is tested as well.
"""

from functools import wraps

import pytest
from flask import Flask, jsonify, session
from sqlalchemy import create_engine, text
from sqlalchemy.pool import StaticPool

from audit.checkpoints import CheckpointArchive
from audit.log import AuditLog
from audit.routes import create_audit_blueprint
from crypto_agility import CryptoService, DEFAULT_POLICY, default_registry
from crypto_agility.keys import KeyStore


# Same audit permissions as docs/RBAC_MATRIX.md (Workstream E)
ROLE_PERMISSIONS = {
    "auditor": {"audit.read", "audit.verify"},
    "administrator": {"staff.manage", "results.publish", "config.read"},
    "officer": {"roll.propose_bulk", "roll.approve_bulk"},
    "voter": {"records.read_own"},
}


def stand_in_require_permission(permission):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not (session.get("staff_authenticated")
                    or session.get("authenticated")):
                return jsonify({"error": "Authentication required"}), 401

            if permission not in ROLE_PERMISSIONS.get(
                session.get("role"), set()
            ):
                return jsonify({"error": "Forbidden"}), 403

            return view(*args, **kwargs)

        return wrapper

    return decorator


@pytest.fixture
def audit_log(tmp_path):
    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    log = AuditLog(
        engine,
        crypto=CryptoService(
            default_registry(), DEFAULT_POLICY, KeyStore.ephemeral()
        ),
        archive=CheckpointArchive(tmp_path / "checkpoints.jsonl"),
    )
    log.create_schema()

    log.record_event(
        "AUTH_FAILURE", stream="identity", actor_type="anonymous",
        actor_id=None, outcome="failure", source_ip="203.0.113.10",
        details={"password": "CorrectPassword123!", "reason": "bad"},
    )
    log.record_event(
        "AUTH_SUCCESS", stream="identity", actor_type="voter",
        actor_id="voter-001", outcome="success",
    )

    return log


def make_client(audit_log, require_permission=stand_in_require_permission):
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="test-only-secret")
    app.register_blueprint(
        create_audit_blueprint(require_permission, audit_log)
    )

    return app.test_client()


def login_staff(client, role, staff_id="auditor-grace-hopper"):
    with client.session_transaction() as staff_session:
        staff_session["staff_authenticated"] = True
        staff_session["staff_id"] = staff_id
        staff_session["role"] = role


@pytest.fixture
def auditor(audit_log):
    client = make_client(audit_log)
    login_staff(client, "auditor")

    return client


# Test 1: Auditor can read events
def test_auditor_reads_events(auditor):
    response = auditor.get("/audit/events?stream=identity")

    assert response.status_code == 200
    assert [e["event_type"] for e in response.get_json()["events"]] == [
        "AUTH_SUCCESS", "AUTH_FAILURE"
    ]


# Test 2: Limit is applied
def test_events_limit(auditor):
    response = auditor.get("/audit/events?stream=identity&limit=1")

    assert len(response.get_json()["events"]) == 1


# Test 3: Responses never include secrets or chain internals
def test_response_has_no_secrets(auditor):
    body = auditor.get("/audit/events?stream=identity").get_data(
        as_text=True
    )

    assert "CorrectPassword123!" not in body
    assert "entry_hash" not in body
    assert "prev_hash" not in body
    assert '"sig"' not in body


# Test 4: Auditor can verify the chain and checkpoints
def test_auditor_verifies_log(auditor, audit_log):
    audit_log.checkpoint("identity")

    response = auditor.get("/audit/verify?stream=identity")

    assert response.status_code == 200
    assert response.get_json() == {
        "stream": "identity", "ok": True, "checked": 2,
        "broken_at_seq": None, "reason": None,
        "checkpoints": {"ok": True, "checked": 1,
                        "broken_at_line": None, "reason": None},
    }


# Test 5: Tampering shows up through the endpoint
def test_verify_reports_tampering(auditor, audit_log):
    with audit_log.engine.begin() as connection:
        connection.execute(text("DROP TRIGGER audit_log_no_update"))
        connection.execute(text(
            "UPDATE audit_log SET actor_id = 'voter-666' WHERE seq = 2"
        ))

    result = auditor.get("/audit/verify?stream=identity").get_json()

    assert result["ok"] is False
    assert result["broken_at_seq"] == 2
    assert result["reason"] == "invalid_mac"


# Test 6: Non-auditor staff roles get 403
@pytest.mark.parametrize("role", ["administrator", "officer"])
@pytest.mark.parametrize("path", [
    "/audit/events?stream=identity", "/audit/verify?stream=identity",
])
def test_non_auditor_is_forbidden(audit_log, role, path):
    client = make_client(audit_log)
    login_staff(client, role, staff_id=f"{role}-jane-citizen")

    response = client.get(path)

    assert response.status_code == 403
    assert "events" not in response.get_json()


# Test 7: A voter session gets 403
def test_voter_is_forbidden(audit_log):
    client = make_client(audit_log)

    with client.session_transaction() as voter_session:
        voter_session["authenticated"] = True
        voter_session["voter_id"] = "voter-001"
        voter_session["role"] = "voter"

    assert client.get("/audit/events?stream=identity").status_code == 403


# Test 8: Anonymous requests get 401
@pytest.mark.parametrize("path", [
    "/audit/events?stream=identity", "/audit/verify?stream=identity",
])
def test_anonymous_is_unauthorised(audit_log, path):
    assert make_client(audit_log).get(path).status_code == 401


# Test 9: Invalid queries get a generic 400
@pytest.mark.parametrize("path", [
    "/audit/events",
    "/audit/events?stream=voting",
    "/audit/events?stream=identity&limit=0",
    "/audit/events?stream=identity&limit=201",
    "/audit/events?stream=identity&limit=abc",
    "/audit/events?stream=identity&limit=-1",
    "/audit/events?stream=identity&actor_id=voter-001",
    "/audit/verify",
    "/audit/verify?stream=identity&limit=5",
])
def test_invalid_query_is_rejected(auditor, path):
    response = auditor.get(path)

    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid request"}


# Test 10: Every auditor read and verification is itself audited
def test_auditor_access_is_audited(auditor, audit_log):
    auditor.get("/audit/events?stream=identity")
    auditor.get("/audit/verify?stream=ballot")

    events = audit_log.list_events("admin")

    assert [(e["event_type"], e["actor_id"], e["details"]) for e in events] == [
        ("AUDIT_LOG_VERIFIED", "auditor-grace-hopper", {"stream": "ballot"}),
        ("AUDIT_LOG_READ", "auditor-grace-hopper", {"stream": "identity"}),
    ]


# Test 11: If access cannot be audited, nothing is returned (fail closed)
def test_unlogged_access_is_refused(audit_log):
    def failing_audit(*args, **kwargs):
        raise RuntimeError("audit database down")

    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="test-only-secret")
    app.register_blueprint(create_audit_blueprint(
        stand_in_require_permission, audit_log, audit=failing_audit
    ))
    client = app.test_client()
    login_staff(client, "auditor")

    response = client.get("/audit/events?stream=identity")

    assert response.status_code == 503
    assert response.get_json() == {"error": "Audit service unavailable"}


# Test 12: Only GET is allowed (the log cannot be written over HTTP)
@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_write_methods_not_allowed(auditor, method):
    response = getattr(auditor, method)("/audit/events?stream=identity")

    assert response.status_code == 405


# Test 13: Blueprint needs a permission decorator
def test_blueprint_requires_decorator(audit_log):
    with pytest.raises(TypeError):
        create_audit_blueprint(None, audit_log)


# Test 14: Works with Workstream E's real SR-04 decorator when available
def test_with_workstream_e_require_permission(audit_log):
    rbac = pytest.importorskip("platform_security.rbac")

    client = make_client(audit_log, rbac.require_permission)
    assert client.get("/audit/events?stream=identity").status_code == 401

    login_staff(client, "administrator", staff_id="admin-ada-lovelace")
    assert client.get("/audit/events?stream=identity").status_code == 403

    login_staff(client, "auditor")
    assert client.get("/audit/events?stream=identity").status_code == 200
