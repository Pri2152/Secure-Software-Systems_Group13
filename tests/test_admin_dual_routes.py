"""
SR-06: Propose / approve / reject endpoint tests.

Two named officers with active SR-02 elevations are
needed for every approval; the proposer can never
approve their own operation.
"""

import pytest
from sqlalchemy import text

from admin.candidates import add_draft_candidate
from records import db
from staff_support import (
    PASSWORD,
    act_as,
    login_as,
    staff_environment,
    staff_request,
)


DIVISION = "Melbourne"
PROPOSE = "candidates.propose_finalise"
APPROVE = "candidates.approve_finalise"


@pytest.fixture
def env():
    with staff_environment() as environment:
        with environment.app.app_context():
            for position, name in enumerate(["Alex Smith", "Sam Jones"], 1):
                add_draft_candidate(
                    db.session, division=DIVISION, name=name,
                    party="Independent", position_in_group=position,
                )
            db.session.commit()

        yield environment


def propose(env, payload=None, op_type="FINALISE_CANDIDATE_LIST"):
    return staff_request(env.client, "post", "/admin/operations", {
        "op_type": op_type,
        "payload": payload if payload is not None else {"division": DIVISION},
    })


def approve(env, operation_id, payload_hash):
    return staff_request(
        env.client, "post", f"/admin/operations/{operation_id}/approve",
        {"payload_hash": payload_hash},
    )


def view(env, operation_id):
    return staff_request(env.client, "get", f"/admin/operations/{operation_id}")


@pytest.fixture
def proposed(env):
    act_as(env, "li", PROPOSE)
    operation = propose(env).get_json()

    return operation


# Test 1: Elevated delegate proposes; payload snapshot and digest stored
def test_delegate_proposes_finalisation(env, proposed):
    assert proposed["status"] == "PROPOSED"
    assert proposed["proposer_id"] == "delegate-li-wei"
    assert proposed["approver_id"] is None
    assert proposed["payload"]["division"] == DIVISION
    assert len(proposed["payload"]["candidate_ids"]) == 2
    assert proposed["payload_hash"].startswith("sha256:")
    assert proposed["expires_at"] - proposed["created_at"] == 24 * 3600


# Test 2: Proposing without elevation -> 403
def test_propose_requires_elevation(env):
    login_as(env, "li")

    response = propose(env)

    assert response.status_code == 403
    assert response.get_json() == {"error": "Elevation required"}


# Test 3: A role without the propose permission -> 403
def test_wrong_role_cannot_propose(env):
    act_as(env, "jane", "roll.propose_bulk")

    assert propose(env).status_code == 403


# Test 4: Invalid proposals -> 400
@pytest.mark.parametrize("body", [
    {"op_type": "DROP_EVERYTHING", "payload": {}},
    {"op_type": "FINALISE_CANDIDATE_LIST"},
    {"op_type": "FINALISE_CANDIDATE_LIST", "payload": {"division": "Nowhere"}},
    {"op_type": "FINALISE_CANDIDATE_LIST",
     "payload": {"division": DIVISION}, "proposer_id": "delegate-noah-brown"},
])
def test_invalid_proposal_is_rejected(env, body):
    act_as(env, "li", PROPOSE)

    response = staff_request(env.client, "post", "/admin/operations", body)

    assert response.status_code == 400


# Test 5: The proposer cannot approve their own operation
def test_self_approval_is_rejected(env, proposed):
    act_as(env, "li", PROPOSE, APPROVE)

    response = approve(env, proposed["id"], proposed["payload_hash"])

    assert response.status_code == 403
    assert view(env, proposed["id"]).get_json()["status"] == "PROPOSED"

    refusal = env.audit.events[-1]

    assert refusal["event_type"] == "OPERATION_REFUSED"
    assert refusal["details"]["reason"] == "self_approval"


# Test 6: A second officer without elevation -> 403
def test_second_officer_needs_elevation(env, proposed):
    login_as(env, "noah")

    response = approve(env, proposed["id"], proposed["payload_hash"])

    assert response.status_code == 403
    assert response.get_json() == {"error": "Elevation required"}


# Test 7: A different, elevated officer approves
def test_second_officer_approves(env, proposed):
    act_as(env, "noah", APPROVE)

    response = approve(env, proposed["id"], proposed["payload_hash"])

    assert response.status_code == 200
    assert response.get_json()["status"] == "EXECUTED"
    assert response.get_json()["approver_id"] == "delegate-noah-brown"
    assert response.get_json()["proposer_id"] == "delegate-li-wei"


# Test 8: An officer whose role lacks the approve permission -> 403
@pytest.mark.parametrize("name, permission", [
    ("mia", "roll.approve_bulk"), ("ada", "staff.manage"),
])
def test_wrong_role_cannot_approve(env, proposed, name, permission):
    act_as(env, name, permission)

    response = approve(env, proposed["id"], proposed["payload_hash"])

    assert response.status_code == 403


# Test 9: Approval must name the reviewed digest exactly
@pytest.mark.parametrize("payload_hash", [
    "sha256:" + "0" * 64, "", "sha3-256:abc",
])
def test_wrong_reviewed_digest_is_refused(env, proposed, payload_hash):
    act_as(env, "noah", APPROVE)

    response = approve(env, proposed["id"], payload_hash)

    assert response.status_code == 409
    assert view(env, proposed["id"]).get_json()["status"] == "PROPOSED"


# Test 10: Payload changed in the database after proposal -> refused
def test_payload_changed_after_proposal_is_refused(env, proposed):
    with env.app.app_context():
        db.session.execute(
            text("UPDATE pending_operations SET payload_json = :p "
                 "WHERE id = :i"),
            {"p": '{"candidate_ids":[1],"division":"Melbourne"}',
             "i": proposed["id"]},
        )
        db.session.commit()

    act_as(env, "noah", APPROVE)

    response = approve(env, proposed["id"], proposed["payload_hash"])

    assert response.status_code == 409
    assert env.audit.events[-1]["details"]["reason"] == "payload_tampered"


# Test 11: Digest changed to match a new payload -> refused as well
def test_payload_and_digest_swapped_together_is_refused(env, proposed):
    act_as(env, "noah", APPROVE)
    reviewed = proposed["payload_hash"]

    with env.app.app_context():
        db.session.execute(
            text("UPDATE pending_operations SET payload_hash = :h "
                 "WHERE id = :i"),
            {"h": "sha256:" + "1" * 64, "i": proposed["id"]},
        )
        db.session.commit()

    assert approve(env, proposed["id"], reviewed).status_code == 409


# Test 12: An approved operation cannot be approved again
def test_operation_cannot_be_approved_twice(env, proposed):
    act_as(env, "noah", APPROVE)
    approve(env, proposed["id"], proposed["payload_hash"])

    response = approve(env, proposed["id"], proposed["payload_hash"])

    assert response.status_code == 409


# Test 13: Rejection is final
def test_rejected_operation_cannot_be_approved(env, proposed):
    act_as(env, "noah", APPROVE)

    response = staff_request(
        env.client, "post", f"/admin/operations/{proposed['id']}/reject",
        {"reason": "Wrong division"},
    )

    assert response.get_json()["status"] == "REJECTED"
    assert approve(env, proposed["id"], proposed["payload_hash"]).status_code == 409


# Test 14: Rejecting needs the approve permission and elevation
def test_reject_requires_elevated_checker(env, proposed):
    login_as(env, "noah")

    response = staff_request(
        env.client, "post", f"/admin/operations/{proposed['id']}/reject", {},
    )

    assert response.status_code == 403


# Test 15: Viewing is limited to officers with a duty for the type
def test_view_requires_related_permission(env, proposed):
    login_as(env, "noah")
    assert view(env, proposed["id"]).status_code == 200

    login_as(env, "jane")
    assert view(env, proposed["id"]).status_code == 403


# Test 16: Unknown operation -> 404; anonymous -> 401; voter -> 401
def test_missing_operation_and_unauthenticated_access(env, proposed):
    login_as(env, "noah")
    assert view(env, 999).status_code == 404

    env.client.delete_cookie("session", domain="localhost")
    assert view(env, proposed["id"]).status_code == 401

    with env.client.session_transaction() as current:
        current["authenticated"] = True
        current["voter_id"] = "voter-001"
        current["role"] = "voter"
        current["last_activity"] = env.clock[0]

    assert propose(env).status_code == 401


# Test 17: Every step is audited with both officers' IDs
def test_steps_are_audited_with_both_officers(env, proposed):
    act_as(env, "noah", APPROVE)
    approve(env, proposed["id"], proposed["payload_hash"])

    events = {
        event["event_type"]: event
        for event in env.audit.events
        if event["event_type"].startswith("OPERATION_")
    }

    assert events["OPERATION_PROPOSED"]["actor_id"] == "delegate-li-wei"
    assert events["OPERATION_APPROVED"]["actor_id"] == "delegate-noah-brown"
    assert events["OPERATION_APPROVED"]["details"]["proposer_id"] == (
        "delegate-li-wei"
    )
    assert events["OPERATION_APPROVED"]["details"]["approver_id"] == (
        "delegate-noah-brown"
    )

    for event in events.values():
        assert event["stream"] == "admin"
        assert PASSWORD not in str(event)


# Test 18: Malformed approval bodies -> 400
@pytest.mark.parametrize("body", [
    {}, {"payload_hash": "x", "approver_id": "delegate-li-wei"}, None,
])
def test_malformed_approval_body(env, proposed, body):
    act_as(env, "noah", APPROVE)

    response = staff_request(
        env.client, "post", f"/admin/operations/{proposed['id']}/approve",
        body,
    )

    assert response.status_code == 400
