"""
SR-06: Atomic execution, expiry, replay protection and the
database trigger backstop.

Uses synthetic candidates and roll records; the 24-hour
proposal lifetime is tested with the injected clock.
"""

from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DatabaseError

from admin import final_candidate_list
from admin.candidates import CandidateListLocked, add_draft_candidate
from admin.dual_authorisation import OperationRefused
from admin.models import Candidate, PendingOperation
from admin.operations import PROPOSAL_LIFETIME_SECONDS
from records import EnrolmentRecord, db
from staff_support import act_as, staff_environment, staff_request


DIVISION = "Melbourne"
REPO_ROOT = Path(__file__).resolve().parent.parent
MYSQL_TRIGGERS = REPO_ROOT / "deploy" / "db" / "dual_authorisation_triggers.sql"

FINALISE = ("candidates.propose_finalise", "candidates.approve_finalise")
EXCLUDE = ("candidates.propose_exclusion", "candidates.approve_exclusion")
BULK = ("roll.propose_bulk", "roll.approve_bulk")


@pytest.fixture
def env(pii_provider):
    with staff_environment() as environment:
        with environment.app.app_context():
            for position, name in enumerate(
                ["Alex Smith", "Sam Jones", "Kim Lee"], 1
            ):
                add_draft_candidate(
                    db.session, division=DIVISION, name=name,
                    party="Independent", position_in_group=position,
                )

            db.session.add_all([
                EnrolmentRecord(owner_voter_id=f"voter-{i:03d}",
                                enrolment_status="enrolled",
                                contact_email=f"voter{i}@example.test")
                for i in range(1, 4)
            ])
            db.session.commit()

        yield environment


def propose(env, op_type, payload):
    return staff_request(env.client, "post", "/admin/operations",
                         {"op_type": op_type, "payload": payload})


def approve(env, operation):
    return staff_request(
        env.client, "post", f"/admin/operations/{operation['id']}/approve",
        {"payload_hash": operation["payload_hash"]},
    )


def proposed_finalisation(env):
    act_as(env, "li", FINALISE[0])

    return propose(env, "FINALISE_CANDIDATE_LIST",
                   {"division": DIVISION}).get_json()


def finalise_division(env):
    operation = proposed_finalisation(env)
    act_as(env, "noah", FINALISE[1])
    assert approve(env, operation).status_code == 200

    return operation


def candidate_statuses(env):
    with env.app.app_context():
        return [c.status for c in db.session.query(Candidate)
                .order_by(Candidate.position_in_group)]


def roll_statuses(env):
    with env.app.app_context():
        return [r.enrolment_status for r in db.session.query(EnrolmentRecord)
                .order_by(EnrolmentRecord.id)]


def operation_status(env, operation_id):
    with env.app.app_context():
        return db.session.get(PendingOperation, operation_id).status


def run_sql(env, statement, **params):
    with env.app.app_context():
        db.session.execute(text(statement), params)
        db.session.commit()


# Test 1: Happy path: finalisation executes exactly once
def test_finalisation_executes_once(env):
    operation = proposed_finalisation(env)
    act_as(env, "noah", FINALISE[1])

    response = approve(env, operation)

    assert response.status_code == 200
    assert response.get_json()["status"] == "EXECUTED"
    assert response.get_json()["executed_at"] is not None
    assert candidate_statuses(env) == ["FINAL"] * 3
    assert env.audit.types().count("OPERATION_EXECUTED") == 1


# Test 2: Replay of an executed approval is refused
def test_replayed_approval_is_refused(env):
    operation = finalise_division(env)

    response = approve(env, operation)

    assert response.status_code == 409
    assert env.audit.types().count("OPERATION_EXECUTED") == 1


# Test 3: Workstream C gets the final list after execution only
def test_final_list_available_after_execution(env):
    with env.app.app_context():
        with pytest.raises(LookupError):
            final_candidate_list(DIVISION)

    finalise_division(env)

    with env.app.app_context():
        final = final_candidate_list(DIVISION)

    assert [c.name for c in final] == ["Alex Smith", "Sam Jones", "Kim Lee"]


# Test 4: The final list is read-only (no new candidates, no edits)
def test_final_list_is_read_only(env):
    finalise_division(env)

    with env.app.app_context():
        with pytest.raises(CandidateListLocked):
            add_draft_candidate(db.session, division=DIVISION,
                                name="Late Entry", party="Independent",
                                position_in_group=9)
        db.session.rollback()

        candidate = db.session.query(Candidate).first()
        candidate.name = "Changed Name"

        with pytest.raises(CandidateListLocked):
            db.session.commit()


# Test 5: A candidate added after the proposal stops execution
def test_list_changed_after_proposal_is_refused(env):
    operation = proposed_finalisation(env)

    with env.app.app_context():
        add_draft_candidate(db.session, division=DIVISION, name="Late Entry",
                            party="Independent", position_in_group=4)
        db.session.commit()

    act_as(env, "noah", FINALISE[1])

    assert approve(env, operation).status_code == 409
    assert candidate_statuses(env) == ["DRAFT"] * 4
    assert operation_status(env, operation["id"]) == "PROPOSED"
    assert "OPERATION_EXECUTION_FAILED" in env.audit.types()


# Test 6: Court-ordered exclusion end to end
def test_court_ordered_exclusion(env):
    finalise_division(env)

    with env.app.app_context():
        target = db.session.query(Candidate).filter_by(name="Sam Jones").one()
        target_id = target.id

    act_as(env, "li", EXCLUDE[0])
    operation = propose(env, "EXCLUDE_CANDIDATE", {
        "candidate_id": target_id, "court_order_ref": "CDR 12/2026",
    }).get_json()

    assert operation["court_order_ref"] == "CDR 12/2026"

    act_as(env, "noah", EXCLUDE[1])

    assert approve(env, operation).status_code == 200
    assert candidate_statuses(env) == ["FINAL", "EXCLUDED", "FINAL"]

    with env.app.app_context():
        names = [c.name for c in final_candidate_list(DIVISION)]

    assert names == ["Alex Smith", "Kim Lee"]


# Test 7: Bulk roll update changes A's records through two officers
def test_bulk_roll_update(env):
    act_as(env, "jane", BULK[0])
    operation = propose(env, "BULK_ROLL_UPDATE", {"changes": [
        {"record_id": 1, "enrolment_status": "removed"},
        {"record_id": 3, "enrolment_status": "suspended"},
    ]}).get_json()

    act_as(env, "mia", BULK[1])

    assert approve(env, operation).status_code == 200
    assert roll_statuses(env) == ["removed", "enrolled", "suspended"]


# Test 8: A bulk update is all or nothing
def test_bulk_roll_update_is_atomic(env):
    act_as(env, "jane", BULK[0])
    operation = propose(env, "BULK_ROLL_UPDATE", {"changes": [
        {"record_id": 1, "enrolment_status": "removed"},
        {"record_id": 2, "enrolment_status": "removed"},
    ]}).get_json()

    run_sql(env, "DELETE FROM enrolment_records WHERE id = 2")

    act_as(env, "mia", BULK[1])

    assert approve(env, operation).status_code == 409
    assert roll_statuses(env) == ["enrolled", "enrolled"]
    assert operation_status(env, operation["id"]) == "PROPOSED"


# Test 9: An expired proposal cannot be approved
def test_expired_proposal_is_refused(env):
    operation = proposed_finalisation(env)

    env.clock[0] += PROPOSAL_LIFETIME_SECONDS
    act_as(env, "noah", FINALISE[1])

    assert approve(env, operation).status_code == 409
    assert operation_status(env, operation["id"]) == "EXPIRED"
    assert candidate_statuses(env) == ["DRAFT"] * 3
    assert "OPERATION_EXPIRED" in env.audit.types()


# Test 10: A proposal is still valid just before 24 hours
def test_proposal_valid_until_expiry(env):
    operation = proposed_finalisation(env)

    env.clock[0] += PROPOSAL_LIFETIME_SECONDS - 60
    act_as(env, "noah", FINALISE[1])

    assert approve(env, operation).status_code == 200


# Test 11: Expired proposals cannot be rejected either, and show as expired
def test_expired_proposal_cannot_be_rejected(env):
    operation = proposed_finalisation(env)
    env.clock[0] += PROPOSAL_LIFETIME_SECONDS
    act_as(env, "noah", FINALISE[1])

    response = staff_request(
        env.client, "post", f"/admin/operations/{operation['id']}/reject", {},
    )

    assert response.status_code == 409

    view = staff_request(env.client, "get",
                         f"/admin/operations/{operation['id']}").get_json()

    assert view["status"] == "EXPIRED"


# Test 12: A stale approval loses the race (conditional claim)
def test_stale_operation_cannot_be_claimed(env):
    operation = proposed_finalisation(env)

    with env.app.app_context():
        service = env.services.dual
        stale = service.get(operation["id"])

        # Another officer's decision lands after this object was loaded
        db.session.execute(text(
            "UPDATE pending_operations SET status = 'REJECTED' WHERE id = :i"
        ), {"i": operation["id"]})

        with pytest.raises(OperationRefused, match="not_pending"):
            service.approve(stale, "delegate-noah-brown",
                            operation["payload_hash"])

    assert candidate_statuses(env) == ["DRAFT"] * 3


# Test 13: Trigger: EXECUTED with no approver is refused by the database
def test_trigger_refuses_execution_without_approver(env):
    operation = proposed_finalisation(env)

    with pytest.raises(DatabaseError, match="two distinct officers"):
        run_sql(env, "UPDATE pending_operations SET status = 'EXECUTED' "
                     "WHERE id = :i", i=operation["id"])

    assert operation_status(env, operation["id"]) == "PROPOSED"


# Test 14: Trigger: EXECUTED approved by the proposer is refused
def test_trigger_refuses_single_officer_execution(env):
    operation = proposed_finalisation(env)

    with pytest.raises(DatabaseError, match="two distinct officers"):
        run_sql(env, "UPDATE pending_operations SET status = 'EXECUTED', "
                     "approver_id = proposer_id WHERE id = :i",
                i=operation["id"])


# Test 15: Trigger: inserting a one-officer EXECUTED row is refused
def test_trigger_refuses_forged_executed_insert(env):
    with pytest.raises(DatabaseError, match="two distinct officers"):
        run_sql(
            env,
            "INSERT INTO pending_operations (op_type, payload_json, "
            "payload_hash, proposer_id, approver_id, status, created_at, "
            "expires_at) VALUES ('BULK_ROLL_UPDATE', '{}', 'sha256:00', "
            "'officer-jane-citizen', 'officer-jane-citizen', 'EXECUTED', 0, 1)",
        )


# Test 16: Trigger: executed operations cannot be reset or deleted
def test_trigger_keeps_executed_operations_final(env):
    operation = finalise_division(env)

    with pytest.raises(DatabaseError, match="executed operations are final"):
        run_sql(env, "UPDATE pending_operations SET status = 'PROPOSED' "
                     "WHERE id = :i", i=operation["id"])

    with pytest.raises(DatabaseError, match="executed operations are final"):
        run_sql(env, "DELETE FROM pending_operations WHERE id = :i",
                i=operation["id"])


# Test 17: Trigger allows a genuine two-officer record
def test_trigger_allows_two_distinct_officers(env):
    operation = proposed_finalisation(env)

    run_sql(env, "UPDATE pending_operations SET status = 'EXECUTED', "
                 "approver_id = 'delegate-noah-brown' WHERE id = :i",
            i=operation["id"])

    assert operation_status(env, operation["id"]) == "EXECUTED"


# Test 18: MySQL backstop script defines the same rules
def test_mysql_dual_authorisation_triggers():
    script = MYSQL_TRIGGERS.read_text(encoding="utf-8")

    assert "BEFORE INSERT ON pending_operations" in script
    assert "BEFORE UPDATE ON pending_operations" in script
    assert "BEFORE DELETE ON pending_operations" in script
    assert script.count("NEW.approver_id = NEW.proposer_id") == 2
    assert script.count("SIGNAL SQLSTATE '45000'") == 4
    assert "USE identity_db;" in script


# Test 19: Execution is audited with both officers and the digest
def test_execution_audit_has_both_officers(env):
    operation = finalise_division(env)

    executed = [e for e in env.audit.events
                if e["event_type"] == "OPERATION_EXECUTED"][0]

    assert executed["stream"] == "admin"
    assert executed["actor_id"] == "delegate-noah-brown"
    assert executed["details"]["proposer_id"] == "delegate-li-wei"
    assert executed["details"]["approver_id"] == "delegate-noah-brown"
    assert executed["details"]["payload_hash"] == operation["payload_hash"]
