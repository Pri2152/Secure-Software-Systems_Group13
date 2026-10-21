"""
SR-06: Candidate, pending operation and payload digest tests.

Uses an isolated in-memory SQLite database and
synthetic candidates and roll records.
"""

import pytest
from flask import Flask

from admin import create_staff_account
from admin.candidates import (
    CandidateListLocked,
    CandidateListNotFinal,
    FinalCandidate,
    add_draft_candidate,
    final_candidate_list,
)
from admin.models import Candidate, PendingOperation
from admin.operations import (
    MAX_BULK_ROWS,
    OP_BULK_ROLL,
    OP_EXCLUDE,
    OP_FINALISE,
    OPERATION_TYPES,
    PROPOSAL_LIFETIME_SECONDS,
    InvalidOperation,
    canonical_payload,
    payload_digest,
    payload_matches,
    prepare_payload,
)
from crypto_agility import CryptoService, DEFAULT_POLICY, default_registry
from crypto_agility.algorithms import HASH
from crypto_agility.keys import KeyStore
from records import EnrolmentRecord, db
from staff_support import make_certificate


DIVISION = "Melbourne"


@pytest.fixture
def database():
    app = Flask(__name__)
    app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )
    db.init_app(app)

    with app.app_context():
        db.create_all()
        yield db.session
        db.session.remove()
        db.drop_all()


@pytest.fixture
def crypto():
    return CryptoService(
        default_registry(), DEFAULT_POLICY, KeyStore.ephemeral()
    )


def add_candidates(db_session, division=DIVISION, count=3):
    candidates = [
        add_draft_candidate(
            db_session, division=division, name=f"Candidate {chr(65 + i)}",
            party="Independent", position_in_group=i + 1,
        )
        for i in range(count)
    ]
    db_session.commit()

    return candidates


def finalise(db_session, division=DIVISION):
    for candidate in db_session.query(Candidate).filter_by(division=division):
        candidate.status = "FINAL"

    db_session.commit()


def add_enrolments(db_session, count=3):
    records = [
        EnrolmentRecord(owner_voter_id=f"voter-{i:03d}",
                        enrolment_status="enrolled",
                        contact_email=f"voter{i}@example.test")
        for i in range(count)
    ]
    db_session.add_all(records)
    db_session.commit()

    return records


# Test 1: Each operation type has its own propose and approve permission
def test_operation_types_have_separate_permissions():
    assert set(OPERATION_TYPES) == {OP_FINALISE, OP_EXCLUDE, OP_BULK_ROLL}

    for op_type in OPERATION_TYPES.values():
        assert op_type.propose_permission != op_type.approve_permission


# Test 2: Draft candidates can be added
def test_draft_candidates_are_added(database):
    candidates = add_candidates(database)

    assert [c.status for c in candidates] == ["DRAFT"] * 3


# Test 3: Invalid candidate details are rejected
@pytest.mark.parametrize("overrides", [
    {"division": ""}, {"division": "<script>"}, {"name": "x"},
    {"party": None}, {"position_in_group": 0},
    {"position_in_group": True}, {"position_in_group": "1"},
])
def test_invalid_candidate_details_rejected(database, overrides):
    values = {"division": DIVISION, "name": "Alex Smith",
              "party": "Independent", "position_in_group": 1}
    values.update(overrides)

    with pytest.raises(ValueError):
        add_draft_candidate(database, **values)


# Test 4: No candidate can be added to a final list
def test_final_list_refuses_new_candidates(database):
    add_candidates(database)
    finalise(database)

    with pytest.raises(CandidateListLocked):
        add_draft_candidate(database, division=DIVISION, name="Late Entry",
                            party="Independent", position_in_group=9)


# Test 5: A final candidate's details cannot be edited
@pytest.mark.parametrize("column, value", [
    ("name", "Someone Else"), ("party", "Other Party"),
    ("position_in_group", 7), ("division", "Sydney"),
])
def test_final_candidate_cannot_be_edited(database, column, value):
    candidate = add_candidates(database)[0]
    finalise(database)

    setattr(candidate, column, value)

    with pytest.raises(CandidateListLocked):
        database.flush()


# Test 6: A final list cannot go back to draft
def test_final_candidate_cannot_return_to_draft(database):
    candidate = add_candidates(database)[0]
    finalise(database)

    candidate.status = "DRAFT"

    with pytest.raises(CandidateListLocked):
        database.flush()


# Test 7: A final candidate cannot be deleted
def test_final_candidate_cannot_be_deleted(database):
    candidate = add_candidates(database)[0]
    finalise(database)

    database.delete(candidate)

    with pytest.raises(CandidateListLocked):
        database.flush()


# Test 8: The only allowed change is FINAL -> EXCLUDED
def test_final_candidate_can_be_excluded(database):
    candidate = add_candidates(database)[0]
    finalise(database)

    candidate.status = "EXCLUDED"
    database.commit()

    assert candidate.status == "EXCLUDED"


# Test 9: Excluded candidates stay excluded
def test_excluded_candidate_cannot_be_restored(database):
    candidate = add_candidates(database)[0]
    finalise(database)
    candidate.status = "EXCLUDED"
    database.commit()

    candidate.status = "FINAL"

    with pytest.raises(CandidateListLocked):
        database.flush()


# Test 10: Workstream C gets an immutable, ordered final list
def test_final_candidate_list_for_ballot(database):
    candidates = add_candidates(database)
    finalise(database)
    candidates[1].status = "EXCLUDED"
    database.commit()

    final = final_candidate_list(DIVISION)

    assert isinstance(final, tuple)
    assert all(isinstance(c, FinalCandidate) for c in final)
    assert [c.position_in_group for c in final] == [1, 3]

    with pytest.raises(AttributeError):
        final[0].name = "Changed"


# Test 11: A draft (non-final) list is not given to the ballot
def test_draft_list_is_not_final(database):
    add_candidates(database)

    with pytest.raises(CandidateListNotFinal):
        final_candidate_list(DIVISION)


# Test 12: Invalid or unknown divisions are refused
@pytest.mark.parametrize("division", ["Nowhere", "", None, "x' OR 1=1"])
def test_unknown_division_is_not_final(database, division):
    with pytest.raises(CandidateListNotFinal):
        final_candidate_list(division)


# Test 13: Canonical payload ignores key order; digest is self-describing
def test_payload_digest_is_canonical(crypto):
    first = canonical_payload({"b": 2, "a": [1, 2]})
    second = canonical_payload({"a": [1, 2], "b": 2})

    assert first == second
    assert payload_digest(crypto, first).startswith("sha256:")


# Test 14: A changed payload no longer matches its digest
def test_changed_payload_fails_digest(crypto):
    stored = canonical_payload({"division": DIVISION, "candidate_ids": [1, 2]})
    digest = payload_digest(crypto, stored)

    changed = canonical_payload({"division": DIVISION, "candidate_ids": [1]})

    assert payload_matches(crypto, stored, digest) is True
    assert payload_matches(crypto, changed, digest) is False
    assert payload_matches(crypto, None, digest) is False


# Test 15: Digests made before a hash algorithm change still verify (SR-14)
def test_digest_survives_hash_algorithm_change(crypto):
    stored = canonical_payload({"division": DIVISION})
    old_digest = payload_digest(crypto, stored)

    upgraded = crypto.with_policy(
        DEFAULT_POLICY.with_default(HASH, "sha3-256")
    )

    assert payload_digest(upgraded, stored).startswith("sha3-256:")
    assert payload_matches(upgraded, stored, old_digest) is True


# Test 16: Finalisation payload snapshots the exact draft candidates
def test_finalise_payload_snapshots_candidates(database):
    candidates = add_candidates(database)

    payload = prepare_payload(database, OP_FINALISE, {"division": DIVISION})

    assert payload == {
        "division": DIVISION,
        "candidate_ids": sorted(c.id for c in candidates),
    }


# Test 17: Finalisation is refused for empty or already-final divisions
def test_finalise_payload_rejects_bad_divisions(database):
    with pytest.raises(InvalidOperation):
        prepare_payload(database, OP_FINALISE, {"division": DIVISION})

    add_candidates(database)
    finalise(database)

    with pytest.raises(InvalidOperation):
        prepare_payload(database, OP_FINALISE, {"division": DIVISION})


# Test 18: Exclusion needs a finalised candidate and a court order
def test_exclusion_payload(database):
    candidate = add_candidates(database)[0]

    with pytest.raises(InvalidOperation):
        prepare_payload(database, OP_EXCLUDE, {
            "candidate_id": candidate.id, "court_order_ref": "CDR 12/2026",
        })

    finalise(database)

    assert prepare_payload(database, OP_EXCLUDE, {
        "candidate_id": candidate.id, "court_order_ref": "CDR 12/2026",
    }) == {
        "candidate_id": candidate.id, "division": DIVISION,
        "court_order_ref": "CDR 12/2026",
    }


# Test 19: Missing or invalid court order reference is refused
@pytest.mark.parametrize("payload", [
    {"candidate_id": 1},
    {"candidate_id": 1, "court_order_ref": ""},
    {"candidate_id": 1, "court_order_ref": "<script>"},
    {"candidate_id": 1, "court_order_ref": "x" * 80},
    {"candidate_id": "1", "court_order_ref": "CDR 12/2026"},
])
def test_exclusion_without_valid_court_order(database, payload):
    add_candidates(database)
    finalise(database)

    with pytest.raises(InvalidOperation):
        prepare_payload(database, OP_EXCLUDE, payload)


# Test 20: Bulk roll payload is validated row by row and sorted
def test_bulk_roll_payload(database):
    records = add_enrolments(database)

    payload = prepare_payload(database, OP_BULK_ROLL, {"changes": [
        {"record_id": records[2].id, "enrolment_status": "removed"},
        {"record_id": records[0].id, "enrolment_status": "suspended"},
    ]})

    assert [row["record_id"] for row in payload["changes"]] == [
        records[0].id, records[2].id
    ]


# Test 21: Any bad bulk row rejects the whole batch
@pytest.mark.parametrize("changes", [
    [],
    "all",
    [{"record_id": 1}],
    [{"record_id": 1, "enrolment_status": "deleted"}],
    [{"record_id": 0, "enrolment_status": "removed"}],
    [{"record_id": 999, "enrolment_status": "removed"}],
    [{"record_id": 1, "enrolment_status": "removed"},
     {"record_id": 1, "enrolment_status": "enrolled"}],
    [{"record_id": 1, "enrolment_status": "removed", "contact_email": "x"}],
])
def test_bad_bulk_rows_are_rejected(database, changes):
    add_enrolments(database)

    with pytest.raises(InvalidOperation):
        prepare_payload(database, OP_BULK_ROLL, {"changes": changes})


# Test 22: Batches larger than the limit are rejected
def test_bulk_roll_size_limit(database):
    add_enrolments(database)
    changes = [{"record_id": 1, "enrolment_status": "removed"}] * (
        MAX_BULK_ROWS + 1
    )

    with pytest.raises(InvalidOperation):
        prepare_payload(database, OP_BULK_ROLL, {"changes": changes})


# Test 23: Unknown operation types and extra payload fields are refused
@pytest.mark.parametrize("op_type, payload", [
    ("DELETE_ROLL", {}),
    (OP_FINALISE, {"division": DIVISION, "candidate_ids": [1]}),
    (OP_FINALISE, None),
])
def test_unknown_operation_or_fields_refused(database, op_type, payload):
    add_candidates(database)

    with pytest.raises(InvalidOperation):
        prepare_payload(database, op_type, payload)


# Test 24: Pending operation stores proposer, digest, expiry and court order
def test_pending_operation_record(database, crypto):
    proposer = create_staff_account(
        database, staff_id="delegate-li-wei", full_name="Li Wei",
        role="delegate", password="Staff-Password-2026!",
        cert_fingerprint=make_certificate("Li Wei")[1],
    )
    candidate = add_candidates(database)[0]
    finalise(database)

    payload = prepare_payload(database, OP_EXCLUDE, {
        "candidate_id": candidate.id, "court_order_ref": "CDR 12/2026",
    })
    payload_json = canonical_payload(payload)

    database.add(PendingOperation(
        op_type=OP_EXCLUDE, payload_json=payload_json,
        payload_hash=payload_digest(crypto, payload_json),
        proposer_id=proposer.staff_id, created_at=0.0,
        expires_at=PROPOSAL_LIFETIME_SECONDS,
        court_order_ref=payload["court_order_ref"],
    ))
    database.commit()

    stored = database.query(PendingOperation).one()

    assert stored.status == "PROPOSED"
    assert stored.approver_id is None
    assert stored.expires_at - stored.created_at == 24 * 60 * 60
    assert payload_matches(crypto, stored.payload_json, stored.payload_hash)
