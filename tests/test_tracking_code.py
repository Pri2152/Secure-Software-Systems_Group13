"""SR-11: the voter gets a tracking code that is on the bulletin and reveals nothing about the choice."""

import pytest

import app as application
import ballot_credentials
from admin.candidates import add_draft_candidate
from ballot_models import AnonymousBallot, VotingEligibility
from ballot_protection import HASH_PATTERN
from records import EnrolmentRecord, db
from verification.bulletin import build_bulletin, verify_bulletin


HTTPS_URL = "https://localhost"
ELECTION = "election-2026"


@pytest.fixture
def two_candidates(monkeypatch, ballot_crypto):
    app = application.app
    monkeypatch.setitem(app.config, "TESTING", True)
    monkeypatch.setitem(app.config, "SR07_GATEWAY_ENFORCED", False)
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", True)
    monkeypatch.setitem(app.config, "VOTING_ELECTION_ID", ELECTION)
    monkeypatch.setattr(ballot_credentials, "crypto", ballot_crypto)

    with app.app_context():
        db.drop_all()
        db.create_all()

        for voter_id in ("voter-001", "voter-002", "voter-003"):
            db.session.add(EnrolmentRecord(
                owner_voter_id=voter_id, enrolment_status="enrolled",
                contact_email=voter_id + "@example.test",
            ))
            db.session.add(VotingEligibility(
                voter_id=voter_id, election_id=ELECTION,
                electoral_division="Melbourne", state_code="VIC",
            ))

        drafts = [
            add_draft_candidate(
                db.session, division="Melbourne", name=name,
                party="Example Party", position_in_group=position,
            )
            for position, name in enumerate(("Candidate Alpha", "Candidate Beta"), 1)
        ]
        for candidate in drafts:
            candidate.status = "FINAL"
        db.session.flush()
        ids = [candidate.id for candidate in drafts]

        db.session.commit()

    yield app, ballot_crypto, ids

    with app.app_context():
        db.session.remove()
        db.drop_all()


def cast(app, voter_id, candidate_id):
    client = app.test_client()

    with client.session_transaction(base_url=HTTPS_URL) as active:
        application.establish_authenticated_session(voter_id, active)

    token = client.get("/login/csrf", base_url=HTTPS_URL).get_json()["csrf_token"]
    headers = {"X-CSRFToken": token, "Referer": HTTPS_URL + "/vote"}
    issued = client.post("/vote/credentials", json={}, base_url=HTTPS_URL, headers=headers)
    result = client.post(
        "/vote/ballots",
        json={"credential": issued.get_json()["credential"], "candidate_id": candidate_id},
        base_url=HTTPS_URL, headers=headers,
    )

    assert result.status_code == 200
    return result.get_json()


def test_tracking_code_is_the_public_record_hash(two_candidates):
    app, _, (alpha, _) = two_candidates

    reply = cast(app, "voter-001", alpha)

    assert HASH_PATTERN.fullmatch(reply["tracking_code"])

    with app.app_context():
        assert AnonymousBallot.query.one().record_hash == reply["tracking_code"]


def test_tracking_code_is_on_the_signed_bulletin(two_candidates):
    app, crypto, (alpha, beta) = two_candidates

    codes = [
        cast(app, "voter-001", alpha)["tracking_code"],
        cast(app, "voter-002", beta)["tracking_code"],
    ]

    with app.app_context():
        package = build_bulletin(crypto, ELECTION, ["Melbourne"], 1)

    published = package["bulletin"]["divisions"][0]["record_hashes"]

    assert all(code in published for code in codes)
    assert all(passed for _, passed in verify_bulletin(crypto, package))


def test_same_choice_gives_different_codes_and_none_names_a_candidate(two_candidates):
    app, _, (alpha, _) = two_candidates

    first = cast(app, "voter-001", alpha)
    second = cast(app, "voter-002", alpha)

    assert first["tracking_code"] != second["tracking_code"]

    for reply in (first, second):
        assert "Candidate" not in str(reply)
        assert reply["tracking_code"] != reply["confirmation_reference"]


def test_bulletin_does_not_link_a_code_to_a_choice(two_candidates):
    app, crypto, (alpha, beta) = two_candidates

    cast(app, "voter-001", alpha)
    cast(app, "voter-002", beta)
    cast(app, "voter-003", alpha)

    with app.app_context():
        entry = build_bulletin(crypto, ELECTION, ["Melbourne"], 1)["bulletin"]["divisions"][0]

    # Hashes and choices are separate lists; nothing pairs them.
    assert set(entry) == {"division", "ballot_count", "record_hashes", "choices"}
    assert sorted(entry["choices"]) == sorted([alpha, beta, alpha])


def test_a_refused_vote_returns_no_tracking_code(two_candidates):
    app, _, (alpha, _) = two_candidates
    client = app.test_client()

    with client.session_transaction(base_url=HTTPS_URL) as active:
        application.establish_authenticated_session("voter-001", active)

    token = client.get("/login/csrf", base_url=HTTPS_URL).get_json()["csrf_token"]
    headers = {"X-CSRFToken": token, "Referer": HTTPS_URL + "/vote"}
    result = client.post(
        "/vote/ballots",
        json={"credential": "A" * 43, "candidate_id": alpha},
        base_url=HTTPS_URL, headers=headers,
    )

    assert result.status_code == 409
    assert "tracking_code" not in result.get_json()
