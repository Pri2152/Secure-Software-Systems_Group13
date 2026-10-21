"""Voting HTTP controllers exercise the existing real security services."""

import pytest

import app as application
import ballot_credentials
from admin.candidates import add_draft_candidate
from ballot_models import AnonymousBallot, BallotChainState, BallotCredential, VotingEligibility
from records import EnrolmentRecord, db


HTTPS_URL = "https://localhost"


@pytest.fixture
def voting_client(monkeypatch, ballot_crypto):
    app = application.app
    monkeypatch.setitem(app.config, "TESTING", True)
    monkeypatch.setitem(app.config, "SR07_GATEWAY_ENFORCED", False)
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", True)
    monkeypatch.setitem(app.config, "VOTING_ELECTION_ID", "election-2026")
    monkeypatch.setattr(ballot_credentials, "crypto", ballot_crypto)
    with app.app_context():
        db.drop_all()
        db.create_all()
        for voter_id in ("voter-001", "voter-002"):
            db.session.add(EnrolmentRecord(
                owner_voter_id=voter_id, enrolment_status="enrolled",
                contact_email=voter_id + "@example.test",
            ))
            db.session.add(VotingEligibility(
                voter_id=voter_id, election_id="election-2026",
                electoral_division="Melbourne", state_code="VIC",
            ))
        candidate = add_draft_candidate(
            db.session, division="Melbourne", name="Candidate Alpha",
            party="Example Party", position_in_group=1,
        )
        candidate.status = "FINAL"
        db.session.commit()
        candidate_id = candidate.id
    client = app.test_client()
    with client.session_transaction(base_url=HTTPS_URL) as active:
        application.establish_authenticated_session("voter-001", active)
    yield client, candidate_id
    with app.app_context():
        db.session.remove()
        db.drop_all()


def csrf_headers(client):
    token = client.get("/login/csrf", base_url=HTTPS_URL).get_json()["csrf_token"]
    return {"X-CSRFToken": token, "Referer": HTTPS_URL + "/vote"}


def issue(client):
    return client.post("/vote/credentials", json={}, base_url=HTTPS_URL,
                       headers=csrf_headers(client))


def vote(client, credential, candidate_id):
    return client.post("/vote/ballots", json=dict(credential=credential, candidate_id=candidate_id),
                       base_url=HTTPS_URL, headers=csrf_headers(client))


def test_real_issuance_and_acceptance_clear_session(voting_client):
    from ballot_confirmation import is_confirmation_reference
    from ballot_integrity import verify_ballot_chain

    client, candidate_id = voting_client
    response = issue(client)
    assert response.status_code == 200
    assert set(response.get_json()) == {"credential"}
    result = vote(client, response.get_json()["credential"], candidate_id)
    assert result.status_code == 200
    assert set(result.get_json()) == {"status", "confirmation_reference"}
    assert result.get_json()["status"] == "accepted"
    assert is_confirmation_reference(result.get_json()["confirmation_reference"])
    assert client.get("/session-status", base_url=HTTPS_URL).status_code == 401
    with application.app.app_context():
        assert VotingEligibility.query.filter_by(voter_id="voter-001").one().has_voted is True
        assert VotingEligibility.query.filter_by(voter_id="voter-002").one().has_voted is False
        assert AnonymousBallot.query.count() == 1
        assert BallotCredential.query.count() == 0
        assert BallotChainState.query.one().record_count == 1
        assert verify_ballot_chain("election-2026", "Melbourne") is True


def test_issuance_requires_active_session(voting_client):
    client, _ = voting_client
    with client.session_transaction(base_url=HTTPS_URL) as active:
        active.clear()
    assert issue(client).status_code == 401


@pytest.mark.parametrize("path,body", [("/vote/credentials", {}),
                                      ("/vote/ballots", {"credential": "A" * 43, "candidate_id": 1})])
def test_csrf_is_required(voting_client, path, body):
    client, _ = voting_client
    result = client.post(path, json=body, base_url=HTTPS_URL)
    assert result.status_code == 400
    assert result.get_json() == {"error": "Invalid request"}


def test_issuance_rejects_client_identity(voting_client):
    client, _ = voting_client
    result = client.post("/vote/credentials", json={"voter_id": "voter-002"},
                         base_url=HTTPS_URL, headers=csrf_headers(client))
    assert result.status_code == 400
    with application.app.app_context():
        assert BallotCredential.query.count() == 0


@pytest.mark.parametrize("field", ["voter_id", "division", "state", "ballot_id", "chain_index",
                                   "record_hash", "has_voted", "confirmation_reference", "payload"])
def test_submission_rejects_untrusted_fields(voting_client, field):
    client, candidate_id = voting_client
    credential = issue(client).get_json()["credential"]
    body = dict(credential=credential, candidate_id=candidate_id)
    body[field] = "untrusted"
    result = client.post("/vote/ballots", json=body, base_url=HTTPS_URL, headers=csrf_headers(client))
    assert result.status_code == 400
    with application.app.app_context():
        assert AnonymousBallot.query.count() == 0


@pytest.mark.parametrize("body", [None, [], {}, {"credential": "A" * 43},
                                 {"credential": "A" * 43, "candidate_id": True},
                                 {"credential": "A" * 43, "candidate_id": "1"}])
def test_malformed_bodies_fail_safely(voting_client, body):
    client, _ = voting_client
    response = client.post("/vote/ballots", data="null" if body is None else None,
                           json=body if body is not None else None,
                           content_type="application/json", base_url=HTTPS_URL,
                           headers=csrf_headers(client))
    assert response.status_code == 400


def test_content_type_and_size_are_bounded(voting_client):
    client, _ = voting_client
    assert client.post("/vote/ballots", data="invalid", base_url=HTTPS_URL,
                       headers=csrf_headers(client)).status_code == 415
    result = client.post("/vote/ballots", data='{"credential":"' + "x" * 5000 + '"}',
                         content_type="application/json", base_url=HTTPS_URL,
                         headers=csrf_headers(client))
    assert result.status_code == 413
    assert result.get_json() == {"error": "Invalid request"}
