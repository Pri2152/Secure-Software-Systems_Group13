"""HTTP integration with real authentication, credentials, AEAD and chain state."""

import pytest
import pyotp
from sqlalchemy import event, select, update
from sqlalchemy.exc import IntegrityError, OperationalError

import app as application
import audit
from admin.candidates import add_draft_candidate
from admin.models import Candidate
from auth import hash_password
from ballot_integrity import BallotIntegrityError, verified_candidate_ids_for_tally, verify_ballot_chain
from ballot_models import AnonymousBallot, BallotChainState, BallotCredential, VotingEligibility
from login_flow import LoginCoordinator, VoterRecord
from records import EnrolmentRecord, db
from test_confirmation_privacy import retained_snapshot
from test_voting_page import BallotPage
from test_voting_routes import HTTPS_URL, csrf_headers, issue, vote, voting_client


def assert_unaccepted():
    with application.app.app_context():
        assert VotingEligibility.query.filter_by(voter_id="voter-001").one().has_voted is False
        assert AnonymousBallot.query.count() == 0
        assert BallotCredential.query.count() == 1
        assert BallotChainState.query.count() == 0


def test_login_page_credential_and_vote_over_real_http(voting_client, monkeypatch, caplog):
    client, candidate_id = voting_client
    secret = "JBSWY3DPEHPK3PXP"
    voter = VoterRecord("voter-001", hash_password("SyntheticPassword!"), secret)
    coordinator = LoginCoordinator(lookup_voter=lambda account: voter if account == "voter-001" else None,
                                   clock=lambda: 1700000000.0)
    monkeypatch.setitem(application.app.config, "LOGIN_COORDINATOR", coordinator)
    with client.session_transaction(base_url=HTTPS_URL) as active:
        active.clear()
    login = client.post("/login", base_url=HTTPS_URL, headers=csrf_headers(client), json={
        "account_id": "voter-001", "password": "SyntheticPassword!",
        "totp_code": pyotp.TOTP(secret).at(1700000000),
    })
    assert login.status_code == 200
    page = client.get("/vote", base_url=HTTPS_URL)
    parsed = BallotPage()
    parsed.feed(page.get_data(as_text=True))
    assert parsed.candidates == [candidate_id]
    headers = {"X-CSRFToken": parsed.csrf, "Referer": HTTPS_URL + "/vote"}
    issued = client.post("/vote/credentials", json={}, headers=headers, base_url=HTTPS_URL)
    credential = issued.get_json()["credential"]
    caplog.clear()
    result = client.post("/vote/ballots", json=dict(credential=credential, candidate_id=candidate_id),
                         headers=headers, base_url=HTTPS_URL)
    assert result.status_code == 200
    output = result.get_json()
    assert set(output) == {"status", "confirmation_reference"}
    reference = output["confirmation_reference"]
    assert output["status"] == "accepted"
    assert caplog.records == []
    with application.app.app_context():
        ballot = AnonymousBallot.query.one()
        snapshot = str(retained_snapshot())
        assert credential not in snapshot
        assert reference not in snapshot
        assert "voter-001" not in str({col.name: getattr(ballot, col.name)
                                      for col in AnonymousBallot.__table__.columns})
        assert not {"source_ip", "timestamp", "candidate_id", "confirmation_reference"} & {
            col.name for col in AnonymousBallot.__table__.columns
        }
        for value in (credential, "voter-001", "Candidate Alpha", "Example Party",
                      ballot.ballot_id, ballot.record_hash, ballot.previous_hash,
                      ballot.encrypted_ballot_json):
            assert value not in result.get_data(as_text=True)
        assert ballot.ballot_id not in str([dict(row) for row in db.session.execute(
            select(VotingEligibility.__table__)).mappings()])
        assert verified_candidate_ids_for_tally("election-2026", "Melbourne") == (candidate_id,)
        assert verify_ballot_chain("election-2026", "Melbourne") is True
        assert BallotChainState.query.one().record_count == 1
        assert BallotCredential.query.count() == 0
    with client.session_transaction(base_url=HTTPS_URL) as active:
        assert "authenticated" not in active
        assert reference not in str(dict(active))
    assert client.get("/vote", base_url=HTTPS_URL).status_code == 401


def test_bearer_submission_needs_no_voter_identity_session(voting_client):
    identity_client, candidate_id = voting_client
    credential = issue(identity_client).get_json()["credential"]
    anonymous_client = application.app.test_client()
    assert vote(anonymous_client, credential, candidate_id).status_code == 200
    with anonymous_client.session_transaction(base_url=HTTPS_URL) as active:
        assert "voter_id" not in active


def test_http_replay_cannot_create_second_confirmation(voting_client):
    client, candidate_id = voting_client
    credential = issue(client).get_json()["credential"]
    assert vote(client, credential, candidate_id).status_code == 200
    failed = vote(client, credential, candidate_id)
    assert failed.status_code == 409
    assert failed.get_json() == {"error": "Vote could not be accepted"}
    with application.app.app_context():
        assert AnonymousBallot.query.count() == 1
        assert BallotChainState.query.one().record_count == 1


def test_already_voted_voter_cannot_issue_again(voting_client):
    client, candidate_id = voting_client
    credential = issue(client).get_json()["credential"]
    assert vote(client, credential, candidate_id).status_code == 200
    with client.session_transaction(base_url=HTTPS_URL) as active:
        application.establish_authenticated_session("voter-001", active)
    result = issue(client)
    assert result.status_code == 409
    assert result.get_json() == {"error": "Voting unavailable"}


@pytest.mark.parametrize("kind", ["unknown", "other-division", "excluded", "expired", "removed"])
def test_invalid_vote_rejected_through_http_without_consumption(voting_client, kind):
    client, candidate_id = voting_client
    credential = issue(client).get_json()["credential"]
    with application.app.app_context():
        if kind == "unknown":
            candidate_id = 999999
        elif kind == "other-division":
            candidate = add_draft_candidate(db.session, division="Sydney", name="Other Candidate",
                                            party="Other Party", position_in_group=1)
            candidate.status = "FINAL"
            db.session.commit()
            candidate_id = candidate.id
        elif kind == "excluded":
            db.session.get(Candidate, candidate_id).status = "EXCLUDED"
        elif kind == "expired":
            BallotCredential.query.one().expires_at = 0
        else:
            EnrolmentRecord.query.filter_by(owner_voter_id="voter-001").one().enrolment_status = "removed"
        db.session.commit()
    failed = vote(client, credential, candidate_id)
    assert failed.status_code == 409
    assert failed.get_json() == {"error": "Vote could not be accepted"}
    assert_unaccepted()
    assert client.get("/session-status", base_url=HTTPS_URL).status_code == 200


@pytest.mark.parametrize("failure", ["insert", "commit"])
def test_http_transaction_failure_restores_all_state(voting_client, failure):
    client, candidate_id = voting_client
    credential = issue(client).get_json()["credential"]
    observed = []

    def fail_insert(mapper, connection, target):
        observed.append(connection.execute(select(BallotChainState.record_count)).scalar_one())
        raise IntegrityError("private SQL details", {}, Exception())

    def fail_commit(active):
        active.flush()
        observed.append(active.execute(select(BallotChainState.record_count)).scalar_one())
        raise OperationalError("private commit details", {}, Exception())

    target, event_name, hook = (AnonymousBallot, "before_insert", fail_insert) if failure == "insert" else (
        db.session.session_factory.class_, "before_commit", fail_commit)
    event.listen(target, event_name, hook)
    try:
        response = vote(client, credential, candidate_id)
    finally:
        event.remove(target, event_name, hook)
    assert response.status_code == 409
    assert response.get_json() == {"error": "Vote could not be accepted"}
    assert observed == [1]
    assert_unaccepted()
    assert vote(client, credential, candidate_id).status_code == 200


def test_unexpected_service_exception_is_not_disclosed(voting_client, monkeypatch):
    import voting_routes

    client, candidate_id = voting_client
    credential = issue(client).get_json()["credential"]

    def fail(*args, **kwargs):
        raise RuntimeError("private diagnostic " + credential)

    monkeypatch.setattr(voting_routes, "accept_ballot_with_credential", fail)
    response = vote(client, credential, candidate_id)
    assert response.status_code == 503
    assert response.get_json() == {"error": "Vote could not be accepted"}
    assert_unaccepted()


def test_http_vote_is_rejected_by_trusted_tally_after_database_tamper(voting_client, monkeypatch):
    client, candidate_id = voting_client
    credential = issue(client).get_json()["credential"]
    assert vote(client, credential, candidate_id).status_code == 200
    events = []
    monkeypatch.setattr(audit, "record_event", lambda *args, **kwargs: events.append((args, kwargs)))
    with application.app.app_context():
        db.session.execute(update(AnonymousBallot).values(record_hash="sha256:" + "f" * 64))
        db.session.commit()
        with pytest.raises(BallotIntegrityError):
            verified_candidate_ids_for_tally("election-2026", "Melbourne")
    assert len(events) == 1
    assert events[0] == (("BALLOT_INTEGRITY_FAILURE",), dict(
        stream="ballot", actor_type="anonymous", actor_id=None, outcome="failure", source_ip=None))
