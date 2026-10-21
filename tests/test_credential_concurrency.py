"""SR-08 two-connection issuance and same-credential contention."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Lock

import pytest
from flask import Flask
from sqlalchemy import event

import ballot_credentials
import ballot_service
import crypto_agility
from admin.candidates import add_draft_candidate
from ballot_confirmation import is_confirmation_reference
from ballot_integrity import verify_ballot_chain
from ballot_credentials import CredentialError, accept_ballot_with_credential
from ballot_models import AnonymousBallot, BallotChainState, BallotCredential, VotingEligibility
from records import db
from test_ballot_credentials import NOW, issue, seed_voter
from test_credential_acceptance import PAYLOAD


@pytest.fixture
def contention_app(tmp_path, monkeypatch, ballot_crypto):
    app = Flask(__name__)
    app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI="sqlite:///" + str(tmp_path / "credential-race.db"),
        SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"timeout": 15}},
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )
    db.init_app(app)
    monkeypatch.setattr(ballot_credentials, "crypto", crypto_agility.build_service(dev_keys=True))
    with app.app_context():
        db.create_all()
        seed_voter()
        candidate = add_draft_candidate(
            db.session, division="Melbourne", name="Candidate A",
            party="Independent", position_in_group=1,
        )
        candidate.status = "FINAL"
        db.session.commit()
        candidate_id = candidate.id
        engine = db.engine
        db.session.remove()
    yield app, candidate_id, engine
    engine.dispose()


@pytest.mark.parametrize("race", range(3))
def test_same_credential_race_accepts_exactly_one(contention_app, monkeypatch, race):
    app, candidate_id, engine = contention_app
    with app.app_context():
        credential = issue()

    ready = Barrier(2, timeout=15)
    original = ballot_service.get_ballot_candidates
    claims, deletions, confirmations = [], [], []
    connections = set()
    lock = Lock()

    def synchronise(record):
        candidates = original(record)
        ready.wait()
        return candidates

    def observe(connection, cursor, statement, parameters, context, many):
        sql = statement.lstrip().upper()
        with lock:
            if sql.startswith("UPDATE VOTING_ELIGIBILITY"):
                claims.append(cursor.rowcount)
                connections.add(id(connection.connection.driver_connection))
            if sql.startswith("DELETE FROM BALLOT_CREDENTIALS"):
                deletions.append(cursor.rowcount)

    monkeypatch.setattr(ballot_service, "get_ballot_candidates", synchronise)
    event.listen(engine, "after_cursor_execute", observe)

    def attempt():
        with app.app_context():
            try:
                reference = accept_ballot_with_credential(
                    credential, candidate_id, PAYLOAD, clock=lambda: NOW
                )
                assert is_confirmation_reference(reference)
                with lock:
                    confirmations.append(reference)
                return "accepted"
            except CredentialError as error:
                return str(error)
            finally:
                db.session.remove()

    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            futures = [workers.submit(attempt) for _ in range(2)]
            results = [future.result(timeout=30) for future in futures]
        assert sorted(results) == ["Credential authorisation failed", "accepted"]
        assert sorted(claims) == [0, 1]
        assert deletions == [1]
        assert len(confirmations) == 1
        assert len(connections) == 2
        with app.app_context():
            assert AnonymousBallot.query.count() == 1
            assert VotingEligibility.query.one().has_voted is True
            assert BallotCredential.query.count() == 0
            assert BallotChainState.query.one().record_count == 1
            assert verify_ballot_chain("election-2026", "Melbourne") is True
            with pytest.raises(CredentialError):
                accept_ballot_with_credential(
                    credential, candidate_id, PAYLOAD, clock=lambda: NOW
                )
    finally:
        event.remove(engine, "after_cursor_execute", observe)


def test_concurrent_issuance_leaves_only_one_valid_credential(contention_app, monkeypatch):
    app, candidate_id, engine = contention_app
    ready = Barrier(2, timeout=15)
    original = ballot_credentials.get_voting_eligibility

    def synchronise(*args):
        record = original(*args)
        ready.wait()
        return record

    monkeypatch.setattr(ballot_credentials, "get_voting_eligibility", synchronise)

    def attempt():
        with app.app_context():
            try:
                return issue()
            except CredentialError:
                return None
            finally:
                db.session.remove()

    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(attempt) for _ in range(2)]
        credentials = [future.result(timeout=30) for future in futures]
    with app.app_context():
        assert BallotCredential.query.count() == 1
        stored = BallotCredential.query.one().verifier
        valid = [credential for credential in credentials if credential is not None and
                 ballot_credentials.credential_verifier(credential) == stored]
        assert len(valid) == 1
        for credential in credentials:
            if credential is not None and credential != valid[0]:
                with pytest.raises(CredentialError):
                    accept_ballot_with_credential(
                        credential, candidate_id, PAYLOAD, clock=lambda: NOW
                    )
        accept_ballot_with_credential(valid[0], candidate_id, PAYLOAD, clock=lambda: NOW)
        assert AnonymousBallot.query.count() == 1


@pytest.mark.parametrize("race", range(3))
def test_two_eligible_voters_append_without_fork(contention_app, monkeypatch, race):
    app, candidate_id, engine = contention_app
    with app.app_context():
        seed_voter("voter-002")
        credentials = [issue(), issue("voter-002")]
    ready = Barrier(2, timeout=15)
    original = ballot_service.get_ballot_candidates

    def synchronise(record):
        candidates = original(record)
        ready.wait()
        return candidates

    monkeypatch.setattr(ballot_service, "get_ballot_candidates", synchronise)

    def attempt(credential):
        with app.app_context():
            try:
                return accept_ballot_with_credential(
                    credential, candidate_id, PAYLOAD, clock=lambda: NOW
                )
            finally:
                db.session.remove()

    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(attempt, credential) for credential in credentials]
        references = [future.result(timeout=30) for future in futures]
    assert len(set(references)) == 2
    assert all(is_confirmation_reference(reference) for reference in references)
    with app.app_context():
        assert AnonymousBallot.query.count() == 2
        assert BallotChainState.query.one().record_count == 2
        assert BallotCredential.query.count() == 0
        assert all(row.has_voted for row in VotingEligibility.query.all())
        assert verify_ballot_chain("election-2026", "Melbourne") is True
