"""SR-03: genuine concurrent submissions against a shared database."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Lock

import pytest
from flask import Flask
from sqlalchemy import event

import ballot_service
from admin.candidates import add_draft_candidate
from ballot_models import AnonymousBallot, VotingEligibility
from records import EnrolmentRecord, db


@pytest.mark.parametrize("race", range(3))
def test_concurrent_double_submission_accepts_exactly_one(
    tmp_path, monkeypatch, ballot_crypto, race
):
    app = Flask(__name__)
    app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI="sqlite:///" + str(tmp_path / "race.db"),
        SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"timeout": 15}},
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )
    db.init_app(app)

    with app.app_context():
        db.create_all()
        db.session.add(EnrolmentRecord(
            owner_voter_id="voter-001", enrolment_status="enrolled",
            contact_email="voter@example.test",
        ))
        db.session.add(VotingEligibility(
            voter_id="voter-001", election_id="election-2026",
            electoral_division="Melbourne", state_code="VIC",
        ))
        candidate = add_draft_candidate(
            db.session, division="Melbourne", name="Candidate A",
            party="Independent", position_in_group=1,
        )
        candidate.status = "FINAL"
        db.session.commit()
        candidate_id = candidate.id
        engine = db.engine
        db.session.remove()

    ready = Barrier(2, timeout=15)
    original = ballot_service.get_ballot_candidates
    claims = []
    connections = set()
    lock = Lock()

    def synchronise(record):
        candidates = original(record)
        ready.wait()
        return candidates

    def observe_claim(connection, cursor, statement, parameters, context, many):
        if statement.lstrip().upper().startswith("UPDATE VOTING_ELIGIBILITY"):
            with lock:
                claims.append(cursor.rowcount)
                connections.add(id(connection.connection.driver_connection))

    monkeypatch.setattr(ballot_service, "get_ballot_candidates", synchronise)
    event.listen(engine, "after_cursor_execute", observe_claim)

    def attempt():
        with app.app_context():
            try:
                ballot_service.accept_ballot(
                    "voter-001", "election-2026", candidate_id,
                    '{"alg":"test","ct":"opaque"}',
                )
                return "accepted"
            except ballot_service.BallotAcceptanceError as error:
                return str(error)
            finally:
                db.session.remove()

    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            futures = [workers.submit(attempt) for _ in range(2)]
            results = [future.result(timeout=30) for future in futures]
        assert results.count("accepted") == 1
        assert "Vote already accepted or eligibility changed" in results
        assert sorted(claims) == [0, 1]
        assert len(connections) == 2
        with app.app_context():
            assert AnonymousBallot.query.count() == 1
            assert VotingEligibility.query.one().has_voted is True
            db.session.remove()
    finally:
        event.remove(engine, "after_cursor_execute", observe_claim)
        engine.dispose()
