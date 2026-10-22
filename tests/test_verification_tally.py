"""SR-18: tally counts only checked ballots and refuses tampered ones."""

import pytest

from sqlalchemy import create_engine, update

import audit

from audit import AuditLog
from ballot_chain import append_ballot
from ballot_models import AnonymousBallot
from records import db
from test_ballot_models import db_app  # noqa: F401  (fixture)
from verification.tally import TallyRefused, count_division, count_election


ELECTION = "election-2026"


@pytest.fixture
def ballots(db_app, ballot_crypto, monkeypatch):
    audit_log = AuditLog(create_engine("sqlite:///:memory:"), crypto=ballot_crypto)
    audit_log.create_schema()
    monkeypatch.setattr(audit, "record_event", audit_log.record_event)

    for division, candidate in (
        ("Melbourne", 7), ("Melbourne", 8), ("Melbourne", 7),
        ("Kooyong", 3), ("Kooyong", 3),
    ):
        append_ballot(ELECTION, division, "opaque", candidate)
        db.session.commit()

    yield audit_log
    audit_log.engine.dispose()


def break_one_ballot(division):
    db.session.execute(
        update(AnonymousBallot)
        .where(
            AnonymousBallot.electoral_division == division,
            AnonymousBallot.chain_index == 1,
        )
        .values(record_hash="sha256:" + "f" * 64)
    )
    db.session.commit()


def test_one_division_is_counted(ballots):
    assert count_division(ELECTION, "Melbourne") == {7: 2, 8: 1}


def test_all_divisions_are_counted(ballots):
    assert count_election(ELECTION, ["Melbourne", "Kooyong"]) == {
        "Melbourne": {7: 2, 8: 1},
        "Kooyong": {3: 2},
    }


def test_tampered_ballots_are_refused(ballots):
    break_one_ballot("Melbourne")

    with pytest.raises(TallyRefused):
        count_division(ELECTION, "Melbourne")


def test_one_bad_division_stops_the_whole_count(ballots):
    break_one_ballot("Kooyong")

    with pytest.raises(TallyRefused):
        count_election(ELECTION, ["Melbourne", "Kooyong"])


def test_refusal_is_written_to_the_audit_log(ballots):
    break_one_ballot("Melbourne")

    with pytest.raises(TallyRefused):
        count_division(ELECTION, "Melbourne")

    events = [
        e for e in ballots.list_events(stream="admin")
        if e["event_type"] == "TALLY_REFUSED"
    ]
    assert len(events) == 1
    assert events[0]["outcome"] == "failure"


def test_missing_chain_is_not_an_empty_result(ballots):
    with pytest.raises(TallyRefused):
        count_division(ELECTION, "Nowhere")


def test_no_divisions_is_refused(ballots):
    with pytest.raises(TallyRefused):
        count_election(ELECTION, [])


def test_refusal_message_shows_no_ballot_detail(ballots):
    break_one_ballot("Melbourne")

    with pytest.raises(TallyRefused) as problem:
        count_division(ELECTION, "Melbourne")

    assert str(problem.value) == "Tally refused: ballot check failed"
