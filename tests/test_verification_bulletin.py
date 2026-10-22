"""SR-11: signed bulletin board and independent recount."""

import copy
import random

import pytest

from sqlalchemy import create_engine, update

import audit

from audit import AuditLog
from ballot_chain import append_ballot
from ballot_models import AnonymousBallot
from records import db
from test_ballot_models import db_app  # noqa: F401  (fixture)
from verification.bulletin import all_passed, build_bulletin, verify_bulletin
from verification.tally import TallyRefused


ELECTION = "election-2026"
DIVISIONS = ["Melbourne", "Kooyong"]


@pytest.fixture
def board(db_app, ballot_crypto, monkeypatch):
    audit_log = AuditLog(create_engine("sqlite:///:memory:"), crypto=ballot_crypto)
    audit_log.create_schema()
    monkeypatch.setattr(audit, "record_event", audit_log.record_event)

    for division, candidate in (
        ("Melbourne", 7), ("Melbourne", 8), ("Melbourne", 7), ("Melbourne", 9),
        ("Kooyong", 3), ("Kooyong", 3),
    ):
        append_ballot(ELECTION, division, "opaque", candidate)
        db.session.commit()

    yield build_bulletin(
        ballot_crypto, ELECTION, DIVISIONS, 1, rng=random.Random(5)
    )
    audit_log.engine.dispose()


def results(crypto, package):
    return dict(verify_bulletin(crypto, package))


def failed(crypto, package):
    return [name for name, passed in verify_bulletin(crypto, package) if not passed]


def test_honest_bulletin_passes_every_check(ballot_crypto, board):
    checks = verify_bulletin(ballot_crypto, board)

    assert all_passed(checks)
    assert len(checks) == 6


def test_bulletin_counts_are_right(board):
    melbourne = next(
        e for e in board["bulletin"]["divisions"] if e["division"] == "Melbourne"
    )

    assert melbourne["ballot_count"] == 4
    assert sorted(melbourne["choices"]) == [7, 7, 8, 9]
    assert board["result"]["result"]["ballots_counted"] == 6


def test_choices_are_not_in_chain_order(board):
    # chain order was 7, 8, 7, 9. The seeded shuffle must change it.
    melbourne = next(
        e for e in board["bulletin"]["divisions"] if e["division"] == "Melbourne"
    )

    assert melbourne["choices"] != [7, 8, 7, 9]


def test_no_ballot_ids_or_encrypted_ballots_are_published(board):
    text = str(board)

    assert "ballot_id" not in text
    assert "encrypted_ballot" not in text
    assert "previous_hash" not in text


def test_removed_choice_is_caught(ballot_crypto, board):
    bad = copy.deepcopy(board)
    bad["bulletin"]["divisions"][0]["choices"].pop()

    assert not all_passed(verify_bulletin(ballot_crypto, bad))


def test_changed_choice_is_caught(ballot_crypto, board):
    bad = copy.deepcopy(board)
    entry = bad["bulletin"]["divisions"][0]
    entry["choices"][0] = 99999

    names = failed(ballot_crypto, bad)

    assert "bulletin signature is valid" in names
    assert "recount of the choices equals the signed result" in names


def test_changed_record_hash_is_caught(ballot_crypto, board):
    bad = copy.deepcopy(board)
    bad["bulletin"]["divisions"][0]["record_hashes"][0] = "sha256:" + "0" * 64

    assert "commitment matches the record hashes" in failed(ballot_crypto, bad)


def test_changed_signed_result_is_caught(ballot_crypto, board):
    bad = copy.deepcopy(board)
    division = next(iter(bad["result"]["result"]["divisions"]))
    first = next(iter(bad["result"]["result"]["divisions"][division]))
    bad["result"]["result"]["divisions"][division][first] += 5

    assert "signed result is valid" in failed(ballot_crypto, bad)


def test_other_signing_key_is_caught(board):
    from crypto_agility import build_service

    assert not all_passed(verify_bulletin(build_service(dev_keys=True), board))


@pytest.mark.parametrize("junk", [None, {}, [], "text", {"bulletin": 5}])
def test_junk_fails_without_crashing(ballot_crypto, junk):
    assert not all_passed(verify_bulletin(ballot_crypto, junk))


def test_tampered_store_means_no_bulletin(db_app, ballot_crypto, board):
    db.session.execute(
        update(AnonymousBallot)
        .where(AnonymousBallot.chain_index == 1)
        .values(record_hash="sha256:" + "f" * 64)
    )
    db.session.commit()

    with pytest.raises(TallyRefused):
        build_bulletin(ballot_crypto, ELECTION, DIVISIONS, 2)
