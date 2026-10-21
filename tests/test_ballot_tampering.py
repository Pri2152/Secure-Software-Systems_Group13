"""SR-10 direct database attacks must never reach tally input."""

import pytest
from sqlalchemy import delete, select, update

from ballot_chain import compute_record_hash, make_checkpoint
from ballot_integrity import BallotIntegrityError
from ballot_models import AnonymousBallot, BallotChainState
from ballot_protection import canonical_json, parse_json
from records import db
from test_ballot_integrity import assert_event, db_app, integrity_chain, tally


@pytest.mark.parametrize("attack", [
    "ciphertext", "ballot-id", "previous-hash", "record-hash", "insertion",
    "middle-deletion", "tail-deletion", "reordering", "checkpoint-count",
    "checkpoint-head", "checkpoint-mac",
])
def test_database_tampering_is_flagged_before_any_tally_output(integrity_chain, attack, caplog):
    rows = db.session.execute(select(AnonymousBallot).order_by(AnonymousBallot.chain_index)).scalars().all()
    last = rows[-1]
    if attack == "ciphertext":
        envelope = parse_json(last.encrypted_ballot_json)
        envelope["ct"] = ("A" if envelope["ct"][0] != "A" else "B") + envelope["ct"][1:]
        db.session.execute(update(AnonymousBallot).where(AnonymousBallot.chain_index == 3)
                           .values(encrypted_ballot_json=canonical_json(envelope)))
    elif attack == "ballot-id":
        db.session.execute(update(AnonymousBallot).where(AnonymousBallot.chain_index == 3)
                           .values(ballot_id="e" * 64))
    elif attack in {"previous-hash", "record-hash"}:
        field = attack.replace("-", "_")
        db.session.execute(update(AnonymousBallot).where(AnonymousBallot.chain_index == 3)
                           .values(**{field: "sha256:" + "f" * 64}))
    elif attack == "insertion":
        db.session.execute(AnonymousBallot.__table__.insert().values(
            ballot_id="e" * 64, election_id="election-2026", electoral_division="Melbourne",
            chain_index=4, previous_hash=last.record_hash, record_hash="sha256:" + "f" * 64,
            encrypted_ballot_json=last.encrypted_ballot_json,
        ))
    elif attack in {"middle-deletion", "tail-deletion"}:
        index = 2 if attack == "middle-deletion" else 3
        db.session.execute(delete(AnonymousBallot).where(AnonymousBallot.chain_index == index))
    elif attack == "reordering":
        for before, after in ((1, 99), (2, 1), (99, 2)):
            db.session.execute(update(AnonymousBallot).where(AnonymousBallot.chain_index == before)
                               .values(chain_index=after))
    elif attack == "checkpoint-count":
        db.session.execute(update(BallotChainState).values(record_count=2))
    elif attack == "checkpoint-head":
        db.session.execute(update(BallotChainState).values(head_hash="sha256:" + "f" * 64))
    else:
        db.session.execute(update(BallotChainState).values(checkpoint_json="{}"))
    db.session.commit()
    received = []
    caplog.clear()
    with pytest.raises(BallotIntegrityError, match="^Ballot integrity verification failed$"):
        received.append(tally())
    assert received == []
    assert_event(integrity_chain)
    assert caplog.records == []


def test_recomputing_every_unkeyed_link_cannot_forge_checkpoint(integrity_chain):
    rows = db.session.execute(select(AnonymousBallot).order_by(AnonymousBallot.chain_index)).scalars().all()
    rows[0].ballot_id = "e" * 64
    for position, row in enumerate(rows):
        if position:
            row.previous_hash = rows[position - 1].record_hash
        row.record_hash = compute_record_hash(row)
    db.session.commit()
    with pytest.raises(BallotIntegrityError):
        tally()
    assert_event(integrity_chain)


def test_aead_rejects_copied_envelope_even_with_valid_resealed_checkpoint(integrity_chain):
    # The trusted test harness reseals state solely to exercise AEAD after all hash checks.
    rows = db.session.execute(select(AnonymousBallot).order_by(AnonymousBallot.chain_index)).scalars().all()
    rows[-1].encrypted_ballot_json = rows[0].encrypted_ballot_json
    rows[-1].record_hash = compute_record_hash(rows[-1])
    state = BallotChainState.query.one()
    state.head_hash = rows[-1].record_hash
    state.checkpoint_json = make_checkpoint(state.election_id, state.electoral_division,
                                            state.record_count, state.head_hash)
    db.session.commit()
    received = []
    with pytest.raises(BallotIntegrityError):
        received.append(tally())
    assert received == []
    assert_event(integrity_chain)


def test_coordinated_tail_delete_and_count_change_without_key_fails(integrity_chain):
    second = AnonymousBallot.query.filter_by(chain_index=2).one()
    db.session.execute(delete(AnonymousBallot).where(AnonymousBallot.chain_index == 3))
    db.session.execute(update(BallotChainState).values(record_count=2, head_hash=second.record_hash))
    db.session.commit()
    with pytest.raises(BallotIntegrityError):
        tally()
    assert_event(integrity_chain)
