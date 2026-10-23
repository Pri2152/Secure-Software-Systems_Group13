"""SR-10 append-only logical ballot chain and authenticated local checkpoint."""

import hashlib
import secrets

from sqlalchemy import select, update

from ballot_models import AnonymousBallot, BallotChainState
from ballot_protection import (
    HASH_PATTERN, ballot_metadata, canonical_json, parse_json, protect_ballot,
)
from crypto_agility import crypto
from records import db


class BallotChainError(Exception):
    """The chain cannot be appended or authenticated safely."""


def digest(value):
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def genesis_hash(election_id, electoral_division):
    return digest(dict(domain="EVP_BALLOT_GENESIS_V1", election_id=election_id,
                       electoral_division=electoral_division))


def checkpoint_body(election_id, electoral_division, record_count, head_hash):
    return dict(domain="EVP_BALLOT_CHECKPOINT_V1", election_id=election_id,
                electoral_division=electoral_division, record_count=record_count,
                head_hash=head_hash)


def make_checkpoint(election_id, electoral_division, record_count, head_hash):
    body = checkpoint_body(election_id, electoral_division, record_count, head_hash)
    return canonical_json(crypto.mac("ballot-chain", canonical_json(body).encode("utf-8")))


def authenticate_state(state):
    if (
        type(state.record_count) is not int or state.record_count < 0
        or not isinstance(state.head_hash, str)
        or HASH_PATTERN.fullmatch(state.head_hash) is None
        or not crypto.verify_mac("ballot-chain", canonical_json(checkpoint_body(
            state.election_id, state.electoral_division, state.record_count, state.head_hash
        )).encode("utf-8"), parse_json(state.checkpoint_json))
    ):
        raise BallotChainError("Ballot chain unavailable")


def record_metadata(record):
    return ballot_metadata(record.ballot_id, record.election_id, record.electoral_division,
                           record.chain_index, record.previous_hash)


def compute_record_hash(record):
    return digest(dict(domain="EVP_BALLOT_RECORD_V1", metadata=record_metadata(record),
                       envelope=parse_json(record.encrypted_ballot_json)))


def append_ballot(election_id, electoral_division, payload, candidate_id):
    """Stage an encrypted append and checkpoint; caller owns commit/rollback.

    Returns the record hash, the public identifier of the new record.
    """
    with db.session.no_autoflush:
        state = db.session.execute(select(BallotChainState).where(
            BallotChainState.election_id == election_id,
            BallotChainState.electoral_division == electoral_division,
        ).execution_options(populate_existing=True)).scalar_one_or_none()
        if state is None:
            existing = db.session.execute(select(AnonymousBallot.ballot_id).where(
                AnonymousBallot.election_id == election_id,
                AnonymousBallot.electoral_division == electoral_division,
            ).limit(1)).first()
            if existing is not None:
                raise BallotChainError("Ballot chain unavailable")
            head = genesis_hash(election_id, electoral_division)
            state = BallotChainState(
                election_id=election_id, electoral_division=electoral_division,
                record_count=0, head_hash=head,
                checkpoint_json=make_checkpoint(election_id, electoral_division, 0, head),
            )
            db.session.add(state)
            db.session.flush()
        authenticate_state(state)
        count, head, checkpoint = state.record_count, state.head_hash, state.checkpoint_json
        record = AnonymousBallot(
            ballot_id=secrets.token_hex(32), election_id=election_id,
            electoral_division=electoral_division, chain_index=count + 1,
            previous_hash=head,
        )
        record.encrypted_ballot_json = protect_ballot(candidate_id, payload, record_metadata(record))
        record.record_hash = compute_record_hash(record)
        new_checkpoint = make_checkpoint(election_id, electoral_division, count + 1, record.record_hash)
        claimed = db.session.execute(update(BallotChainState).where(
            BallotChainState.election_id == election_id,
            BallotChainState.electoral_division == electoral_division,
            BallotChainState.record_count == count,
            BallotChainState.head_hash == head,
            BallotChainState.checkpoint_json == checkpoint,
        ).values(record_count=count + 1, head_hash=record.record_hash,
                 checkpoint_json=new_checkpoint).execution_options(synchronize_session=False)).rowcount
        if claimed != 1:
            raise BallotChainError("Ballot chain unavailable")
        db.session.add(record)
    return record.record_hash
