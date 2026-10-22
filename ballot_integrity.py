"""SR-10 full snapshot verification before trusted tally input is released."""

import hmac
import logging

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

import audit
from ballot_chain import (
    BallotChainError, authenticate_state, compute_record_hash, genesis_hash, record_metadata,
)
from ballot_models import AnonymousBallot, BallotChainState
from ballot_protection import BallotProtectionError, _open_ballot
from crypto_agility import CryptoError
from records import db


logger = logging.getLogger("evp.ballot_integrity")


class BallotIntegrityError(Exception):
    """No trusted tally input is available."""


def _failure_event():
    try:
        audit.record_event(
            "BALLOT_INTEGRITY_FAILURE", stream="ballot", actor_type="anonymous",
            actor_id=None, outcome="failure", source_ip=None,
        )
    except Exception:
        # Preserve a generic security signal even if the audit store is unavailable.
        logger.error("BALLOT_INTEGRITY_FAILURE audit_unavailable")


def _verified_contents(election_id, electoral_division):
    try:
        if (
            not isinstance(election_id, str) or not election_id.strip()
            or not isinstance(electoral_division, str) or not electoral_division.strip()
        ):
            raise BallotChainError("Ballot chain unavailable")
        # SQLite's legacy driver needs an explicit BEGIN for a stable read snapshot.
        with db.engine.connect() as connection:
            if connection.dialect.name == "sqlite":
                connection.exec_driver_sql("BEGIN")
            else:
                connection = connection.execution_options(isolation_level="SERIALIZABLE")
                connection.begin()
            with Session(bind=connection) as reader:
                state = reader.get(BallotChainState, (election_id, electoral_division))
                if state is None:
                    raise BallotChainError("Ballot chain unavailable")
                authenticate_state(state)
                records = reader.execute(select(AnonymousBallot).where(
                    AnonymousBallot.election_id == election_id,
                    AnonymousBallot.electoral_division == electoral_division,
                ).order_by(AnonymousBallot.chain_index)).scalars().all()
                if len(records) != state.record_count:
                    raise BallotChainError("Ballot chain unavailable")
                previous = genesis_hash(election_id, electoral_division)
                for position, record in enumerate(records, start=1):
                    if (
                        record.chain_index != position
                        or not hmac.compare_digest(record.previous_hash, previous)
                        or not hmac.compare_digest(record.record_hash, compute_record_hash(record))
                    ):
                        raise BallotChainError("Ballot chain unavailable")
                    previous = record.record_hash
                if not hmac.compare_digest(previous, state.head_hash):
                    raise BallotChainError("Ballot chain unavailable")
                # Materialise all authenticated choices before returning any tally input.
                return tuple(_open_ballot(record.encrypted_ballot_json, record_metadata(record))
                             for record in records)
    except (BallotChainError, BallotProtectionError, CryptoError, SQLAlchemyError,
            ValueError, TypeError):
        _failure_event()
        raise BallotIntegrityError("Ballot integrity verification failed") from None


def verify_ballot_chain(election_id, electoral_division):
    """Verify every link, checkpoint and AEAD envelope; disclose no choices."""
    _verified_contents(election_id, electoral_division)
    return True


def verified_candidate_ids_for_tally(election_id, electoral_division):
    """Trusted server-side boundary; never expose this through voter responses."""
    contents = _verified_contents(election_id, electoral_division)
    return tuple(content["candidate_id"] for content in contents)
