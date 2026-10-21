"""SR-10 failures roll back eligibility, credential, ballot and checkpoint."""

import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import OperationalError

import ballot_chain
from ballot_chain import BallotChainError
from ballot_credentials import CredentialError
from ballot_integrity import verified_candidate_ids_for_tally
from ballot_models import AnonymousBallot, BallotChainState, BallotCredential, VotingEligibility
from crypto_agility import CryptoNotConfigured
from records import db
from test_ballot_credentials import credential_app, issue, seed_voter
from test_credential_acceptance import credential_ballot, submit


@pytest.mark.parametrize("failure", ["encryption", "record", "checkpoint", "state-update", "insert", "commit"])
def test_failed_append_restores_existing_chain_and_authorisation(
    credential_ballot, ballot_crypto, monkeypatch, failure
):
    submit(*credential_ballot)
    seed_voter("voter-002")
    second = issue("voter-002")
    candidate_id = credential_ballot[1]
    state = BallotChainState.query.one()
    previous = (state.record_count, state.head_hash, state.checkpoint_json)
    received, observed = [], []
    engine = db.engine
    session = db.session()

    def fail_crypto(*args, **kwargs):
        raise CryptoNotConfigured("private crypto diagnostic")

    def fail_record(*args, **kwargs):
        raise BallotChainError("Ballot chain unavailable")

    def fail_state(connection, cursor, statement, parameters, context, many):
        if statement.upper().startswith("UPDATE BALLOT_CHAIN_STATE"):
            observed.append(connection.execute(select(VotingEligibility.has_voted).where(
                VotingEligibility.voter_id == "voter-002"
            )).scalar_one())
            raise OperationalError("private state error", {}, Exception())

    def fail_insert(mapper, connection, target):
        observed.append(connection.execute(select(BallotChainState.record_count)).scalar_one())
        raise OperationalError("private insertion error", {}, Exception())

    def fail_commit():
        session.flush()
        observed.append((AnonymousBallot.query.count(), session.execute(select(BallotChainState.record_count)).scalar_one()))
        raise OperationalError("private commit error", {}, Exception())

    with monkeypatch.context() as patch:
        if failure == "encryption":
            patch.setattr(ballot_crypto, "encrypt", fail_crypto)
        elif failure == "record":
            patch.setattr(ballot_chain, "compute_record_hash", fail_record)
        elif failure == "checkpoint":
            patch.setattr(ballot_crypto, "mac", fail_crypto)
        elif failure == "state-update":
            event.listen(engine, "before_cursor_execute", fail_state)
        elif failure == "insert":
            event.listen(AnonymousBallot, "before_insert", fail_insert)
        else:
            patch.setattr(session, "commit", fail_commit)
        try:
            with pytest.raises(CredentialError, match="^Credential authorisation failed$"):
                received.append(submit(second, candidate_id))
        finally:
            if failure == "state-update":
                event.remove(engine, "before_cursor_execute", fail_state)
            if failure == "insert":
                event.remove(AnonymousBallot, "before_insert", fail_insert)
    assert received == []
    db.session.remove()
    assert VotingEligibility.query.filter_by(voter_id="voter-002").one().has_voted is False
    assert BallotCredential.query.count() == 1
    assert AnonymousBallot.query.count() == 1
    state = BallotChainState.query.one()
    assert (state.record_count, state.head_hash, state.checkpoint_json) == previous
    if failure == "state-update":
        assert observed == [True]
    elif failure == "insert":
        assert observed == [2]
    elif failure == "commit":
        assert observed == [(2, 2)]
    assert verified_candidate_ids_for_tally("election-2026", "Melbourne") == (candidate_id,)
    submit(second, candidate_id)
    assert verified_candidate_ids_for_tally("election-2026", "Melbourne") == (candidate_id, candidate_id)


def test_first_vote_crypto_failure_leaves_no_checkpoint(credential_ballot, ballot_crypto, monkeypatch):
    def fail(*args, **kwargs):
        raise CryptoNotConfigured("no ballot key")

    monkeypatch.setattr(ballot_crypto, "encrypt", fail)
    with pytest.raises(CredentialError):
        submit(*credential_ballot)
    db.session.remove()
    assert BallotChainState.query.count() == 0
    assert AnonymousBallot.query.count() == 0
    assert BallotCredential.query.count() == 1
    assert VotingEligibility.query.one().has_voted is False
