"""SR-09 success contract and confirmation timing around the real transaction."""

from sqlalchemy import event, select

import ballot_credentials
from ballot_confirmation import is_confirmation_reference
from ballot_models import AnonymousBallot, BallotCredential, VotingEligibility
from records import db
from test_ballot_credentials import credential_app
from test_credential_acceptance import (
    PAYLOAD, assert_state, credential_ballot, submit,
)


def test_success_returns_only_ephemeral_confirmation(credential_ballot):
    credential, candidate_id = credential_ballot
    verifier = ballot_credentials.credential_verifier(credential)
    reference = submit(credential, candidate_id)
    assert type(reference) is str
    assert is_confirmation_reference(reference)
    assert_state(True, 1, 0)
    ballot = AnonymousBallot.query.one()
    for private_value in (credential, verifier, ballot.ballot_id, PAYLOAD, "voter-001",
                          "Candidate A", "Independent"):
        assert private_value not in reference
    # The response is a single opaque value, with no structured preference fields.
    assert len(reference) == 37
    assert reference != str(candidate_id)


def test_confirmation_is_generated_before_commit_and_returned_after(
    credential_ballot, monkeypatch
):
    sequence = []
    session = db.session()
    expected = "conf_" + "C" * 32

    def generate():
        assert session.execute(select(VotingEligibility.has_voted)).scalar_one() is True
        assert session.query(BallotCredential).count() == 0
        assert session.query(AnonymousBallot).count() == 1
        sequence.append("generated")
        return expected

    def committed(active_session):
        sequence.append("committed")

    monkeypatch.setattr(ballot_credentials, "generate_confirmation_reference", generate)
    event.listen(session, "after_commit", committed)
    try:
        result = submit(*credential_ballot)
        sequence.append("returned")
    finally:
        event.remove(session, "after_commit", committed)
    assert result == expected
    assert sequence == ["generated", "committed", "returned"]
    assert_state(True, 1, 0)


def test_confirmation_uses_separate_randomness_from_internal_ballot_id(
    credential_ballot, monkeypatch
):
    import ballot_confirmation
    import ballot_storage

    calls = []

    def random_ballot_id(nbytes):
        calls.append(("ballot", nbytes))
        return "d" * 64

    def random_confirmation(nbytes):
        calls.append(("confirmation", nbytes))
        return "E" * 32

    monkeypatch.setattr(ballot_storage.secrets, "token_hex", random_ballot_id)
    monkeypatch.setattr(ballot_confirmation.secrets, "token_urlsafe", random_confirmation)
    reference = submit(*credential_ballot)
    assert reference == "conf_" + "E" * 32
    assert AnonymousBallot.query.one().ballot_id == "d" * 64
    assert calls == [("ballot", 32), ("confirmation", 24)]
