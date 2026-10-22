"""SR-09 failures never return a confirmation or create a reusable receipt."""

from datetime import timedelta

import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError, OperationalError

import ballot_confirmation
import ballot_credentials
from ballot_confirmation import is_confirmation_reference
from ballot_credentials import CredentialError
from ballot_models import AnonymousBallot, BallotCredential, VotingEligibility
from records import db
from test_ballot_credentials import NOW, credential_app
from test_credential_acceptance import (
    assert_state, credential_ballot, submit,
)
from test_confirmation_privacy import retained_snapshot


@pytest.mark.parametrize("failure", ["invalid-credential", "expired", "invalid-candidate"])
def test_rejected_input_returns_no_reference(credential_ballot, monkeypatch, failure):
    generated = []
    received = []

    def generate():
        generated.append("unexpected")
        return "conf_" + "F" * 32

    monkeypatch.setattr(ballot_credentials, "generate_confirmation_reference", generate)
    credential, candidate_id = credential_ballot
    if failure == "invalid-credential":
        credential = "invalid"
    if failure == "invalid-candidate":
        candidate_id = 999999
    moment = NOW + timedelta(seconds=600) if failure == "expired" else NOW
    with pytest.raises(CredentialError, match="^Credential authorisation failed$"):
        received.append(submit(credential, candidate_id, moment=moment))
    assert received == []
    assert generated == []
    assert_state()


@pytest.mark.parametrize("failure", ["insert", "commit"])
def test_database_failure_discards_generated_confirmation(
    credential_ballot, monkeypatch, caplog, failure
):
    expected = "conf_" + "G" * 32
    generated, observed, received = [], [], []
    session = db.session()

    def generate():
        generated.append(expected)
        return expected

    def fail_insert(mapper, connection, target):
        observed.append((
            connection.execute(select(VotingEligibility.has_voted)).scalar_one(),
            connection.execute(select(BallotCredential.verifier)).all(),
        ))
        raise IntegrityError("private insertion details", {}, Exception())

    def fail_commit():
        session.flush()
        observed.append((
            session.execute(select(VotingEligibility.has_voted)).scalar_one(),
            session.query(BallotCredential).count(),
            session.query(AnonymousBallot).count(),
        ))
        raise OperationalError("private commit details", {}, Exception())

    monkeypatch.setattr(ballot_credentials, "generate_confirmation_reference", generate)
    caplog.clear()
    if failure == "insert":
        event.listen(AnonymousBallot, "before_insert", fail_insert)
    else:
        monkeypatch.setattr(session, "commit", fail_commit)
    try:
        with pytest.raises(CredentialError, match="^Credential authorisation failed$") as error:
            received.append(submit(*credential_ballot))
    finally:
        if failure == "insert":
            event.remove(AnonymousBallot, "before_insert", fail_insert)
    assert generated == [expected]
    assert received == []
    assert observed == ([(True, [])] if failure == "insert" else [(True, 0, 1)])
    assert_state()
    assert expected not in str(retained_snapshot())
    assert expected not in str(error.value)
    assert caplog.records == []
    # Fresh-session retry can succeed; the failed attempt returned nothing.
    assert is_confirmation_reference(submit(*credential_ballot))
    assert_state(True, 1, 0)


def test_random_generation_failure_rolls_back_before_commit(credential_ballot, monkeypatch):
    observed, received = [], []

    def fail_random(nbytes):
        observed.append((
            db.session.execute(select(VotingEligibility.has_voted)).scalar_one(),
            BallotCredential.query.count(), AnonymousBallot.query.count(),
        ))
        raise OSError("private entropy failure")

    monkeypatch.setattr(ballot_confirmation.secrets, "token_urlsafe", fail_random)
    with pytest.raises(CredentialError, match="^Credential authorisation failed$"):
        received.append(submit(*credential_ballot))
    assert received == []
    assert observed == [(True, 0, 1)]
    assert_state()


def test_replay_cannot_return_a_second_confirmation(credential_ballot, monkeypatch):
    generated, received = [], []
    original = ballot_credentials.generate_confirmation_reference

    def generate():
        reference = original()
        generated.append(reference)
        return reference

    monkeypatch.setattr(ballot_credentials, "generate_confirmation_reference", generate)
    reference = submit(*credential_ballot)
    assert generated == [reference]
    with pytest.raises(CredentialError):
        received.append(submit(*credential_ballot))
    assert received == []
    assert generated == [reference]
    assert_state(True, 1, 0)


def test_confirmation_is_not_an_authorisation_or_ballot_lookup(credential_ballot, monkeypatch):
    reference = submit(*credential_ballot)
    received = []

    def forbid_verifier_lookup(data):
        pytest.fail("Confirmation must be rejected by format before credential hashing")

    monkeypatch.setattr(ballot_credentials.crypto, "hash", forbid_verifier_lookup)
    with pytest.raises(CredentialError, match="^Credential authorisation failed$"):
        received.append(submit(reference, credential_ballot[1]))
    assert received == []
    assert_state(True, 1, 0)
    assert db.session.get(AnonymousBallot, reference) is None
    assert reference not in str(retained_snapshot())
