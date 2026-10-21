"""SR-08 anonymous interface and one-time authorisation."""

from datetime import timedelta
import secrets

import pytest

from admin.candidates import add_draft_candidate
from ballot_credentials import CredentialError, accept_ballot_with_credential
from ballot_models import AnonymousBallot, BallotCredential, VotingEligibility
from records import EnrolmentRecord, db
from test_ballot_credentials import NOW, credential_app, issue


PAYLOAD = '{"alg":"test","ct":"opaque"}'


@pytest.fixture
def credential_ballot(credential_app):
    candidate = add_draft_candidate(
        db.session, division="Melbourne", name="Candidate A",
        party="Independent", position_in_group=1,
    )
    candidate.status = "FINAL"
    db.session.commit()
    candidate_id = candidate.id
    return issue(), candidate_id


def submit(credential, candidate_id, *, moment=NOW):
    return accept_ballot_with_credential(
        credential, candidate_id, PAYLOAD, clock=lambda: moment
    )


def assert_state(voted=False, ballots=0, credentials=1):
    db.session.remove()
    assert VotingEligibility.query.one().has_voted is voted
    assert AnonymousBallot.query.count() == ballots
    assert BallotCredential.query.count() == credentials


def test_anonymous_acceptance_and_replay(credential_ballot):
    credential, candidate_id = credential_ballot
    assert submit(credential, candidate_id) is None
    assert_state(True, 1, 0)
    with pytest.raises(CredentialError, match="^Credential authorisation failed$"):
        submit(credential, candidate_id)
    assert_state(True, 1, 0)


@pytest.mark.parametrize("credential", [None, "", " ", [], "short", "!" * 43, "a" * 1000])
def test_invalid_credential_fails_closed(credential_ballot, credential):
    with pytest.raises(CredentialError, match="^Credential authorisation failed$"):
        submit(credential, credential_ballot[1])
    assert_state()


def test_unknown_credential(credential_ballot):
    with pytest.raises(CredentialError):
        submit(secrets.token_urlsafe(32), credential_ballot[1])
    assert_state()


@pytest.mark.parametrize("seconds", [600, 601])
def test_expiry_boundary(credential_ballot, seconds):
    with pytest.raises(CredentialError):
        submit(*credential_ballot, moment=NOW + timedelta(seconds=seconds))
    assert_state()


def test_just_before_expiry_is_valid(credential_ballot):
    submit(*credential_ballot, moment=NOW + timedelta(seconds=599))
    assert_state(True, 1, 0)


def test_replacement_cannot_be_used(credential_ballot):
    old, candidate_id = credential_ballot
    replacement = issue()
    with pytest.raises(CredentialError):
        submit(old, candidate_id)
    assert_state()
    submit(replacement, candidate_id)
    assert_state(True, 1, 0)


@pytest.mark.parametrize("reason", ["missing", "removed", "suspended", "ineligible", "voted", "assignment"])
def test_consumption_revalidates_identity(credential_ballot, reason):
    if reason == "missing":
        db.session.delete(EnrolmentRecord.query.one())
    elif reason in {"removed", "suspended"}:
        EnrolmentRecord.query.one().enrolment_status = reason
    elif reason == "ineligible":
        VotingEligibility.query.one().eligible = False
    elif reason == "voted":
        VotingEligibility.query.one().has_voted = True
    else:
        VotingEligibility.query.one().state_code = "NSW"
    db.session.commit()
    with pytest.raises(CredentialError, match="^Credential authorisation failed$"):
        submit(*credential_ballot)
    assert_state(voted=reason == "voted")


@pytest.mark.parametrize("candidate_id", [None, True, "1", 0, -1, 99999])
def test_bad_candidate_preserves_credential(credential_ballot, candidate_id):
    with pytest.raises(CredentialError):
        submit(credential_ballot[0], candidate_id)
    assert_state()


def test_other_division_is_rejected(credential_ballot):
    other = add_draft_candidate(
        db.session, division="Sydney", name="Candidate B",
        party="Independent", position_in_group=1,
    )
    other.status = "FINAL"
    db.session.commit()
    with pytest.raises(CredentialError):
        submit(credential_ballot[0], other.id)
    assert_state()


def test_excluded_candidate_is_rejected(credential_ballot):
    from admin.models import Candidate
    db.session.get(Candidate, credential_ballot[1]).status = "EXCLUDED"
    db.session.commit()
    with pytest.raises(CredentialError):
        submit(*credential_ballot)
    assert_state()


def test_draft_candidate_list_is_rejected(credential_app):
    candidate = add_draft_candidate(
        db.session, division="Melbourne", name="Candidate A",
        party="Independent", position_in_group=1,
    )
    db.session.commit()
    candidate_id = candidate.id
    credential = issue()
    with pytest.raises(CredentialError):
        submit(credential, candidate_id)
    assert_state()
