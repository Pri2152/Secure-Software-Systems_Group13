"""SR-08 credential issuance and identity-side constraints."""

from datetime import datetime, timezone

import pytest
from flask import Flask
from sqlalchemy.exc import IntegrityError

import ballot_credentials
import crypto_agility
from ballot_credentials import CredentialError, issue_ballot_credential
from ballot_models import BallotCredential, VotingEligibility
from records import EnrolmentRecord, db


NOW = datetime(2026, 10, 21, tzinfo=timezone.utc)


@pytest.fixture
def credential_app(monkeypatch, ballot_crypto):
    app = Flask(__name__)
    app.config.update(
        TESTING=True, SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )
    db.init_app(app)
    monkeypatch.setattr(ballot_credentials, "crypto", crypto_agility.build_service(dev_keys=True))
    with app.app_context():
        db.create_all()
        seed_voter()
        yield app
        db.session.remove()
        db.drop_all()


def seed_voter(voter_id="voter-001"):
    db.session.add(EnrolmentRecord(
        owner_voter_id=voter_id, enrolment_status="enrolled",
        contact_email="voter@example.test",
    ))
    db.session.add(VotingEligibility(
        voter_id=voter_id, election_id="election-2026",
        electoral_division="Melbourne", state_code="VIC",
    ))
    db.session.commit()


def issue(voter_id="voter-001"):
    return issue_ballot_credential(voter_id, "election-2026", clock=lambda: NOW)


def test_issue_random_credential_stores_only_verifier(credential_app):
    first = issue()
    seed_voter("voter-002")
    second = issue("voter-002")
    assert first != second
    assert len(first) == 43
    assert "voter-001" not in first
    rows = BallotCredential.query.all()
    assert len(rows) == 2
    for row in rows:
        assert row.verifier not in {first, second}
        assert row.expires_at == NOW.timestamp() + 600
        assert first not in str(row.__dict__)
        assert second not in str(row.__dict__)


def test_replacement_invalidates_previous_verifier(credential_app):
    first = issue()
    second = issue()
    assert first != second
    assert BallotCredential.query.count() == 1
    assert db.session.get(BallotCredential, ballot_credentials.credential_verifier(first)) is None
    assert db.session.get(BallotCredential, ballot_credentials.credential_verifier(second)) is not None


def test_database_rejects_two_credentials_per_voter_election(credential_app):
    issue()
    db.session.add(BallotCredential(
        verifier="different-verifier", voter_id="voter-001",
        election_id="election-2026", expires_at=NOW.timestamp() + 600,
    ))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()
    assert BallotCredential.query.count() == 1


@pytest.mark.parametrize("reason", ["missing", "suspended", "removed", "ineligible", "voted", "assignment"])
def test_issuance_revalidates_eligibility(credential_app, reason):
    if reason == "missing":
        db.session.delete(EnrolmentRecord.query.one())
    elif reason in {"suspended", "removed"}:
        EnrolmentRecord.query.one().enrolment_status = reason
    elif reason == "ineligible":
        VotingEligibility.query.one().eligible = False
    elif reason == "voted":
        VotingEligibility.query.one().has_voted = True
    else:
        VotingEligibility.query.one().state_code = "NSW"
    db.session.commit()
    with pytest.raises(CredentialError, match="^Credential authorisation failed$"):
        issue()
    assert BallotCredential.query.count() == 0


def test_crypto_configuration_failure_is_safe(credential_app, monkeypatch):
    from crypto_agility import CryptoNotConfigured

    def fail(data):
        raise CryptoNotConfigured("internal configuration")

    monkeypatch.setattr(ballot_credentials.crypto, "hash", fail)
    with pytest.raises(CredentialError, match="^Credential authorisation failed$"):
        issue()
    assert BallotCredential.query.count() == 0
