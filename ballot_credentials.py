"""SR-08 identity-side issuance of short-lived ballot authorisation."""

import re
import secrets
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError

from ballot_confirmation import ConfirmationGenerationError, generate_confirmation_reference
from ballot_models import BallotCredential
from ballot_chain import BallotChainError
from ballot_protection import BallotProtectionError
from ballot_service import EligibilityError, get_voting_eligibility
from ballot_service import _claim_eligibility, _validate_ballot
from ballot_storage import store_anonymous_ballot
from crypto_agility import CryptoError, crypto
from records import db


CREDENTIAL_LIFETIME_SECONDS = 600
CREDENTIAL_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")


class CredentialError(Exception):
    """Credential authorisation failed without disclosing identity."""


def utc_now():
    return datetime.now(timezone.utc)


def credential_timestamp(clock=None):
    moment = (clock or utc_now)()
    if not isinstance(moment, datetime) or moment.tzinfo is None:
        raise CredentialError("Credential authorisation failed")
    return moment.timestamp()


def credential_verifier(credential):
    if (
        not isinstance(credential, str)
        or CREDENTIAL_PATTERN.fullmatch(credential) is None
    ):
        raise CredentialError("Credential authorisation failed")
    return crypto.hash(b"evp.ballot-credential.v1\x00" + credential.encode("ascii"))


def issue_ballot_credential(voter_id, election_id, *, clock=None):
    """
    Issue once to an authenticated caller, replacing any previous credential.

    Owns the current session transaction; call without unrelated pending writes.
    The raw bearer credential must not be logged or retained by the caller.
    """
    try:
        get_voting_eligibility(voter_id, election_id)
        credential = secrets.token_urlsafe(32)
        verifier = credential_verifier(credential)
        expires_at = credential_timestamp(clock) + CREDENTIAL_LIFETIME_SECONDS
        db.session.execute(delete(BallotCredential).where(
            BallotCredential.voter_id == voter_id,
            BallotCredential.election_id == election_id,
        ))
        db.session.add(BallotCredential(
            verifier=verifier, voter_id=voter_id, election_id=election_id,
            expires_at=expires_at,
        ))
        db.session.commit()
        return credential
    except (EligibilityError, CredentialError, CryptoError, SQLAlchemyError):
        db.session.rollback()
        raise CredentialError("Credential authorisation failed") from None
    except Exception:
        db.session.rollback()
        raise


def accept_ballot_with_credential(
    credential, candidate_id, encrypted_ballot_json, *, clock=None,
    on_recorded=None,
):
    """
    Accept without caller-supplied identity; commit all three changes together.

    Returns only an ephemeral confirmation after commit; never a ballot ID.
    If on_recorded is given it is called once, after the commit, with the
    record hash (SR-11 tracking code). The hash is a public value on the
    bulletin and says nothing about the choice or the voter.
    Owns the current session transaction.
    """
    try:
        verifier = credential_verifier(credential)
        authorisation = db.session.execute(
            select(BallotCredential).where(BallotCredential.verifier == verifier)
        ).scalar_one_or_none()
        if (
            authorisation is None
            or authorisation.expires_at <= credential_timestamp(clock)
        ):
            raise CredentialError("Credential authorisation failed")

        record = _validate_ballot(
            authorisation.voter_id, authorisation.election_id,
            candidate_id, encrypted_ballot_json,
        )
        _claim_eligibility(record, authorisation.voter_id, authorisation.election_id)
        consumed = db.session.execute(
            delete(BallotCredential).where(
                BallotCredential.verifier == verifier,
                BallotCredential.expires_at > credential_timestamp(clock),
            ).execution_options(synchronize_session=False)
        ).rowcount
        if consumed != 1:
            raise CredentialError("Credential authorisation failed")

        record_hash = store_anonymous_ballot(
            record.election_id, record.electoral_division, encrypted_ballot_json, candidate_id
        )
        confirmation = generate_confirmation_reference()
        db.session.commit()
        if on_recorded is not None:
            on_recorded(record_hash)
        return confirmation
    except (
        EligibilityError, CredentialError, CryptoError, SQLAlchemyError,
        ConfirmationGenerationError,
        BallotProtectionError, BallotChainError,
    ):
        db.session.rollback()
        raise CredentialError("Credential authorisation failed") from None
    except Exception:
        db.session.rollback()
        raise
