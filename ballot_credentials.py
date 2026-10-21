"""SR-08 identity-side issuance of short-lived ballot authorisation."""

import re
import secrets
from datetime import datetime, timezone

from sqlalchemy import delete
from sqlalchemy.exc import SQLAlchemyError

from ballot_models import BallotCredential
from ballot_service import EligibilityError, get_voting_eligibility
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
