"""SR-08 narrow ballot-domain writer; transaction belongs to the caller."""

import secrets

from ballot_models import AnonymousBallot
from records import db


def store_anonymous_ballot(election_id, electoral_division, encrypted_ballot_json):
    """Stage only ballot-domain data, without identity or credential metadata."""
    db.session.add(AnonymousBallot(
        ballot_id=secrets.token_hex(32),
        election_id=election_id,
        electoral_division=electoral_division,
        encrypted_ballot_json=encrypted_ballot_json,
    ))
