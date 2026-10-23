"""SR-08 narrow ballot-domain writer; transaction belongs to the caller."""

from ballot_chain import append_ballot


def store_anonymous_ballot(election_id, electoral_division, encrypted_ballot_json, candidate_id):
    """Protect the validated choice; never receive identity/credential metadata."""
    return append_ballot(election_id, electoral_division, encrypted_ballot_json, candidate_id)
