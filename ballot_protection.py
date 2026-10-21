"""SR-10 canonical authenticated ballot content and metadata binding."""

import json
import re

from crypto_agility import CryptoError, crypto


HASH_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")


class BallotProtectionError(Exception):
    """Ballot protection or authentication failed."""


def canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    )


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def parse_json(value):
    return json.loads(value, object_pairs_hook=_unique_object)


def ballot_metadata(ballot_id, election_id, electoral_division, chain_index, previous_hash):
    if (
        not isinstance(ballot_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", ballot_id) is None
        or not isinstance(election_id, str) or not 1 <= len(election_id) <= 64
        or not isinstance(electoral_division, str) or not 1 <= len(electoral_division) <= 128
        or type(chain_index) is not int or chain_index < 1
        or not isinstance(previous_hash, str)
        or HASH_PATTERN.fullmatch(previous_hash) is None
    ):
        raise BallotProtectionError("Ballot protection failed")
    return dict(
        domain="EVP_BALLOT_V1", ballot_id=ballot_id, election_id=election_id,
        electoral_division=electoral_division, chain_index=chain_index,
        previous_hash=previous_hash,
    )


def protect_ballot(candidate_id, payload, metadata):
    """Caller must pass the candidate that passed trusted final-list validation."""
    try:
        metadata = ballot_metadata(**{k: v for k, v in metadata.items() if k != "domain"})
        if type(candidate_id) is not int or candidate_id <= 0:
            raise ValueError("Invalid choice")
        if not isinstance(payload, str) or not payload.strip() or len(payload) > 65536:
            raise ValueError("Invalid content")
        plaintext = canonical_json(dict(v=1, candidate_id=candidate_id, payload=payload))
        envelope = crypto.encrypt("ballot", plaintext.encode("utf-8"),
                                  aad=canonical_json(metadata).encode("utf-8"))
        return canonical_json(envelope)
    except (CryptoError, ValueError, TypeError):
        raise BallotProtectionError("Ballot protection failed") from None


def _open_ballot(envelope_json, metadata):
    """Internal authentication step; tally must use the full-chain boundary."""
    try:
        metadata = ballot_metadata(**{k: v for k, v in metadata.items() if k != "domain"})
        envelope = parse_json(envelope_json)
        if canonical_json(envelope) != envelope_json:
            raise ValueError("Noncanonical envelope")
        plaintext = crypto.decrypt("ballot", envelope,
                                   aad=canonical_json(metadata).encode("utf-8"))
        content = parse_json(plaintext.decode("utf-8"))
        if (
            not isinstance(content, dict) or set(content) != {"v", "candidate_id", "payload"}
            or type(content["v"]) is not int or content["v"] != 1
            or type(content["candidate_id"]) is not int or content["candidate_id"] <= 0
            or not isinstance(content["payload"], str) or not content["payload"].strip()
            or len(content["payload"]) > 65536
            or canonical_json(content).encode("utf-8") != plaintext
        ):
            raise ValueError("Invalid protected content")
        return content
    except (CryptoError, ValueError, TypeError, KeyError):
        raise BallotProtectionError("Ballot authentication failed") from None
