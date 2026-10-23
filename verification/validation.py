"""
SR-15: one place to check all user input.

- Only known fields are allowed, extra or missing ones are rejected.
- We check type, length and format with allow-lists (no blocklists).
- Small checks run one after another in a chain.
- Any problem raises ValidationError. The route sends a plain 400
  and never sends the input back.
"""

import base64
import binascii
import re


ELECTION_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", re.ASCII)
DIVISION_PATTERN = re.compile(r"[A-Za-z][A-Za-z' -]{1,63}", re.ASCII)
CANDIDATE_NAME_PATTERN = re.compile(r"[A-Za-z][A-Za-z' .-]{1,127}", re.ASCII)
CREDENTIAL_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}", re.ASCII)
CONFIRMATION_PATTERN = re.compile(r"conf_[A-Za-z0-9_-]{32}", re.ASCII)
ENVELOPE_ALGORITHM_PATTERN = re.compile(r"[a-z0-9+._-]{1,64}", re.ASCII)
ENVELOPE_KID_PATTERN = re.compile(r"[A-Za-z0-9:._-]{1,128}", re.ASCII)

MAX_ENVELOPE_FIELD_LENGTH = 16384
ADDRESS_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ,.'/#()-]{0,254}", re.ASCII)
LIMIT_PATTERN = re.compile(r"[0-9]{1,3}", re.ASCII)
STREAM_PATTERN = re.compile(r"[a-z]{1,32}", re.ASCII)
AUDIT_DEFAULT_LIMIT = 50
AUDIT_MAX_LIMIT = 200

CANDIDATE_KEY_PATTERN = re.compile(r"[0-9]{1,10}", re.ASCII)

MAX_DIVISIONS = 200
MAX_CANDIDATES = 1000
RESULT_PACKAGE_FIELDS = frozenset({"result", "signature"})
RESULT_FIELDS = frozenset(
    {"election_id", "version", "divisions", "ballots_counted"}
)
SIGNATURE_FIELDS = frozenset({"alg", "kid", "v", "sig"})

ENVELOPE_FIELDS = frozenset(
    {"alg", "kid", "v", "wrapped_key", "nonce", "ct"}
)


class ValidationError(ValueError):
    """Input rejected. The reason is only for logs and tests."""

    def __init__(self, field, reason):
        super().__init__(reason)
        self.field = field
        self.reason = reason


# Small checks. Each one returns the value or raises ValidationError.

def require_exact_fields(data, allowed, required=None):
    """Only allowed fields can be there, required ones must be there."""

    required = allowed if required is None else required

    if (
        not isinstance(data, dict)
        or not set(data) <= set(allowed)
        or not set(required) <= set(data)
    ):
        raise ValidationError(None, "field_set")

    return data


def check_text(field, *, min_len=1, max_len=255, pattern=None):
    def check(value):
        if not isinstance(value, str):
            raise ValidationError(field, "type")

        if not min_len <= len(value) <= max_len:
            raise ValidationError(field, "length")

        if pattern is not None and pattern.fullmatch(value) is None:
            raise ValidationError(field, "format")

        return value

    return check


def check_int(field, *, minimum=1, maximum=2**31 - 1):
    def check(value):
        # True and False count as int in Python, so check exact type
        if type(value) is not int:
            raise ValidationError(field, "type")

        if not minimum <= value <= maximum:
            raise ValidationError(field, "range")

        return value

    return check


def check_base64(field, *, max_len=MAX_ENVELOPE_FIELD_LENGTH):
    def check(value):
        check_text(field, min_len=1, max_len=max_len)(value)

        try:
            base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raise ValidationError(field, "format") from None

        return value

    return check


def run_chain(value, *checks):
    """Run the value through each check, one by one."""

    for check in checks:
        value = check(value)

    return value


# Checks for the values our voting app uses.

def validate_election_id(value):
    return run_chain(
        value,
        check_text("election_id", max_len=64, pattern=ELECTION_ID_PATTERN),
    )


def validate_division(value):
    return run_chain(
        value,
        check_text("division", max_len=64, pattern=DIVISION_PATTERN),
    )


def validate_candidate_name(value):
    return run_chain(
        value,
        check_text(
            "candidate_name", max_len=128, pattern=CANDIDATE_NAME_PATTERN
        ),
    )


def validate_candidate_id(value):
    return run_chain(value, check_int("candidate_id"))


def validate_credential(value):
    return run_chain(
        value,
        check_text(
            "credential", min_len=43, max_len=43, pattern=CREDENTIAL_PATTERN
        ),
    )


def validate_confirmation_reference(value):
    return run_chain(
        value,
        check_text(
            "confirmation_reference",
            min_len=37,
            max_len=37,
            pattern=CONFIRMATION_PATTERN,
        ),
    )


def validate_ballot_request(data):
    """Body of POST /vote/ballots."""

    require_exact_fields(data, {"credential", "candidate_id"})

    return {
        "credential": validate_credential(data["credential"]),
        "candidate_id": validate_candidate_id(data["candidate_id"]),
    }


def validate_ballot_envelope(data):
    """
    Check a sealed ballot (made by crypto_agility seal()).
    Only the shape: exact keys, base64 fields, size limit.
    Decrypting is done later, not here.
    """

    require_exact_fields(data, ENVELOPE_FIELDS)

    run_chain(
        data["alg"],
        check_text("alg", max_len=64, pattern=ENVELOPE_ALGORITHM_PATTERN),
    )
    run_chain(
        data["kid"],
        check_text("kid", max_len=128, pattern=ENVELOPE_KID_PATTERN),
    )
    run_chain(data["v"], check_int("v", minimum=1, maximum=99))

    for name in ("wrapped_key", "nonce", "ct"):
        check_base64(name)(data[name])

    return data


def validate_result_package(data):
    """
    Check a signed result sent to the results receiver.
    Only the shape and the value formats. The signature, election id
    and version are checked after this by verification/results.py.
    """

    require_exact_fields(data, RESULT_PACKAGE_FIELDS)

    result = require_exact_fields(data["result"], RESULT_FIELDS)

    validate_election_id(result["election_id"])
    run_chain(result["version"], check_int("version"))
    run_chain(
        result["ballots_counted"], check_int("ballots_counted", minimum=0)
    )

    divisions = result["divisions"]

    if not isinstance(divisions, dict) or len(divisions) > MAX_DIVISIONS:
        raise ValidationError("divisions", "shape")

    for division, counts in divisions.items():
        validate_division(division)

        if not isinstance(counts, dict) or len(counts) > MAX_CANDIDATES:
            raise ValidationError("divisions", "shape")

        for candidate, votes in counts.items():
            run_chain(
                candidate,
                check_text(
                    "candidate", max_len=10, pattern=CANDIDATE_KEY_PATTERN
                ),
            )
            run_chain(votes, check_int("votes", minimum=0))

    signature = require_exact_fields(data["signature"], SIGNATURE_FIELDS)

    run_chain(
        signature["alg"],
        check_text("alg", max_len=64, pattern=ENVELOPE_ALGORITHM_PATTERN),
    )
    run_chain(
        signature["kid"],
        check_text("kid", max_len=128, pattern=ENVELOPE_KID_PATTERN),
    )
    run_chain(signature["v"], check_int("v", minimum=1, maximum=99))
    check_base64("sig", max_len=1024)(signature["sig"])

    return data


def validate_audit_query(args, *, streams, allow_limit):
    """
    Query string of the audit read routes, as a plain dict of strings.
    Returns (stream, limit). The stream is needed and must be one of
    streams. The limit is only allowed when allow_limit is true.
    """

    allowed = {"stream", "limit"} if allow_limit else {"stream"}

    require_exact_fields(args, allowed, required={"stream"})

    stream = run_chain(
        args["stream"], check_text("stream", pattern=STREAM_PATTERN)
    )

    if stream not in streams:
        raise ValidationError("stream", "unknown")

    if "limit" not in args:
        return stream, AUDIT_DEFAULT_LIMIT

    limit = int(run_chain(
        args["limit"], check_text("limit", pattern=LIMIT_PATTERN)
    ))

    if not 1 <= limit <= AUDIT_MAX_LIMIT:
        raise ValidationError("limit", "range")

    return stream, limit


def validate_address_update(data):
    """
    Body of PATCH /records/addresses/<id>: only address_text, as plain
    text. Letters, digits, spaces and , . ' / # ( ) - only, up to 255
    characters after trimming. Returns the trimmed address.
    """

    require_exact_fields(data, {"address_text"})

    value = data["address_text"]

    if not isinstance(value, str):
        raise ValidationError("address_text", "type")

    return run_chain(
        value.strip(),
        check_text("address_text", max_len=255, pattern=ADDRESS_PATTERN),
    )
