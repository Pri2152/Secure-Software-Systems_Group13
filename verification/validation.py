"""
SR-15: Centralised server-side input validation.

Security controls:
- Allow-list of fields for every request (unknown or
  missing fields are rejected)
- Type, length, format and range checks (allow-lists,
  never blocklists)
- Small validators joined in a chain: each check either
  passes the value on or stops the request
- Every failure raises ValidationError; routes return
  one generic 400 and never echo the input

Local academic prototype.
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
ENVELOPE_FIELDS = frozenset(
    {"alg", "kid", "v", "wrapped_key", "nonce", "ct"}
)


class ValidationError(ValueError):
    """Input rejected. The reason is for logs and tests only."""

    def __init__(self, field, reason):
        super().__init__(reason)
        self.field = field
        self.reason = reason


# Building blocks: each check takes a value and returns it,
# or raises ValidationError.

def require_exact_fields(data, allowed, required=None):
    """Only the allowed fields may appear; required ones must."""

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
        # bool is a subclass of int, so test the exact type
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
    """Pass the value through each check in order."""

    for check in checks:
        value = check(value)

    return value


# Validators for the values used by the voting platform.

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
    Sealed ballot envelope (see crypto_agility seal()): exact
    keys, base64 binary fields and size caps. Format only; the
    signature or decryption check happens later.
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
