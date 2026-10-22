"""SR-18: results receiver accepts only signed, current, matching results."""

import pytest

from results_consumer import ResultsState, create_app
from verification.results import build_result, sign_result


ELECTION = "election-2026"


@pytest.fixture
def state():
    return ResultsState()


@pytest.fixture
def client(ballot_crypto, state):
    app = create_app(crypto=ballot_crypto, election_id=ELECTION, state=state)
    return app.test_client()


def signed(crypto, version=1, election=ELECTION, counts=None):
    counts = counts or {"Melbourne": {7: 2, 8: 1}}
    return sign_result(crypto, build_result(election, version, counts))


def test_good_result_is_accepted_and_stored(client, ballot_crypto, state):
    response = client.post("/results", json=signed(ballot_crypto))

    assert response.status_code == 200
    assert response.get_json() == {"status": "accepted", "version": 1}
    assert state.last_version == 1
    assert state.accepted[0]["ballots_counted"] == 3


def test_changed_number_is_rejected(client, ballot_crypto, state):
    package = signed(ballot_crypto)
    package["result"]["divisions"]["Melbourne"]["7"] = 500

    assert client.post("/results", json=package).status_code == 400
    assert state.accepted == []


def test_unsigned_result_is_rejected(client, ballot_crypto):
    package = signed(ballot_crypto)
    del package["signature"]

    assert client.post("/results", json=package).status_code == 400


def test_wrong_election_is_rejected(client, ballot_crypto):
    package = signed(ballot_crypto, election="election-2030")

    assert client.post("/results", json=package).status_code == 400


def test_same_result_sent_again_is_rejected(client, ballot_crypto):
    package = signed(ballot_crypto)

    assert client.post("/results", json=package).status_code == 200
    assert client.post("/results", json=package).status_code == 409


def test_older_version_is_rejected_after_newer(client, ballot_crypto, state):
    assert client.post("/results", json=signed(ballot_crypto, 2)).status_code == 200
    assert client.post("/results", json=signed(ballot_crypto, 1)).status_code == 409
    assert state.last_version == 2


def test_newer_version_is_accepted(client, ballot_crypto):
    assert client.post("/results", json=signed(ballot_crypto, 1)).status_code == 200
    assert client.post("/results", json=signed(ballot_crypto, 2)).status_code == 200


def test_result_signed_by_another_key_is_rejected(client):
    from crypto_agility import build_service

    package = signed(build_service(dev_keys=True))

    assert client.post("/results", json=package).status_code == 400


@pytest.mark.parametrize("body", [b"", b"not json", b"[1]", b"null"])
def test_malformed_body_is_rejected(client, body):
    response = client.post("/results", data=body, content_type="application/json")

    assert response.status_code == 400


def test_non_json_is_rejected(client):
    response = client.post("/results", data="x", content_type="text/plain")

    assert response.status_code == 415


def test_oversize_body_is_rejected(client):
    response = client.post(
        "/results", data=b"{" + b"a" * 70000, content_type="application/json"
    )

    assert response.status_code == 413


def test_rejection_does_not_say_why(client, ballot_crypto):
    package = signed(ballot_crypto)
    package["result"]["version"] = 0

    response = client.post("/results", json=package)

    assert response.get_json() == {"error": "Result rejected"}


def test_responses_have_security_headers(client):
    response = client.post("/results", data="x", content_type="text/plain")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
