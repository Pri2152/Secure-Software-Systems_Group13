"""SR-15: the results receiver checks input format before the signature."""

import logging

import pytest

from results_consumer import ResultsState, create_app
from verification.results import build_result, sign_result


ELECTION = "election-2026"
ATTACKS = [
    "' OR '1'='1",
    "<script>alert(1)</script>",
    "{{7*7}}",
    "../../etc/passwd",
    "A" * 5000,
]


@pytest.fixture
def state():
    return ResultsState()


@pytest.fixture
def client(ballot_crypto, state):
    app = create_app(crypto=ballot_crypto, election_id=ELECTION, state=state)
    return app.test_client()


@pytest.fixture
def package(ballot_crypto):
    return sign_result(
        ballot_crypto, build_result(ELECTION, 1, {"Melbourne": {7: 2, 8: 1}})
    )


def test_good_signed_result_still_passes_validation(client, package, state):
    assert client.post("/results", json=package).status_code == 200
    assert state.last_version == 1


@pytest.mark.parametrize("attack", ATTACKS)
def test_attack_text_in_a_division_name_is_refused_before_the_signature(
    client, package, state, attack
):
    package["result"]["divisions"][attack] = {"7": 1}

    response = client.post("/results", json=package)

    assert response.status_code == 400
    assert response.get_json() == {"error": "Result rejected"}
    assert state.last_version == 0


@pytest.mark.parametrize("attack", ATTACKS)
def test_attack_text_in_the_election_id_is_refused(client, package, attack):
    package["result"]["election_id"] = attack

    assert client.post("/results", json=package).status_code == 400


def test_the_input_is_never_sent_back(client, package):
    package["result"]["election_id"] = "<script>alert(1)</script>"

    response = client.post("/results", json=package)

    assert b"script" not in response.data
    assert b"alert" not in response.data


def test_the_reason_is_logged_without_the_input(client, package, caplog):
    package["result"]["election_id"] = "<script>alert(1)</script>"

    with caplog.at_level(logging.WARNING, logger="evp.results_consumer"):
        client.post("/results", json=package)

    assert "result_invalid field=election_id" in caplog.text
    assert "alert" not in caplog.text


def test_oversized_counts_are_refused(client, package):
    package["result"]["divisions"]["Melbourne"] = {
        str(i): 1 for i in range(1001)
    }

    assert client.post("/results", json=package).status_code == 400


def test_not_json_object_is_refused(client):
    for body in ("[]", "7", "null", '"text"'):
        response = client.post(
            "/results", data=body, content_type="application/json"
        )

        assert response.status_code == 400
