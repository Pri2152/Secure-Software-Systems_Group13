"""SR-18: result package is signed and checked."""

import copy

import pytest

from verification.results import (
    ResultRejected,
    build_result,
    canonical,
    sign_result,
    verify_package,
)


@pytest.fixture
def package(ballot_crypto):
    result = build_result(
        "election-2026", 1, {"Melbourne": {7: 2, 8: 1}, "Kooyong": {3: 2}}
    )
    return sign_result(ballot_crypto, result)


def check(crypto, package, **changes):
    arguments = {"election_id": "election-2026", "last_version": 0}
    arguments.update(changes)
    return verify_package(crypto, package, **arguments)


def test_result_counts_all_ballots():
    result = build_result("e", 1, {"A": {1: 2}, "B": {2: 3, 3: 1}})

    assert result["ballots_counted"] == 6
    assert result["divisions"]["B"] == {"2": 3, "3": 1}


def test_good_package_is_accepted(ballot_crypto, package):
    assert check(ballot_crypto, package)["version"] == 1


def test_changed_vote_count_is_rejected(ballot_crypto, package):
    package["result"]["divisions"]["Melbourne"]["7"] = 99

    with pytest.raises(ResultRejected, match="signature"):
        check(ballot_crypto, package)


def test_changed_total_is_rejected(ballot_crypto, package):
    package["result"]["ballots_counted"] += 1

    with pytest.raises(ResultRejected, match="signature"):
        check(ballot_crypto, package)


def test_unsigned_package_is_rejected(ballot_crypto, package):
    del package["signature"]

    with pytest.raises(ResultRejected, match="package_fields"):
        check(ballot_crypto, package)


def test_empty_signature_is_rejected(ballot_crypto, package):
    package["signature"] = {}

    with pytest.raises(ResultRejected, match="signature"):
        check(ballot_crypto, package)


def test_other_election_is_rejected(ballot_crypto, package):
    with pytest.raises(ResultRejected, match="election_id"):
        check(ballot_crypto, package, election_id="election-2030")


@pytest.mark.parametrize("last_version", [1, 2, 50])
def test_old_or_same_version_is_rejected(ballot_crypto, package, last_version):
    with pytest.raises(ResultRejected, match="version_not_newer"):
        check(ballot_crypto, package, last_version=last_version)


def test_extra_field_is_rejected(ballot_crypto, package):
    package["result"]["note"] = "hello"

    with pytest.raises(ResultRejected, match="result_fields"):
        check(ballot_crypto, package)


@pytest.mark.parametrize("junk", [None, [], "text", 5, {}])
def test_junk_is_rejected(ballot_crypto, junk):
    with pytest.raises(ResultRejected):
        check(ballot_crypto, junk)


def test_signature_from_another_key_is_rejected(ballot_crypto, package):
    from crypto_agility import build_service

    other = build_service(dev_keys=True)

    with pytest.raises(ResultRejected, match="signature"):
        check(other, package)


def test_signed_bytes_do_not_depend_on_key_order():
    one = {"a": 1, "b": {"y": 1, "x": 2}}
    two = {"b": {"x": 2, "y": 1}, "a": 1}

    assert canonical(one) == canonical(two)


def test_signing_does_not_change_the_result(ballot_crypto):
    result = build_result("election-2026", 1, {"A": {1: 1}})
    before = copy.deepcopy(result)

    sign_result(ballot_crypto, result)

    assert result == before
