"""
SR-18: signed result package.

The counted result is signed with the "results" key. The receiver
checks the signature, the election id and the version number, so a
changed, forged or old result is rejected.
"""

import json


RESULT_FIELDS = frozenset(
    {"election_id", "version", "divisions", "ballots_counted"}
)
PACKAGE_FIELDS = frozenset({"result", "signature"})
SIGNING_PURPOSE = "results"


class ResultRejected(ValueError):
    """The result package was not accepted. The reason is for logs."""


def canonical(value):
    """Same bytes every time for the same data. Used for signing."""

    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def build_result(election_id, version, division_counts):
    """Make the result dict from {division: {candidate_id: votes}}."""

    divisions = {
        division: {str(candidate): votes for candidate, votes in counts.items()}
        for division, counts in division_counts.items()
    }

    return {
        "election_id": election_id,
        "version": version,
        "divisions": divisions,
        "ballots_counted": sum(
            votes for counts in divisions.values() for votes in counts.values()
        ),
    }


def sign_result(crypto, result):
    """Return {"result": ..., "signature": ...}."""

    return {
        "result": result,
        "signature": crypto.sign(SIGNING_PURPOSE, canonical(result)),
    }


def _check_shape(package):
    if not isinstance(package, dict) or set(package) != PACKAGE_FIELDS:
        raise ResultRejected("package_fields")

    result = package["result"]

    if not isinstance(result, dict) or set(result) != RESULT_FIELDS:
        raise ResultRejected("result_fields")

    if type(result["version"]) is not int or result["version"] < 1:
        raise ResultRejected("version_type")

    return result


def verify_package(crypto, package, *, election_id, last_version):
    """
    Return the result if everything is fine, else raise ResultRejected.
    Checks: shape, signature, election id, version bigger than last_version.
    """

    result = _check_shape(package)

    if not crypto.verify(SIGNING_PURPOSE, canonical(result), package["signature"]):
        raise ResultRejected("signature")

    if result["election_id"] != election_id:
        raise ResultRejected("election_id")

    if result["version"] <= last_version:
        raise ResultRejected("version_not_newer")

    return result
