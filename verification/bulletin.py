"""
SR-11: public bulletin board and independent check.

After the polls close we publish, for every division:
- the hash of every stored ballot record (in chain order),
- the choices in RANDOM order, so nobody can match a choice to a record,
- the counts.
All of it is signed. Anyone can recount the choices and compare.
"""

import hashlib
import secrets

from sqlalchemy import select

from ballot_models import AnonymousBallot
from records import db
from verification.results import (
    ResultRejected,
    build_result,
    canonical,
    sign_result,
    verify_package,
)
from verification.tally import verified_choices


SIGNING_PURPOSE = "bulletin"


def commitment_for(record_hashes_by_division):
    """One hash over all published record hashes."""

    digest = hashlib.sha256(canonical(record_hashes_by_division)).hexdigest()

    return "sha256:" + digest


def _record_hashes(election_id, division):
    rows = db.session.execute(
        select(AnonymousBallot.record_hash)
        .where(
            AnonymousBallot.election_id == election_id,
            AnonymousBallot.electoral_division == division,
        )
        .order_by(AnonymousBallot.chain_index)
    ).scalars()

    return list(rows)


def build_bulletin(crypto, election_id, divisions, version, *, rng=None):
    """
    Return {"bulletin": ..., "signature": ..., "result": signed result}.
    Raises TallyRefused if any division fails the integrity check.
    """

    rng = rng or secrets.SystemRandom()
    entries, hashes, counts = [], {}, {}

    for division in sorted(divisions):
        choices = list(verified_choices(election_id, division))
        record_hashes = _record_hashes(election_id, division)
        rng.shuffle(choices)                 # no link to chain order

        division_counts = {}
        for choice in choices:
            division_counts[choice] = division_counts.get(choice, 0) + 1

        hashes[division] = record_hashes
        counts[division] = dict(sorted(division_counts.items()))
        entries.append({
            "division": division,
            "ballot_count": len(record_hashes),
            "record_hashes": record_hashes,
            "choices": choices,
        })

    body = {
        "election_id": election_id,
        "version": version,
        "divisions": entries,
        "commitment": commitment_for(hashes),
    }

    return {
        "bulletin": body,
        "signature": crypto.sign(SIGNING_PURPOSE, canonical(body)),
        "result": sign_result(crypto, build_result(election_id, version, counts)),
    }


def verify_bulletin(crypto, package):
    """
    Check a published bulletin. Returns a list of (check name, passed).
    Never raises on bad input, it just fails the checks.
    """

    checks = []

    def record(name, passed):
        checks.append((name, bool(passed)))

    try:
        body = package["bulletin"]
        entries = body["divisions"]
        hashes = {e["division"]: e["record_hashes"] for e in entries}

        record(
            "bulletin signature is valid",
            crypto.verify(SIGNING_PURPOSE, canonical(body), package["signature"]),
        )
        record(
            "commitment matches the record hashes",
            body["commitment"] == commitment_for(hashes),
        )
        record(
            "ballot counts match the lists",
            all(
                e["ballot_count"] == len(e["record_hashes"]) == len(e["choices"])
                for e in entries
            ),
        )

        recount = {}
        for entry in entries:
            division_counts = {}
            for choice in entry["choices"]:
                key = str(choice)
                division_counts[key] = division_counts.get(key, 0) + 1
            recount[entry["division"]] = division_counts

        signed = verify_package(
            crypto,
            package["result"],
            election_id=body["election_id"],
            last_version=0,
        )
        record("signed result is valid", True)
        record(
            "recount of the choices equals the signed result",
            signed["divisions"] == recount
            and signed["version"] == body["version"],
        )
        record(
            "total equals the number of records",
            signed["ballots_counted"] == sum(len(h) for h in hashes.values()),
        )
    except ResultRejected:
        record("signed result is valid", False)
    except (KeyError, TypeError, AttributeError):
        record("bulletin has the right shape", False)

    return checks


def all_passed(checks):
    return bool(checks) and all(passed for _, passed in checks)
