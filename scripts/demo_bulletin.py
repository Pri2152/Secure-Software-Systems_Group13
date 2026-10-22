"""
SR-11 demo for the video (one process, no Docker needed).

1. makes a few test ballots,
2. builds and signs the bulletin board,
3. checks it (all PASS),
4. changes one choice and checks again (FAIL).

Run from the project folder:  python scripts/demo_bulletin.py
"""

import copy
import json
import sys

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ballot_chain  # noqa: E402
import ballot_protection  # noqa: E402

from flask import Flask  # noqa: E402

from ballot_chain import append_ballot  # noqa: E402
from crypto_agility import build_service  # noqa: E402
from records import db  # noqa: E402
from verification.bulletin import build_bulletin, verify_bulletin  # noqa: E402


ELECTION = "election-2026"


def show(title, checks):
    print(f"\n{title}")
    for name, passed in checks:
        print(f"  {'PASS' if passed else 'FAIL'}  {name}")


def main():
    crypto = build_service(dev_keys=True)
    ballot_chain.crypto = crypto
    ballot_protection.crypto = crypto

    app = Flask(__name__)
    app.config.update(
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )
    db.init_app(app)

    with app.app_context():
        db.create_all()
        for division, candidate in (
            ("Melbourne", 7), ("Melbourne", 8), ("Melbourne", 7), ("Kooyong", 3),
        ):
            append_ballot(ELECTION, division, "opaque", candidate)
            db.session.commit()

        package = build_bulletin(crypto, ELECTION, ["Melbourne", "Kooyong"], 1)

    print("Published bulletin (first division):")
    print(json.dumps(package["bulletin"]["divisions"][0], indent=2))
    show("Check of the honest bulletin:", verify_bulletin(crypto, package))

    forged = copy.deepcopy(package)
    forged["bulletin"]["divisions"][0]["choices"][0] = 99
    show("Check after one choice was changed:", verify_bulletin(crypto, forged))


if __name__ == "__main__":
    main()
