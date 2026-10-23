"""
SR-11 demo for the video: the verification page in a browser.

Starts the tally service on this computer with test ballots and
development keys (no Docker needed), then open http://127.0.0.1:5055/verify
and paste the token that is printed. Use "Count and publish", then
"Verify latest result".

Run from the project folder:  python scripts/demo_verify_page.py
Test data only. Stop with Ctrl+C.
"""

import sys
import tempfile

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import crypto_agility  # noqa: E402

from ballot_chain import append_ballot  # noqa: E402
from records import db  # noqa: E402
from verification import wsgi  # noqa: E402


ELECTION = "election-2026"
TOKEN = "demo-token-" + "x" * 30
PORT = 5055

BALLOTS = (
    ("Melbourne", 7), ("Melbourne", 8), ("Melbourne", 7), ("Melbourne", 7),
    ("Kooyong", 3), ("Kooyong", 4), ("Kooyong", 3),
)


def main():
    folder = Path(tempfile.mkdtemp(prefix="evp-verify-demo-"))
    (folder / "token").write_text(TOKEN)

    app = wsgi.create_app(
        {
            "EVP_ELECTION_ID": ELECTION,
            "EVP_DIVISIONS": "Melbourne,Kooyong",
            "EVP_TALLY_TOKEN_FILE": str(folder / "token"),
            "EVP_BALLOT_DB_URL": f"sqlite:///{folder / 'ballot.db'}",
            "EVP_AUDIT_DB_URL": f"sqlite:///{folder / 'audit.db'}",
        },
        crypto=crypto_agility.build_service(dev_keys=True),
    )

    with app.app_context():
        db.create_all()
        sample_code = None
        for division, candidate in BALLOTS:
            code = append_ballot(ELECTION, division, "opaque", candidate)
            db.session.commit()
            sample_code = sample_code or code

    print(f"Open  http://127.0.0.1:{PORT}/verify")
    print(f"Token {TOKEN}")
    print(f"Sample tracking code (a test ballot) {sample_code}")
    app.run(host="127.0.0.1", port=PORT)


if __name__ == "__main__":
    main()
