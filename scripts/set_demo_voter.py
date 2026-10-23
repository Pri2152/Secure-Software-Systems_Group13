"""
Lab demo: make your own demo voter, with a code from your phone.

Run this before the presentation, not during it. It writes the demo voter
file (account ID, password, TOTP secret) and shows a QR code. Scan the QR
code with an authenticator app (Google Authenticator, Microsoft
Authenticator, Authy) and the app then shows the 6-digit sign-in code, like
a real bank login.

Usage (from the project folder, with the venv active):
  python scripts/set_demo_voter.py --account priyanka
  docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.voting-demo.yml \
      up -d --force-recreate voter-access-1 voter-access-2

Then sign in at https://localhost:8443/signin with that account, the
password you typed here and the code from your phone.

Notes:
- The password is typed at a hidden prompt and is never printed.
- The file holds the password and the TOTP secret in plain text, so it is
  written with permission 600 and git ignores deploy/secrets/. Never commit it.
- The gateway reads one demo voter. This replaces the old one.
- For the QR code: pip install qrcode (not needed otherwise; the setup key
  is also printed so it can be typed into the app).

Local academic prototype. Test data only.
"""

import argparse
import getpass
import json
import os
import re
import sys

from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pyotp  # noqa: E402

from verification.validation import ACCOUNT_ID_PATTERN  # noqa: E402


DEFAULT_FILE = Path(__file__).resolve().parent.parent / "deploy" / "secrets" / "demo-voter.json"
ISSUER = "Electronic Voting Platform"
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128


class DemoVoterError(ValueError):
    """The account name or password is not acceptable."""


def check_account(account):
    if ACCOUNT_ID_PATTERN.fullmatch(account) is None:
        raise DemoVoterError(
            "Account: letters, digits and . _ @ - only, starting with a letter or digit"
        )

    return account.casefold()


def check_password(password):
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise DemoVoterError(
            f"Password must be {MIN_PASSWORD_LENGTH} to {MAX_PASSWORD_LENGTH} characters"
        )

    return password


def make_voter(account, password, secret=None):
    """The data for the demo voter file."""

    return {
        "account_id": check_account(account),
        "password": check_password(password),
        "totp_secret": secret or pyotp.random_base32(),
    }


def provisioning_uri(voter):
    return pyotp.TOTP(voter["totp_secret"]).provisioning_uri(
        name=voter["account_id"], issuer_name=ISSUER
    )


def write_voter(voter, path):
    """Write in place (keeps the file Docker already mounts), mode 600."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(voter, handle)
        handle.write("\n")

    os.chmod(path, 0o600)


def show_qr(uri):
    try:
        import qrcode
    except ImportError:
        print("(For a QR code run: pip install qrcode   Otherwise type the setup key.)")
        return

    code = qrcode.QRCode(border=1)
    code.add_data(uri)
    code.make(fit=True)
    code.print_ascii(invert=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--account", required=True, help="your demo account name")
    parser.add_argument("--out", action="append", default=None,
                        help="file to write (repeat for more; default deploy/secrets/demo-voter.json)")
    options = parser.parse_args(argv)

    try:
        account = check_account(options.account)
        password = getpass.getpass("Choose a password (hidden): ")
        if password != getpass.getpass("Type it again: "):
            raise DemoVoterError("The two passwords differ")
        voter = make_voter(account, password)
    except DemoVoterError as problem:
        print(f"Not saved. {problem}")
        return 1

    for target in options.out or [DEFAULT_FILE]:
        write_voter(voter, target)
        print(f"Wrote {target}")

    uri = provisioning_uri(voter)
    print("\nScan this with your authenticator app:\n")
    show_qr(uri)
    print(f"\nOr add it by hand. Account: {voter['account_id']}   Setup key: {voter['totp_secret']}")
    print("Type of key: time-based. Then recreate the voter containers (see the top of this file).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
