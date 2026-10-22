"""
SR-13: Encryption-at-rest demonstration (evidence screenshot).

Writes one synthetic voter through Workstream A's models into a
fresh SQLite file, shows what the application reads (plaintext),
then prints the sqlite3 commands that show what is stored
(JSON ciphertext envelopes).

Usage (from the repository root):
    python scripts/demo_encryption_at_rest.py /tmp/evp-demo.db

Security controls:
- Real keys from deploy/secrets/keys (EVP_KEY_DIR), registered
  exactly as the voter-access start-up does; development keys
  are never used, and missing keys stop the demo (fail closed)
- Synthetic data only; the database file must be new and outside
  the repository, so it can never be committed
- Never prints key material; only the key ID (version)

Local academic prototype.
"""

import os
import shlex
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from platform_security.crypto_setup import install_pii_provider  # noqa: E402
from platform_security.field_crypto import (  # noqa: E402
    CryptoProviderNotConfigured,
    set_crypto_provider,
)
from records import AddressRecord, EnrolmentRecord, db  # noqa: E402


DEFAULT_KEY_DIR = REPO_ROOT / "deploy" / "secrets" / "keys"

DEMO_VOTER = "demo-voter-001"
DEMO_EMAIL = "demo.voter@example.test"
DEMO_ADDRESS = "1 Synthetic Lane, Testville VIC 3999"


class DemoError(Exception):
    pass


def check_database_path(argument):
    path = Path(argument).expanduser().resolve()

    if path == REPO_ROOT or REPO_ROOT in path.parents:
        raise DemoError(
            "Choose a database path outside the repository, "
            "for example /tmp/evp-demo.db"
        )

    if path.exists() or path.is_symlink():
        raise DemoError(f"{path} already exists; choose a new file")

    if not path.parent.is_dir():
        raise DemoError(f"Folder {path.parent} does not exist")

    return path


def sqlite_commands(path):
    quoted = shlex.quote(str(path))

    return [
        f'sqlite3 {quoted} "SELECT id, owner_voter_id, contact_email '
        f'FROM enrolment_records;"',
        f'sqlite3 {quoted} "SELECT id, owner_voter_id, address_text '
        f'FROM address_records;"',
    ]


def run(argument, environ=os.environ, report=print):
    path = check_database_path(argument)

    # Real keys only, as voter-access loads them.
    settings = {
        "EVP_KEY_DIR": environ.get("EVP_KEY_DIR") or str(DEFAULT_KEY_DIR),
    }

    try:
        service = install_pii_provider(settings)
    except CryptoProviderNotConfigured:
        raise DemoError(
            f"No usable PII key in {settings['EVP_KEY_DIR']}; "
            "run bash deploy/scripts/make_secrets.sh first"
        ) from None

    engine = create_engine(f"sqlite:///{path}")

    try:
        db.metadata.create_all(
            engine,
            tables=[EnrolmentRecord.__table__, AddressRecord.__table__],
        )

        with Session(engine) as session:
            session.add_all([
                EnrolmentRecord(id=1, owner_voter_id=DEMO_VOTER,
                                enrolment_status="enrolled",
                                contact_email=DEMO_EMAIL),
                AddressRecord(id=1, owner_voter_id=DEMO_VOTER,
                              address_text=DEMO_ADDRESS),
            ])
            session.commit()

        with Session(engine) as session:
            enrolment = session.get(EnrolmentRecord, 1)
            address = session.get(AddressRecord, 1)

            report("SR-13 encryption at rest: what the application sees "
                   "(ORM read, decrypted)")
            report(f"  database       {path}")
            report(f"  key ID         {current_kid(service)}")
            report(f"  voter          {enrolment.owner_voter_id}")
            report(f"  contact_email  {enrolment.contact_email}")
            report(f"  address_text   {address.address_text}")
    finally:
        engine.dispose()
        set_crypto_provider(None)

    report("")
    report("What is stored: run these commands to see the raw columns")
    for command in sqlite_commands(path):
        report(f"  {command}")

    return path


def current_kid(service):
    from crypto_agility.algorithms import AEAD

    return service.keys.current("pii", service.factory.for_new(AEAD)).kid


def main(arguments=None):
    arguments = sys.argv[1:] if arguments is None else arguments

    if len(arguments) != 1:
        print("Usage: python scripts/demo_encryption_at_rest.py "
              "<new-sqlite-file-outside-the-repo>", file=sys.stderr)
        return 2

    try:
        run(arguments[0])
    except DemoError as error:
        print(error, file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
