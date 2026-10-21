"""
SR-13 / SR-14: Rotate the PII field-encryption key.

Re-encrypts every EncryptedText('pii') value in the identity
database under a new key version (for example pii_key_v2),
through Workstream B's crypto_agility service.

Usage (from the repository root, with the voter-access and
admin-audit services stopped):

    EVP_IDENTITY_DB_URL=... python deploy/scripts/rotate_pii_key.py \\
        [--key-dir deploy/secrets/keys] [--generate-new-key] \\
        [--batch-size 100] [--dry-run]

The database URL comes from the environment only, so its
password never appears on a command line or in shell history.

Steps:
1. Load the current keys and the new key version, and make the
   new version the default for purpose 'pii' in a crypto service
2. List the new key in every manifest that holds a PII key, as
   NOT current, so both versions can decrypt from now on
3. Decrypt each row with its own (old) key and re-encrypt it
   with the new one, in batches, one transaction per batch
4. Check every row has the new key ID and decrypts with a
   service that holds only the new key
5. Only then make the new key current in the manifests; the
   old key stays listed (it can be retired later)
6. Record KEY_ROTATED in the admin audit stream if available

Security controls:
- Fails safe: a failure at any point leaves every row readable,
  because both key versions are listed before any row changes
  and each batch commits or rolls back as a whole
- A row is only replaced if it still holds the value that was
  decrypted (no lost concurrent update)
- The old key is never removed by this script
- Key files: hex, 256-bit, distinct from older versions;
  written 600 and manifests replaced atomically
- --dry-run checks every row decrypts and reports the count,
  without writing anything
- Never prints keys, plaintext or ciphertext

Local academic prototype.
"""

import argparse
import json
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import Text, create_engine, select, type_coerce, update  # noqa: E402

from crypto_agility import CryptoService, build_service  # noqa: E402
from crypto_agility.algorithms import AEAD, KeyMaterial  # noqa: E402
from crypto_agility.keys import KeyStore, make_kid, parse_kid  # noqa: E402
from crypto_agility.policy import DEFAULT_POLICY  # noqa: E402
from crypto_agility.registry import default_registry  # noqa: E402
from platform_security.field_crypto import EncryptedText  # noqa: E402
from records import db  # noqa: E402


PURPOSE = "pii"
DB_URL_VARIABLE = "EVP_IDENTITY_DB_URL"
KEY_PATTERN = re.compile(r"[0-9a-f]{64}")
DEFAULT_KEY_DIR = REPO_ROOT / "deploy" / "secrets" / "keys"


class RotationError(Exception):
    pass


# Columns

def encrypted_columns(metadata=db.metadata, purpose=PURPOSE):
    """Every (table, primary key, column) stored as EncryptedText(purpose)."""

    found = []

    for table in metadata.sorted_tables:
        for column in table.columns:
            if (
                isinstance(column.type, EncryptedText)
                and column.type.purpose == purpose
            ):
                keys = list(table.primary_key.columns)

                if len(keys) != 1:
                    raise RotationError(
                        f"{table.name} needs a single-column primary key"
                    )

                found.append((table, keys[0], column))

    return found


def raw_rows(connection, table, key, column, after=None, limit=None):
    """(id, stored text) pairs, read without decrypting."""

    statement = (
        select(key, type_coerce(column, Text))
        .where(column.isnot(None))
        .order_by(key)
    )

    if after is not None:
        statement = statement.where(key > after)
    if limit is not None:
        statement = statement.limit(limit)

    return connection.execute(statement).all()


# Keys and manifests

def pii_entries(manifest):
    return [entry for entry in manifest["keys"] if entry["purpose"] == PURPOSE]


def read_manifest(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_private(path, text):
    descriptor, temporary = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}."
    )

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)

        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def pii_manifests(key_dir):
    """manifest.json and every compartment manifest that holds a PII key."""

    paths = [key_dir / "manifest.json", *sorted(key_dir.glob("manifest-*.json"))]

    return [path for path in paths if path.is_file()
            and pii_entries(read_manifest(path))]


def plan_new_key(key_dir):
    """(kid, version, file name, algorithm entry) for the next PII version."""

    entries = pii_entries(read_manifest(key_dir / "manifest.json"))

    if not entries:
        raise RotationError("manifest.json has no PII key")

    current = [entry for entry in entries if entry["current"]]

    if len(current) != 1:
        raise RotationError("manifest.json needs exactly one current PII key")

    alg = current[0]["alg"]
    version = 1 + max(parse_kid(entry["kid"])[2] for entry in entries
                      if entry["alg"] == alg)

    # Resume an interrupted rotation: reuse a listed, non-current key.
    pending = [entry for entry in entries if not entry["current"]
               and entry["alg"] == alg]
    if pending:
        newest = max(pending, key=lambda entry: parse_kid(entry["kid"])[2])
        if parse_kid(newest["kid"])[2] > parse_kid(current[0]["kid"])[2]:
            return newest["kid"], parse_kid(newest["kid"])[2], newest["file"], alg

    return make_kid(PURPOSE, alg, version), version, f"pii_key_v{version}", alg


def load_new_key(key_dir, name, generate, dry_run):
    path = key_dir / name

    if not path.exists():
        if not generate:
            raise RotationError(
                f"{name} does not exist; create it or use --generate-new-key"
            )
        if dry_run:
            return None

        write_private(path, secrets.token_hex(32) + "\n")
        print(f"Wrote {name}")

    value = path.read_text(encoding="ascii").strip()

    if not KEY_PATTERN.fullmatch(value):
        raise RotationError(f"{name} is not a 256-bit hex key")

    for entry in pii_entries(read_manifest(key_dir / "manifest.json")):
        if entry["file"] == name:
            continue
        old = (key_dir / entry["file"]).read_text(encoding="ascii").strip()
        if old == value:
            raise RotationError(f"{name} repeats an older PII key")

    return bytes.fromhex(value)


def new_key_service(secret, version):
    """A crypto service whose only, default PII key is the new one."""

    registry = default_registry()
    service = CryptoService(registry, DEFAULT_POLICY, KeyStore())
    algorithm = service.factory.for_new(AEAD)
    service.keys.add(
        PURPOSE, algorithm, KeyMaterial(secret=secret), version, current=True
    )

    return service


def list_new_key(key_dir, kid, name, alg, current):
    """
    Add the new key to every PII manifest. current=False lists it
    for decryption only; current=True makes it the default.
    """

    for path in pii_manifests(key_dir):
        manifest = read_manifest(path)
        entries = manifest["keys"]

        if not any(entry["kid"] == kid for entry in entries):
            entries.append({
                "kid": kid, "purpose": PURPOSE, "family": "aead",
                "alg": alg, "file": name, "encoding": "hex",
                "current": False,
            })

        if current:
            for entry in entries:
                if entry["purpose"] == PURPOSE and entry["alg"] == alg:
                    entry["current"] = entry["kid"] == kid

        write_private(path, json.dumps(manifest, indent=2) + "\n")


# Rotation

def count_and_check(engine, old_service, columns):
    """Every stored value decrypts with the current keys."""

    total = 0

    with engine.connect() as connection:
        for table, key, column in columns:
            for _, stored in raw_rows(connection, table, key, column):
                old_service.decrypt(PURPOSE, json.loads(stored))
                total += 1

    return total


def reencrypt(engine, old_service, new_service, new_kid, columns, batch_size):
    changed = 0

    for table, key, column in columns:
        last = None

        while True:
            with engine.begin() as connection:
                batch = raw_rows(connection, table, key, column,
                                 after=last, limit=batch_size)

                for row_id, stored in batch:
                    envelope = json.loads(stored)

                    if envelope.get("kid") != new_kid:
                        plaintext = old_service.decrypt(PURPOSE, envelope)
                        replacement = json.dumps(
                            new_service.encrypt(PURPOSE, plaintext),
                            sort_keys=True, separators=(",", ":"),
                        )
                        result = connection.execute(
                            update(table)
                            .where(key == row_id)
                            .where(type_coerce(column, Text) == stored)
                            .values({column.name: type_coerce(replacement, Text)})
                        )

                        if result.rowcount != 1:
                            raise RotationError(
                                f"{table.name} row changed during rotation"
                            )

                        changed += 1

            if len(batch) < batch_size:
                break

            last = batch[-1][0]

    return changed


def verify(engine, new_service, new_kid, columns):
    """Every row has the new key ID and decrypts with only the new key."""

    checked = 0

    with engine.connect() as connection:
        for table, key, column in columns:
            for row_id, stored in raw_rows(connection, table, key, column):
                envelope = json.loads(stored)

                if envelope.get("kid") != new_kid:
                    raise RotationError(f"{table.name} row still uses an old key")

                new_service.decrypt(PURPOSE, envelope)
                checked += 1

    return checked


def default_record_event():
    try:
        import audit
    except ImportError:
        return None

    if not os.environ.get(audit.ENV_AUDIT_DB_URL):
        return None

    return audit.record_event


def rotate(engine, key_dir, *, batch_size=100, dry_run=False,
           generate=False, record_event=None, columns=None, report=print):
    key_dir = Path(key_dir)
    columns = encrypted_columns() if columns is None else columns

    if batch_size < 1:
        raise RotationError("--batch-size must be at least 1")

    kid, version, name, alg = plan_new_key(key_dir)
    secret = load_new_key(key_dir, name, generate, dry_run)
    old_service = build_service(key_dir=str(key_dir))

    total = count_and_check(engine, old_service, columns)

    if dry_run:
        report(f"Dry run: {total} encrypted values decrypt with the current "
               f"keys and would be re-encrypted under {kid}. Nothing changed.")
        return {"rows": total, "kid": kid, "dry_run": True}

    new_service = new_key_service(secret, version)

    # Both versions readable before any row changes.
    list_new_key(key_dir, kid, name, alg, current=False)
    old_service = build_service(key_dir=str(key_dir))

    changed = reencrypt(engine, old_service, new_service, kid, columns,
                        batch_size)
    checked = verify(engine, new_service, kid, columns)

    list_new_key(key_dir, kid, name, alg, current=True)

    report(f"Re-encrypted {changed} values; all {checked} decrypt with {kid}.")
    report("The old key is still listed. Restart the services so they use "
           f"{kid}, and mount {name} for them (deploy/README.md).")

    if record_event is not None:
        record_event(
            "KEY_ROTATED",
            stream="admin",
            actor_type="system",
            actor_id="rotate_pii_key",
            outcome="success",
            details={"purpose": PURPOSE, "new_version": version,
                     "values": checked},
        )
        report("Recorded KEY_ROTATED in the admin audit stream.")
    else:
        report("Audit log not configured: KEY_ROTATED was not recorded.")

    return {"rows": checked, "changed": changed, "kid": kid, "dry_run": False}


def main(arguments=None):
    parser = argparse.ArgumentParser(description="Rotate the PII key (SR-13).")
    parser.add_argument("--key-dir", default=str(DEFAULT_KEY_DIR))
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--generate-new-key", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    options = parser.parse_args(arguments)

    url = os.environ.get(DB_URL_VARIABLE)

    if not url:
        print(f"Set {DB_URL_VARIABLE} to the identity database URL",
              file=sys.stderr)
        return 2

    try:
        rotate(
            create_engine(url, hide_parameters=True),
            options.key_dir,
            batch_size=options.batch_size,
            dry_run=options.dry_run,
            generate=options.generate_new_key,
            record_event=default_record_event(),
        )
    except Exception as error:
        # RotationError messages hold no data; for anything else
        # report only the type, never values from the database.
        reason = (str(error) if isinstance(error, RotationError)
                  else type(error).__name__)
        print(f"Rotation stopped: {reason}. Every row is still readable "
              "with the keys listed in the manifests; fix the cause and "
              "run the script again to continue.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
