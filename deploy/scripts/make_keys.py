"""
SR-13 / SR-14 / SR-20: Generate the crypto_agility key folder.

Writes deploy/secrets/keys/ with one key per purpose and
algorithm that the default crypto policy uses, plus the
manifest.json that crypto_agility.keys.KeyStore loads.
Called by make_secrets.sh; not meant to be run directly.

Security controls:
- Symmetric keys from Python's secrets module (CSPRNG);
  key pairs from the cryptography package
- Application keys only (signing, sealing, encryption);
  no TLS certificates are created or changed
- The PII key reuses deploy/secrets/pii_key_v1, and a copy
  that no longer matches it is refused, so data is never
  encrypted under two different "v1" keys
- Existing files are left untouched unless --force is given
- Writes only inside <secrets>/keys/: folder 700, files 600,
  written through a temporary file and renamed into place
- Refuses a symbolic-linked key folder
- Never prints key material; only file names
- A smaller manifest per compartment lists only the keys that
  compartment uses, so it mounts nothing else (SR-20)

Local academic prototype.
"""

import base64
import json
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa


KEY_DIR_NAME = "keys"
MANIFEST_NAME = "manifest.json"
PII_SOURCE_NAME = "pii_key_v1"
PII_KEY_PATTERN = re.compile(r"[0-9a-f]{64}")

# Matches crypto_agility.algorithms (RSA-3072, 256-bit secrets).
RSA_SEAL_KEY_BITS = 3072
SECRET_BYTES = 32


def _pem(private):
    return private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def _hmac_secret():
    return base64.b64encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii")


def _ed25519_pair():
    return _pem(ed25519.Ed25519PrivateKey.generate())


def _rsa_pair():
    return _pem(rsa.generate_private_key(
        public_exponent=65537, key_size=RSA_SEAL_KEY_BITS
    ))


# (kid, purpose, family, alg, file, encoding, generator)
# The PII key has no generator: it is copied from pii_key_v1.
KEYS = (
    ("pii.aes-256-gcm.v1", "pii", "aead", "aes-256-gcm",
     "pii_key_v1", "hex", None),
    ("audit.hmac-sha256.v1", "audit", "mac", "hmac-sha256",
     "audit_hmac_v1", None, _hmac_secret),
    ("audit.ed25519.v1", "audit", "sign", "ed25519",
     "audit_sign_v1", None, _ed25519_pair),
    ("ballot.ed25519.v1", "ballot", "sign", "ed25519",
     "ballot_sign_v1", None, _ed25519_pair),
    # Each ballot record is encrypted under this key (ballot_protection.py).
    ("ballot.aes-256-gcm.v1", "ballot", "aead", "aes-256-gcm",
     "ballot_aead_v1", None, _hmac_secret),
    # Authenticates the hash-linked ballot chain (ballot_chain.py).
    ("ballot-chain.hmac-sha256.v1", "ballot-chain", "mac", "hmac-sha256",
     "ballot_chain_hmac_v1", None, _hmac_secret),
    # Signs the public bulletin board (verification/bulletin.py).
    ("bulletin.ed25519.v1", "bulletin", "sign", "ed25519",
     "bulletin_sign_v1", None, _ed25519_pair),
    ("results.ed25519.v1", "results", "sign", "ed25519",
     "results_sign_v1", None, _ed25519_pair),
    ("election.rsa-oaep-sha256+aes-256-gcm.v1", "election", "seal",
     "rsa-oaep-sha256+aes-256-gcm", "election_seal_v1", None, _rsa_pair),
)


# Keys each compartment mounts, with its own manifest file. The
# compartment mounts that file as manifest.json.
COMPARTMENT_KEYS = {
    "admin-audit": (
        "pii.aes-256-gcm.v1",
        "audit.hmac-sha256.v1",
        "audit.ed25519.v1",
    ),
    # Voter access encrypts contact emails and addresses (SR-13).
    "voter-access": (
        "pii.aes-256-gcm.v1",
    ),
}


def compartment_manifest_name(compartment):
    return f"manifest-{compartment}.json"


class KeySetupError(Exception):
    pass


def manifest_text(kids=None):
    entries = []

    for kid, purpose, family, alg, name, encoding, _ in KEYS:
        if kids is not None and kid not in kids:
            continue

        entry = {
            "kid": kid,
            "purpose": purpose,
            "family": family,
            "alg": alg,
            "file": name,
            "current": True,
        }

        if encoding:
            entry["encoding"] = encoding

        entries.append(entry)

    return json.dumps({"keys": entries}, indent=2) + "\n"


def _exists(path):
    return path.exists() or path.is_symlink()


def _write(path, text):
    descriptor, temporary = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}."
    )

    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(text)

        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def _read_pii_source(secrets_dir):
    try:
        value = (secrets_dir / PII_SOURCE_NAME).read_text("ascii").strip()
    except (OSError, UnicodeDecodeError):
        raise KeySetupError(f"Cannot read {PII_SOURCE_NAME}") from None

    if not PII_KEY_PATTERN.fullmatch(value):
        raise KeySetupError(
            f"{PII_SOURCE_NAME} is not a 256-bit hex key"
        )

    return value


def make_keys(secrets_dir, force=False, report=print):
    secrets_dir = Path(secrets_dir)
    key_dir = secrets_dir / KEY_DIR_NAME

    if key_dir.is_symlink():
        raise KeySetupError(
            "Refusing to use the key folder: it is a symbolic link"
        )

    pii_value = _read_pii_source(secrets_dir)
    pii_copy = key_dir / PII_SOURCE_NAME

    # Check before writing anything, so a refusal changes nothing.
    if not force and _exists(pii_copy):
        try:
            current = pii_copy.read_text("ascii").strip()
        except (OSError, UnicodeDecodeError):
            current = None

        if current != pii_value:
            raise KeySetupError(
                f"keys/{PII_SOURCE_NAME} does not match {PII_SOURCE_NAME}; "
                "re-run with --force to replace both"
            )

    key_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(key_dir, 0o700)

    files = [(name, generator) for *_, name, _, generator in KEYS]
    files.append((MANIFEST_NAME, manifest_text))

    for compartment, kids in COMPARTMENT_KEYS.items():
        files.append((
            compartment_manifest_name(compartment),
            lambda kids=kids: manifest_text(kids),
        ))

    for name, generator in files:
        path = key_dir / name

        if _exists(path) and not force:
            report(f"Kept existing deploy/secrets/{KEY_DIR_NAME}/{name}")
            continue

        text = pii_value + "\n" if generator is None else generator()
        _write(path, text)

        report(f"Wrote deploy/secrets/{KEY_DIR_NAME}/{name}")


def main(arguments):
    if not arguments or arguments[1:] not in ([], ["--force"]):
        print("Usage: make_keys.py <secrets-folder> [--force]",
              file=sys.stderr)
        return 2

    try:
        make_keys(arguments[0], force=arguments[1:] == ["--force"])
    except KeySetupError as error:
        print(error, file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
