"""
SR-07: Generate the lab test certificates and synthetic demo voter.

Writes the files the gateway and scripts/vote_demo.py need, which are
git-ignored and so never come with a clone:

- nginx/certs/: server.crt, server.key, test-ca.crt
- deploy/secrets/: demo-voter.json, registered_fingerprints.txt
- deploy/secrets/ca/: test-ca.crt and its private key test-ca.key
- deploy/secrets/client/: test-ca.crt, mission-client.crt,
  mission-client.key, demo-voter.json (the --certs folder of vote_demo.py)

Security controls:
- Keys from the cryptography package (ECDSA P-256), passwords and TOTP
  secrets from the secrets module and pyotp (CSPRNG); no openssl CLI
- Test CA: basicConstraints CA:TRUE pathlen 0 and keyUsage
  keyCertSign + cRLSign (both critical), subjectKeyIdentifier
- Server certificate for localhost / 127.0.0.1, serverAuth only;
  client certificate for mission-device-01, clientAuth only
- Certificates are valid for 30 days
- The CA private key stays in deploy/secrets/ca/, never in nginx/certs/
- The registered fingerprint is the SHA-256 of the client certificate
  DER as 64 lowercase hex characters, the format mission_access.py accepts
- Creates only missing files; --force regenerates all of them. A
  missing CA with certificates already signed by the old one is refused
  without --force, so the chain never silently breaks
- Private keys and secrets are written with permission 600 (folders 700)
  where the OS supports it, through a temporary file renamed into place
- Never prints keys, passwords or TOTP secrets; only file names

Local academic prototype. These are test certificates for the lab only.

Usage (from the repository root):
  python deploy/scripts/make_lab_certs.py [--force]
"""

import argparse
import datetime
import ipaddress
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

import pyotp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


REPO_ROOT = Path(__file__).resolve().parents[2]

VALIDITY = datetime.timedelta(days=30)
SERVER_NAME = "localhost"
SERVER_ADDRESS = "127.0.0.1"
CLIENT_NAME = "mission-device-01"
DEMO_ACCOUNT_ID = "demo-voter"

# Paths relative to the repository root.
NGINX_CERTS = Path("nginx") / "certs"
SECRETS = Path("deploy") / "secrets"
CA_DIR = SECRETS / "ca"
CLIENT_DIR = SECRETS / "client"

CA_CERT = CA_DIR / "test-ca.crt"
CA_KEY = CA_DIR / "test-ca.key"
SERVER_CERT = NGINX_CERTS / "server.crt"
SERVER_KEY = NGINX_CERTS / "server.key"
NGINX_CA_CERT = NGINX_CERTS / "test-ca.crt"
CLIENT_CERT = CLIENT_DIR / "mission-client.crt"
CLIENT_KEY = CLIENT_DIR / "mission-client.key"
CLIENT_CA_CERT = CLIENT_DIR / "test-ca.crt"
DEMO_VOTER = SECRETS / "demo-voter.json"
CLIENT_DEMO_VOTER = CLIENT_DIR / "demo-voter.json"
FINGERPRINTS = SECRETS / "registered_fingerprints.txt"

# Files signed by the CA, which a new CA would leave unverifiable.
SIGNED_FILES = (SERVER_CERT, CLIENT_CERT, NGINX_CA_CERT, CLIENT_CA_CERT,
                FINGERPRINTS)


class LabCertError(Exception):
    pass


def _exists(path):
    return path.exists() or path.is_symlink()


def _write(path, data, private):
    if path.is_symlink():
        raise LabCertError(f"Refusing to write {path.name}: symbolic link")

    descriptor, temporary = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}."
    )

    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)

        os.chmod(temporary, 0o600 if private else 0o644)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def _new_key():
    return ec.generate_private_key(ec.SECP256R1())


def _key_pem(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _cert_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def _name(common_name):
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EVP Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def _builder(subject, issuer, public_key):
    now = datetime.datetime.now(datetime.timezone.utc)

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + VALIDITY)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
    )


def _key_usage(**enabled):
    flags = dict.fromkeys((
        "digital_signature", "content_commitment", "key_encipherment",
        "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign",
        "encipher_only", "decipher_only",
    ), False)
    flags.update(enabled)

    return x509.KeyUsage(**flags)


def make_ca():
    key = _new_key()
    name = _name("EVP Lab Test CA")

    cert = (
        _builder(name, name, key.public_key())
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
        .add_extension(
            _key_usage(key_cert_sign=True, crl_sign=True), critical=True
        )
        .sign(key, hashes.SHA256())
    )

    return cert, key


def _make_leaf(ca_cert, ca_key, common_name, usage, extra=()):
    key = _new_key()

    builder = (
        _builder(_name(common_name), ca_cert.subject, key.public_key())
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(usage, critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            ),
            critical=False,
        )
    )

    for extension, critical in extra:
        builder = builder.add_extension(extension, critical=critical)

    return builder.sign(ca_key, hashes.SHA256()), key


def make_server_cert(ca_cert, ca_key):
    return _make_leaf(
        ca_cert, ca_key, SERVER_NAME,
        _key_usage(digital_signature=True, key_encipherment=True),
        extra=(
            (x509.SubjectAlternativeName([
                x509.DNSName(SERVER_NAME),
                x509.IPAddress(ipaddress.ip_address(SERVER_ADDRESS)),
            ]), False),
            (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False),
        ),
    )


def make_client_cert(ca_cert, ca_key):
    return _make_leaf(
        ca_cert, ca_key, CLIENT_NAME,
        _key_usage(digital_signature=True),
        extra=(
            (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False),
        ),
    )


def fingerprint(cert):
    # 64 lowercase hex characters, no colons (mission_access.py).
    return cert.fingerprint(hashes.SHA256()).hex()


def demo_voter_text():
    return json.dumps({
        "account_id": DEMO_ACCOUNT_ID,
        "password": secrets.token_urlsafe(16),
        "totp_secret": pyotp.random_base32(),
    }, indent=2) + "\n"


def _load_pair(root, cert_path, key_path):
    """Return (cert, key) if both files exist, None if neither does."""
    have_cert = _exists(root / cert_path)
    have_key = _exists(root / key_path)

    if not have_cert and not have_key:
        return None

    if have_cert != have_key:
        raise LabCertError(
            f"Only one of {cert_path.as_posix()} and {key_path.as_posix()} "
            "exists; re-run with --force to replace both"
        )

    try:
        cert = x509.load_pem_x509_certificate((root / cert_path).read_bytes())
        key = serialization.load_pem_private_key(
            (root / key_path).read_bytes(), password=None
        )
    except (OSError, ValueError, TypeError):
        raise LabCertError(
            f"Cannot read {cert_path.as_posix()} or {key_path.as_posix()}; "
            "re-run with --force to replace them"
        ) from None

    return cert, key


def make_lab_certs(root=REPO_ROOT, force=False, report=print):
    root = Path(root)

    for folder, mode in ((NGINX_CERTS, 0o755), (SECRETS, 0o700),
                         (CA_DIR, 0o700), (CLIENT_DIR, 0o700)):
        path = root / folder

        if path.is_symlink():
            raise LabCertError(
                f"Refusing to use {folder.as_posix()}: it is a symbolic link"
            )

        path.mkdir(mode=mode, parents=True, exist_ok=True)
        os.chmod(path, mode)

    def needed(path):
        if force or not _exists(root / path):
            return True

        report(f"Kept existing {path.as_posix()}")
        return False

    def write(path, data, private=False):
        _write(root / path, data, private)
        report(f"Wrote {path.as_posix()}")

    # Check before writing anything, so a refusal changes nothing.
    ca = None if force else _load_pair(root, CA_CERT, CA_KEY)
    server = None if force else _load_pair(root, SERVER_CERT, SERVER_KEY)
    client = None if force else _load_pair(root, CLIENT_CERT, CLIENT_KEY)

    if ca is None and not force:
        signed = [p.as_posix() for p in SIGNED_FILES if _exists(root / p)]

        if signed:
            raise LabCertError(
                "The test CA is missing but files from it exist ("
                + ", ".join(signed) + "); re-run with --force to replace all"
            )

    if ca is None:
        ca = make_ca()
        write(CA_KEY, _key_pem(ca[1]), private=True)
        write(CA_CERT, _cert_pem(ca[0]))
    else:
        report(f"Kept existing {CA_CERT.as_posix()} and {CA_KEY.as_posix()}")

    ca_cert, ca_key = ca

    for path in (NGINX_CA_CERT, CLIENT_CA_CERT):
        if needed(path):
            write(path, _cert_pem(ca_cert))

    if server is None:
        cert, key = make_server_cert(ca_cert, ca_key)
        write(SERVER_KEY, _key_pem(key), private=True)
        write(SERVER_CERT, _cert_pem(cert))
    else:
        report(f"Kept existing {SERVER_CERT.as_posix()} and "
               f"{SERVER_KEY.as_posix()}")

    if client is None:
        client = make_client_cert(ca_cert, ca_key)
        write(CLIENT_KEY, _key_pem(client[1]), private=True)
        write(CLIENT_CERT, _cert_pem(client[0]))
    else:
        report(f"Kept existing {CLIENT_CERT.as_posix()} and "
               f"{CLIENT_KEY.as_posix()}")

    if needed(FINGERPRINTS):
        write(FINGERPRINTS, (fingerprint(client[0]) + "\n").encode("ascii"))

    if needed(DEMO_VOTER):
        write(DEMO_VOTER, demo_voter_text().encode("utf-8"), private=True)

    if needed(CLIENT_DEMO_VOTER):
        write(CLIENT_DEMO_VOTER, (root / DEMO_VOTER).read_bytes(),
              private=True)


def main(arguments=None):
    parser = argparse.ArgumentParser(
        description="Generate lab test certificates and the demo voter."
    )
    parser.add_argument("--force", action="store_true",
                        help="regenerate every file, replacing existing ones")
    parser.add_argument("--root", type=Path, default=REPO_ROOT,
                        help=argparse.SUPPRESS)
    options = parser.parse_args(arguments)

    try:
        make_lab_certs(options.root, force=options.force)
    except LabCertError as error:
        print(error, file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
