"""
Shared helpers for the SR-02 staff tests.

Throwaway X.509 client certificates are generated in
memory with `cryptography`; nothing is written to disk.
"""

import datetime

from urllib.parse import quote

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def make_certificate(common_name: str):
    """Return (pem_bytes, sha256_hex_fingerprint)."""

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )

    pem = certificate.public_bytes(serialization.Encoding.PEM)

    return pem, certificate.fingerprint(hashes.SHA256()).hex()


def gateway_headers(pem: bytes | None, source_ip="203.0.113.10") -> dict:
    """Headers as Nginx sets them after the mTLS handshake."""

    if pem is None:
        return {
            "X-EVP-Source-IP": source_ip,
            "X-EVP-Client-Verify": "NONE",
        }

    return {
        "X-EVP-Source-IP": source_ip,
        "X-EVP-Client-Verify": "SUCCESS",
        "X-EVP-Client-Cert": quote(pem.decode("ascii")),
    }


# Staff part of Workstream E's SR-04 matrix (docs/RBAC_MATRIX.md)
STAFF_ROLE_PERMISSIONS = {
    "officer": {"roll.propose_bulk", "roll.approve_bulk", "candidates.read"},
    "delegate": {
        "candidates.enter",
        "candidates.propose_finalise",
        "candidates.approve_finalise",
        "candidates.propose_exclusion",
        "candidates.approve_exclusion",
    },
    "auditor": {"audit.read", "audit.verify", "tally.run", "bulletin.publish"},
    "administrator": {"staff.manage", "results.publish", "config.read"},
}
