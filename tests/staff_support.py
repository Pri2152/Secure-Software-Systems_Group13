"""
Shared helpers for the SR-02 staff tests.

Throwaway X.509 client certificates are generated in
memory with `cryptography`; nothing is written to disk.
"""

import datetime

from datetime import timedelta
from urllib.parse import quote

from cachelib import SimpleCache
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from flask import Flask
from flask_session import Session
from flask_wtf.csrf import CSRFProtect

from audit.events import validate_event
from records import db


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


HTTPS_URL = "https://localhost"
GATEWAY_PEER = "127.0.0.1"


class AuditRecorder:
    """
    Fake SR-17 audit target: checks the record_event
    contract and keeps the events in memory.
    """

    def __init__(self):
        self.events = []

    def __call__(self, event_type, *, stream, actor_type, actor_id,
                 outcome, details=None, source_ip=None):
        validate_event(
            event_type, stream, actor_type, actor_id, outcome, source_ip
        )
        self.events.append({
            "event_type": event_type, "stream": stream,
            "actor_type": actor_type, "actor_id": actor_id,
            "outcome": outcome, "details": details or {},
            "source_ip": source_ip,
        })

    def types(self):
        return [event["event_type"] for event in self.events]


def base_app() -> Flask:
    """Flask app configured like Workstream A's (sessions, CSRF, DB)."""

    app = Flask(__name__)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test-only-secret",
        SESSION_TYPE="cachelib",
        SESSION_CACHELIB=SimpleCache(),
        SESSION_PERMANENT=True,
        SESSION_COOKIE_SECURE=True,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=10),
        WTF_CSRF_ENABLED=True,
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )
    Session(app)
    CSRFProtect(app)
    db.init_app(app)

    return app


def csrf_headers(client) -> dict:
    token = client.get("/staff/csrf", base_url=HTTPS_URL).get_json()[
        "csrf_token"
    ]

    return {"X-CSRFToken": token, "Referer": HTTPS_URL + "/staff/csrf"}


def staff_request(client, method, path, payload=None, pem=None,
                  source_ip="203.0.113.10", peer=GATEWAY_PEER):
    """A request as it arrives from the Nginx mTLS gateway."""

    headers = gateway_headers(pem, source_ip)

    if method != "get":
        headers.update(csrf_headers(client))

    return getattr(client, method)(
        path,
        base_url=HTTPS_URL,
        json=payload,
        headers=headers,
        environ_overrides={"REMOTE_ADDR": peer},
    )
