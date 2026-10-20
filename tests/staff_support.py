"""
Shared helpers for the SR-02 staff tests.

Throwaway X.509 client certificates are generated in
memory with `cryptography`; nothing is written to disk.
"""

import datetime

from contextlib import contextmanager
from functools import wraps
from datetime import timedelta
from types import SimpleNamespace
from urllib.parse import quote

from cachelib import SimpleCache
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from flask import Flask, jsonify, session
from flask_session import Session
from flask_wtf.csrf import CSRFProtect

from admin import create_staff_account
from admin.elevation import ElevationService
from admin.login import StaffAuthenticator
from admin.routes import create_staff_blueprint
from admin.sessions import StaffSessions
from audit.events import validate_event
from rate_limit import LoginRateLimiter
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


PASSWORD = "Staff-Password-2026!"
START_TIME = 1700000000.0

# name -> (staff_id, full name, role)
PEOPLE = {
    "jane": ("officer-jane-citizen", "Jane Citizen", "officer"),
    "li": ("delegate-li-wei", "Li Wei", "delegate"),
    "grace": ("auditor-grace-hopper", "Grace Hopper", "auditor"),
    "ada": ("admin-ada-lovelace", "Ada Lovelace", "administrator"),
}


def stand_in_has_permission(role, permission):
    return permission in STAFF_ROLE_PERMISSIONS.get(role, set())


def stand_in_require_permission(permission):
    """Same 401/403 behaviour as Workstream E's require_permission."""

    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if session.get("staff_authenticated") is not True:
                return jsonify({"error": "Authentication required"}), 401

            if "authenticated" in session or not stand_in_has_permission(
                session.get("role"), permission
            ):
                return jsonify({"error": "Forbidden"}), 403

            return view(*args, **kwargs)

        wrapper.required_permission = permission

        return wrapper

    return decorator


def rbac_functions():
    """Workstream E's SR-04 functions when available, else stand-ins."""

    try:
        from platform_security.rbac import has_permission, require_permission
    except ImportError:
        return stand_in_require_permission, stand_in_has_permission

    return require_permission, has_permission


def wire_staff(app, recorder, clock) -> SimpleNamespace:
    """Register the staff blueprint with test dependencies."""

    authenticator = StaffAuthenticator(
        db_session=lambda: db.session,
        rate_limiter=LoginRateLimiter(clock=clock),
        audit=recorder,
    )
    sessions = StaffSessions(audit=recorder, clock=clock)
    require_permission, has_permission = rbac_functions()
    elevation = ElevationService(
        db_session=lambda: db.session,
        sessions=sessions,
        require_permission=require_permission,
        has_permission=has_permission,
        audit=recorder,
    )

    app.register_blueprint(create_staff_blueprint(
        authenticator=authenticator, sessions=sessions, elevation=elevation,
    ))

    return SimpleNamespace(
        authenticator=authenticator, sessions=sessions, elevation=elevation,
    )


@contextmanager
def staff_environment():
    """App, client, audit recorder, clock and one account per role."""

    now = [START_TIME]
    recorder = AuditRecorder()
    app = base_app()
    services = wire_staff(app, recorder, lambda: now[0])
    pems = {}

    with app.app_context():
        db.create_all()

        for name, (staff_id, full_name, role) in PEOPLE.items():
            pems[name], fingerprint = make_certificate(full_name)
            create_staff_account(
                db.session, staff_id=staff_id, full_name=full_name,
                role=role, password=PASSWORD, cert_fingerprint=fingerprint,
            )

        db.session.commit()
        db.session.remove()

    # Requests run without a shared app context, so each one
    # gets its own `g` (as in production).
    with app.test_client() as client:
        yield SimpleNamespace(
            app=app, client=client, audit=recorder, clock=now,
            pems=pems, services=services,
        )

    with app.app_context():
        db.drop_all()


def login_as(env, name, password=PASSWORD, pem="own", **kwargs):
    if pem == "own":
        pem = env.pems[name]

    return staff_request(
        env.client, "post", "/staff/login",
        {"staff_id": PEOPLE[name][0], "password": password},
        pem=pem, **kwargs,
    )
