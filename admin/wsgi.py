"""
SR-20: admin-audit compartment entrypoint (Workstream B).

Gunicorn target: admin.wsgi:app (deploy/ENTRYPOINTS.md)

Security controls:
- Registers only Workstream B's routes: staff login and
  elevation (SR-02), dual authorisation (SR-06) and the
  auditor endpoints (SR-17); no voter or ballot routes
- Own database URLs from the environment; the audit log
  uses its own engine on the audit database
- Fails closed at start-up: no secret key, identity or
  audit database, crypto keys (SR-14) or SR-04 RBAC
  module means no app, never insecure defaults
- Same session hardening as Workstream A (server-side
  sessions, Secure/HttpOnly/SameSite cookies, CSRF,
  request size cap); 10-minute idle timeout (SR-16)
- Installs crypto_agility as Workstream E's field
  encryption provider (SR-13) when that module exists,
  and captures evp.* security logs into the audit log
- Auditor endpoints also require an SR-02 elevation

Environment:
- SECRET_KEY or SECRET_KEY_FILE  Flask session key
- EVP_IDENTITY_DB_URL            staff accounts, operations
- EVP_AUDIT_DB_URL               audit log (SR-17)
- EVP_AUDIT_ARCHIVE              checkpoint archive file
- EVP_KEY_DIR / EVP_CRYPTO_POLICY  keys and policy (SR-14)

Local academic prototype.
"""

import os

from datetime import timedelta
from pathlib import Path

from cachelib import SimpleCache
from flask import Flask
from flask_session import Session
from flask_wtf.csrf import CSRFProtect

import audit
import crypto_agility
from audit import create_audit_blueprint, install_audit_handler
from rate_limit import LoginRateLimiter
from records import db

from .accounts import staff_account_is_active
from .dual_authorisation import DualAuthorisationService
from .elevation import ElevationService
from .login import StaffAuthenticator
from .operation_routes import create_operations_blueprint
from .routes import create_staff_blueprint
from .sessions import INACTIVITY_LIMIT_SECONDS, StaffSessions
from .triggers import ensure_dual_authorisation_triggers


ENV_SECRET_KEY = "SECRET_KEY"
ENV_SECRET_KEY_FILE = "SECRET_KEY_FILE"
ENV_IDENTITY_DB_URL = "EVP_IDENTITY_DB_URL"

MIN_SECRET_KEY_LENGTH = 32
MAX_SECRET_KEY_FILE_BYTES = 4096
MAX_REQUEST_BYTES = 16 * 1024


class CompartmentNotConfigured(RuntimeError):
    """A required setting is missing; the compartment will not start."""


def _secret_key(environ) -> str:
    key = environ.get(ENV_SECRET_KEY)
    key_file = environ.get(ENV_SECRET_KEY_FILE)

    if not key and key_file:
        path = Path(key_file)

        if not path.is_file() or path.stat().st_size > MAX_SECRET_KEY_FILE_BYTES:
            raise CompartmentNotConfigured("Secret key file is not usable")

        key = path.read_text(encoding="utf-8").strip()

    if not key or len(key) < MIN_SECRET_KEY_LENGTH:
        raise CompartmentNotConfigured("A strong SECRET_KEY is required")

    return key


def _required(environ, name: str) -> str:
    value = environ.get(name)

    if not value:
        raise CompartmentNotConfigured(f"{name} is required")

    return value


def _rbac_functions():
    """Workstream E's SR-04 functions; refuse to start without them."""

    try:
        from platform_security.rbac import has_permission, require_permission
    except ImportError:
        raise CompartmentNotConfigured(
            "platform_security.rbac (SR-04) is required"
        ) from None

    return require_permission, has_permission


def _install_field_crypto_provider(crypto) -> bool:
    """Give Workstream E's EncryptedText columns the SR-14 service."""

    try:
        from platform_security.field_crypto import set_crypto_provider
    except ImportError:
        return False

    set_crypto_provider(crypto)

    return True


def _configure_flask(app: Flask, environ) -> None:
    app.config.update(
        SECRET_KEY=_secret_key(environ),
        SESSION_TYPE="cachelib",
        SESSION_CACHELIB=SimpleCache(),
        SESSION_PERMANENT=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=True,
        SESSION_REFRESH_EACH_REQUEST=True,
        PERMANENT_SESSION_LIFETIME=timedelta(seconds=INACTIVITY_LIMIT_SECONDS),
        WTF_CSRF_ENABLED=True,
        MAX_CONTENT_LENGTH=MAX_REQUEST_BYTES,
        SQLALCHEMY_DATABASE_URI=_required(environ, ENV_IDENTITY_DB_URL),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    Session(app)
    CSRFProtect(app)
    db.init_app(app)


def create_app(
    environ=None,
    *,
    require_permission=None,
    has_permission=None,
) -> Flask:
    """
    Build the admin-audit app. The SR-04 functions can
    be injected (tests); otherwise E's module is required.
    """

    environ = os.environ if environ is None else environ

    if require_permission is None or has_permission is None:
        require_permission, has_permission = _rbac_functions()

    _required(environ, audit.ENV_AUDIT_DB_URL)

    crypto = crypto_agility.build_service_from_env(environ)
    crypto_agility.configure(crypto)

    audit_log = audit.build_audit_log_from_env(environ)
    audit.configure(audit_log)
    record_event = audit.record_event

    app = Flask(__name__)
    _configure_flask(app, environ)

    with app.app_context():
        db.create_all()
        ensure_dual_authorisation_triggers(db.engine)

    sessions = StaffSessions(
        audit=record_event,
        account_is_active=lambda staff_id: staff_account_is_active(
            db.session, staff_id
        ),
    )
    authenticator = StaffAuthenticator(
        db_session=lambda: db.session,
        rate_limiter=LoginRateLimiter(),
        audit=record_event,
    )
    elevation = ElevationService(
        db_session=lambda: db.session,
        sessions=sessions,
        require_permission=require_permission,
        has_permission=has_permission,
        audit=record_event,
    )
    dual = DualAuthorisationService(
        db_session=lambda: db.session,
        crypto=crypto,
        audit=record_event,
        clock=sessions.clock,
    )

    app.register_blueprint(create_staff_blueprint(
        authenticator=authenticator, sessions=sessions, elevation=elevation,
    ))
    app.register_blueprint(create_operations_blueprint(
        sessions=sessions, elevation=elevation, service=dual,
    ))
    app.register_blueprint(create_audit_blueprint(
        elevation.require_elevated, audit_log, audit=record_event,
    ))

    _install_field_crypto_provider(crypto)
    install_audit_handler(record_event)

    return app


_app = None


def __getattr__(name):
    # Built on first access (gunicorn's "admin.wsgi:app"), so
    # importing this module never needs secrets.
    global _app

    if name == "app":
        if _app is None:
            _app = create_app()

        return _app

    raise AttributeError(name)
