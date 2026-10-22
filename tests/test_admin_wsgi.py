"""
SR-20: admin-audit compartment entrypoint tests.

Builds the compartment from environment settings
pointing at temporary SQLite files, with throwaway
development keys and Workstream E's RBAC (or the
stand-in with the same behaviour).
"""

import importlib
import logging
import secrets

import pytest
from sqlalchemy import create_engine, text

import audit
import crypto_agility
from admin import create_staff_account
from admin.wsgi import CompartmentNotConfigured, create_app
from audit.handler import AuditLogHandler
from crypto_agility import CryptoNotConfigured
from records import db
from staff_support import (
    PASSWORD,
    make_certificate,
    rbac_functions,
    staff_request,
)


ADMIN_PREFIXES = ("/staff/", "/admin/", "/audit/", "/static/")


@pytest.fixture
def environ(tmp_path):
    return {
        "SECRET_KEY": secrets.token_hex(32),
        "EVP_IDENTITY_DB_URL": f"sqlite:///{tmp_path / 'identity.db'}",
        "EVP_AUDIT_DB_URL": f"sqlite:///{tmp_path / 'audit.db'}",
        "EVP_AUDIT_ARCHIVE": str(tmp_path / "checkpoints.jsonl"),
        "EVP_CRYPTO_DEV_KEYS": "1",
    }


@pytest.fixture(autouse=True)
def reset_globals():
    evp_logger = logging.getLogger("evp")
    level = evp_logger.level

    yield

    for handler in list(evp_logger.handlers):
        if isinstance(handler, AuditLogHandler):
            evp_logger.removeHandler(handler)

    evp_logger.setLevel(level)
    crypto_agility.configure(None)
    audit.configure(None)


def build(environ):
    require_permission, has_permission = rbac_functions()

    return create_app(
        environ,
        require_permission=require_permission,
        has_permission=has_permission,
    )


# Test 1: Only Workstream B routes are registered
def test_only_admin_audit_routes_are_registered(environ):
    app = build(environ)

    rules = {rule.rule for rule in app.url_map.iter_rules()}

    # /healthz is the one extra route: Docker's health check (SR-19)
    assert all(
        rule.startswith(ADMIN_PREFIXES) or rule == "/healthz"
        for rule in rules
    )
    assert {"/staff/login", "/staff/elevate", "/admin/operations",
            "/audit/events", "/audit/verify"} <= rules
    assert "/login" not in rules


# SR-19: the container health check needs GET /healthz to answer
def test_health_check_answers_without_login(environ):
    app = build(environ)

    reply = app.test_client().get("/healthz")

    assert reply.status_code == 200
    assert reply.get_json() == {"status": "ok"}


# Test 2: Session and cookie hardening match Workstream A
def test_security_configuration(environ):
    config = build(environ).config

    assert config["SESSION_COOKIE_SECURE"] is True
    assert config["SESSION_COOKIE_HTTPONLY"] is True
    assert config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert config["WTF_CSRF_ENABLED"] is True
    assert config["SESSION_TYPE"] == "cachelib"
    assert config["MAX_CONTENT_LENGTH"] <= 16 * 1024


# Test 3: Missing or weak settings stop start-up (fail closed)
@pytest.mark.parametrize("missing", [
    "SECRET_KEY", "EVP_IDENTITY_DB_URL", "EVP_AUDIT_DB_URL",
])
def test_missing_settings_fail_closed(environ, missing):
    del environ[missing]

    with pytest.raises(CompartmentNotConfigured):
        build(environ)


def test_weak_secret_key_fails_closed(environ):
    environ["SECRET_KEY"] = "short"

    with pytest.raises(CompartmentNotConfigured):
        build(environ)


# Test 4: No crypto keys -> no app
def test_missing_crypto_keys_fail_closed(environ):
    del environ["EVP_CRYPTO_DEV_KEYS"]

    with pytest.raises(CryptoNotConfigured):
        build(environ)


# Test 5: Secret key can come from a Docker secret file
def test_secret_key_from_file(environ, tmp_path):
    key_file = tmp_path / "flask_secret_key"
    key_file.write_text(secrets.token_hex(32))
    del environ["SECRET_KEY"]
    environ["SECRET_KEY_FILE"] = str(key_file)

    assert build(environ).config["SECRET_KEY"] == key_file.read_text()


# Test 6: Without Workstream E's RBAC module the compartment refuses to start
def test_missing_rbac_module_fails_closed(environ):
    try:
        importlib.import_module("platform_security.rbac")
    except ImportError:
        with pytest.raises(CompartmentNotConfigured):
            create_app(environ)
    else:
        pytest.skip("Workstream E's RBAC module is installed")


# Test 7: Two-person triggers are installed on the identity database
def test_dual_authorisation_triggers_installed(environ):
    build(environ)

    engine = create_engine(environ["EVP_IDENTITY_DB_URL"])

    with engine.connect() as connection:
        names = {name for (name,) in connection.execute(text(
            "SELECT name FROM sqlite_master WHERE type = 'trigger'"
        ))}

    engine.dispose()

    assert "pending_operations_two_person_update" in names
    assert "pending_operations_executed_no_update" in names


# Test 8: End to end in the compartment: login, elevate, read audit log
def test_compartment_end_to_end(environ):
    app = build(environ)
    pem, fingerprint = make_certificate("Grace Hopper")

    with app.app_context():
        create_staff_account(
            db.session, staff_id="auditor-grace-hopper",
            full_name="Grace Hopper", role="auditor",
            password=PASSWORD, cert_fingerprint=fingerprint,
        )
        db.session.commit()

    client = app.test_client()

    login = staff_request(client, "post", "/staff/login",
                          {"staff_id": "auditor-grace-hopper",
                           "password": PASSWORD}, pem=pem)
    assert login.status_code == 200

    assert staff_request(
        client, "get", "/audit/events?stream=admin"
    ).status_code == 403

    elevate = staff_request(client, "post", "/staff/elevate",
                            {"permission": "audit.read", "password": PASSWORD},
                            pem=pem)
    assert elevate.status_code == 200

    response = staff_request(client, "get", "/audit/events?stream=admin")
    types = [e["event_type"] for e in response.get_json()["events"]]

    assert response.status_code == 200
    assert "STAFF_LOGIN_SUCCESS" in types
    assert audit.get_audit_log().verify_chain("admin").ok is True


# Test 9: evp.* security logs are captured into the audit log
def test_security_logs_are_captured(environ):
    build(environ)

    logging.getLogger("evp.gateway_security").warning(
        "gateway_access_denied reason=untrusted_gateway_peer"
    )

    events = audit.get_audit_log().list_events("identity")

    assert events[0]["event_type"] == "GATEWAY_ACCESS_DENIED"


# Test 10: Importing the module never builds the app or needs secrets
def test_import_does_not_build_app(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)

    module = importlib.import_module("admin.wsgi")

    assert module._app is None

    with pytest.raises(AttributeError):
        module.not_a_setting


# Test 11: E's field-encryption provider is set when the module exists
def test_field_crypto_provider_installed_when_available(environ):
    field_crypto = pytest.importorskip("platform_security.field_crypto")

    build(environ)

    assert field_crypto.get_crypto_provider() is crypto_agility.get_service()
    field_crypto.set_crypto_provider(None)
