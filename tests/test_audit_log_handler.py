"""
SR-17: Workstream A security log capture tests.

Drives Workstream A's real login, rate-limit, mission
access and gateway code (unchanged) and checks the
audit log handler records identity-stream events.
"""

import logging

import pyotp
import pytest
from flask import Flask, session
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

import gateway_security
from audit.handler import (
    AuditLogHandler,
    install_audit_handler,
    remove_audit_handler,
)
from audit.log import AuditLog
from auth import hash_password
from crypto_agility import CryptoService, DEFAULT_POLICY, default_registry
from crypto_agility.keys import KeyStore
from login_flow import LoginCoordinator, VoterRecord
from mission_access import MissionAccessPolicy
from rate_limit import LoginRateLimiter


TOTP_SECRET = "JBSWY3DPEHPK3PXP"
PASSWORD = "CorrectPassword123!"
SOURCE = "203.0.113.10"
NOW = 1700000000.0


@pytest.fixture
def audit_log():
    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    log = AuditLog(
        engine,
        crypto=CryptoService(
            default_registry(), DEFAULT_POLICY, KeyStore.ephemeral()
        ),
    )
    log.create_schema()

    return log


@pytest.fixture
def handler(audit_log):
    evp_logger = logging.getLogger("evp")
    previous_level = evp_logger.level

    installed = install_audit_handler(audit_log.record_event)

    yield installed

    remove_audit_handler(installed)
    evp_logger.setLevel(previous_level)


@pytest.fixture
def coordinator():
    voter = VoterRecord(
        voter_id="voter-001",
        password_hash=hash_password(PASSWORD),
        totp_secret=TOTP_SECRET,
    )

    return LoginCoordinator(
        lookup_voter={"voter-001": voter}.get,
        rate_limiter=LoginRateLimiter(clock=lambda: NOW),
        clock=lambda: NOW,
    )


def login(coordinator, password=PASSWORD, callback=None):
    return coordinator.authenticate(
        account_id="voter-001",
        password=password,
        totp_code=pyotp.TOTP(TOTP_SECRET).at(int(NOW)),
        source_id=SOURCE,
        on_authenticated=callback or (lambda voter_id: None),
    )


def identity_events(audit_log):
    return list(reversed(audit_log.list_events("identity", limit=200)))


# Test 1: A failed login (A's code) becomes an identity audit event
def test_failed_login_is_audited(handler, audit_log, coordinator):
    result = login(coordinator, password="WrongPassword!")

    assert result.success is False

    event = identity_events(audit_log)[-1]

    assert event["event_type"] == "AUTH_FAILURE"
    assert event["outcome"] == "failure"
    assert event["actor_type"] == "anonymous"
    assert event["details"]["source"] == "evp.login"


# Test 2: The attempted password never reaches the audit log
def test_failed_login_does_not_store_password(handler, audit_log, coordinator):
    login(coordinator, password="WrongPassword!")

    assert "WrongPassword" not in str(identity_events(audit_log))


# Test 3: Successful login in a request records voter and source IP
def test_successful_login_records_actor(handler, audit_log, coordinator):
    app = Flask(__name__)
    app.secret_key = "test-only-secret"

    def establish(voter_id):
        session["voter_id"] = voter_id

    with app.test_request_context(environ_base={"REMOTE_ADDR": SOURCE}):
        assert login(coordinator, callback=establish).success is True

    event = identity_events(audit_log)[-1]

    assert event["event_type"] == "AUTH_SUCCESS"
    assert event["actor_type"] == "voter"
    assert event["actor_id"] == "voter-001"
    assert event["source_ip"] == SOURCE


# Test 4: Outside a request the actor is unknown, not guessed
def test_success_outside_request_has_no_actor(handler, audit_log, coordinator):
    login(coordinator)

    event = identity_events(audit_log)[-1]

    assert event["event_type"] == "AUTH_SUCCESS"
    assert event["actor_id"] is None
    assert event["source_ip"] is None


# Test 5: Rate limiting (A's code) is audited with its scope
def test_rate_limit_is_audited(handler, audit_log, coordinator):
    for _ in range(5):
        login(coordinator, password="WrongPassword!")

    login(coordinator)

    types = [event["event_type"] for event in identity_events(audit_log)]

    assert types.count("AUTH_FAILURE") == 5
    assert "RATE_LIMIT_REACHED" in types
    assert types[-1] == "AUTH_RATE_LIMITED"

    reached = [e for e in identity_events(audit_log)
               if e["event_type"] == "RATE_LIMIT_REACHED"]

    assert {e["details"]["scope"] for e in reached} == {"account", "source"}


# Test 6: Mission access denial (A's SR-07 policy) is audited
def test_mission_access_denial_is_audited(handler, audit_log):
    policy = MissionAccessPolicy(
        mission_networks=["198.51.100.0/24"],
        registered_fingerprints=["a" * 64],
        country_lookup=lambda ip: "AU",
    )

    assert policy.evaluate("not-an-ip").allowed is False

    event = identity_events(audit_log)[-1]

    assert event["event_type"] == "MISSION_ACCESS_DENIED"
    assert event["outcome"] == "denied"
    assert event["details"]["reason"] == "invalid_source"


# Test 7: Gateway denial (A's SR-07 gateway) is audited
def test_gateway_denial_is_audited(handler, audit_log):
    gateway_security.deny("untrusted_gateway_peer")

    event = identity_events(audit_log)[-1]

    assert event["event_type"] == "GATEWAY_ACCESS_DENIED"
    assert event["details"] == {
        "source": "evp.gateway_security",
        "reason": "untrusted_gateway_peer",
    }


# Test 8: The audited chain stays valid
def test_captured_events_form_valid_chain(handler, audit_log, coordinator):
    login(coordinator, password="WrongPassword!")
    login(coordinator)

    assert audit_log.verify_chain("identity").ok is True


# Test 9: Unknown messages are ignored
def test_unknown_messages_are_ignored(handler, audit_log):
    logging.getLogger("evp.login").warning("something_else happened")
    logging.getLogger("evp.rbac").warning("authz_denied permission=x")

    assert identity_events(audit_log) == []


# Test 10: Only allow-listed, simple details are kept
def test_log_text_injection_is_filtered(handler, audit_log):
    logging.getLogger("evp.gateway_security").warning(
        "gateway_access_denied reason=<script> password=hunter2 "
        "scope=account extra=1"
    )

    event = identity_events(audit_log)[-1]

    assert event["details"] == {
        "source": "evp.gateway_security", "scope": "account"
    }


# Test 11: Records outside the evp namespace are not captured
def test_other_loggers_are_not_captured(handler, audit_log):
    logging.getLogger("werkzeug").warning("authentication_rejected")

    assert identity_events(audit_log) == []


# Test 12: Audit failure never breaks Workstream A's login
def test_audit_failure_does_not_break_login(monkeypatch, coordinator):
    monkeypatch.setattr(logging, "raiseExceptions", False)

    def failing_audit(*args, **kwargs):
        raise RuntimeError("audit database down")

    installed = install_audit_handler(failing_audit)

    try:
        assert login(coordinator).success is True
    finally:
        remove_audit_handler(installed)


# Test 13: The handler's own and crypto loggers are not re-audited
def test_own_loggers_are_skipped(handler, audit_log):
    logging.getLogger("evp.audit").warning("authentication_rejected")
    logging.getLogger("evp.crypto").warning("authentication_rejected")

    assert identity_events(audit_log) == []


# Test 14: Installing twice keeps a single handler
def test_install_is_idempotent(handler, audit_log):
    second = install_audit_handler(audit_log.record_event)

    try:
        handlers = [
            h for h in logging.getLogger("evp").handlers
            if isinstance(h, AuditLogHandler)
        ]

        assert handlers == [second]

    finally:
        remove_audit_handler(second)


# Test 15: Installation lets INFO events through
def test_install_lowers_evp_level_to_info(handler):
    assert logging.getLogger("evp").isEnabledFor(logging.INFO)
