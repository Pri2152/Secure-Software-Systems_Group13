"""
SR-11 / SR-18 / SR-20: tally compartment entrypoint (Workstream D).

Gunicorn target: verification.wsgi:app (deploy/ENTRYPOINTS.md)

Routes (internal network only, never on the public edge):
- GET  /healthz   liveness for Docker (no data)
- POST /publish   count the ballots, check the chain, sign and store a
                  new bulletin; also sends the signed result to the
                  results receiver when EVP_RESULTS_URL is set
- GET  /bulletin  the last published bulletin
- GET  /verify   the verification web page (no data in it)
- GET  /bulletin/checks  the same bulletin checked again (signature,
                  commitment, recount) with the totals, for the
                  verification page

Security controls:
- Both /publish and /bulletin need a bearer token read from a secret
  file; no token file means the app does not start
- If any division fails its integrity check nothing is published and
  the caller only sees a generic "Tally refused" (SR-11)
- Reads only the ballot database; has no voter or identity data
- Each publish gets a higher version, so an old result cannot be replayed
- The result is sent over mutual TLS 1.3 only (verification/export.py)
- Fails closed at start-up: missing database, keys, divisions or token
  means no app
- The app is built on first use, so importing this file needs no secrets

Environment:
- EVP_BALLOT_DB_URL    ballot database (read only account)
- EVP_AUDIT_DB_URL     audit log (records TALLY_REFUSED)
- EVP_ELECTION_ID      election to tally
- EVP_DIVISIONS        comma separated division names
- EVP_TALLY_TOKEN_FILE file holding the bearer token (at least 32 chars)
- EVP_KEY_DIR          keys: election (open), ballot, bulletin, results
- EVP_RESULTS_URL      optional https URL of the results receiver
- EVP_RESULTS_CA / EVP_RESULTS_CERT / EVP_RESULTS_KEY   for that call

Local academic prototype.
"""

import hmac
import logging
import os
import threading

from pathlib import Path

from flask import Flask, jsonify, request

import audit
import crypto_agility
from platform_security.health import health_blueprint
from records import db
from verification.bulletin import all_passed, build_bulletin, verify_bulletin
from verification.export import ExportFailed, send_results
from verification.headers import register_security_headers
from verification.tally import TallyRefused
from verification.verify_page import create_verify_blueprint


logger = logging.getLogger("evp.tally")

ENV_BALLOT_DB_URL = "EVP_BALLOT_DB_URL"
ENV_ELECTION_ID = "EVP_ELECTION_ID"
ENV_DIVISIONS = "EVP_DIVISIONS"
ENV_TOKEN_FILE = "EVP_TALLY_TOKEN_FILE"
ENV_RESULTS_URL = "EVP_RESULTS_URL"
ENV_RESULTS_CA = "EVP_RESULTS_CA"
ENV_RESULTS_CERT = "EVP_RESULTS_CERT"
ENV_RESULTS_KEY = "EVP_RESULTS_KEY"

MIN_TOKEN_LENGTH = 32
MAX_TOKEN_FILE_BYTES = 4096
MAX_DIVISIONS = 200


class TallyNotConfigured(RuntimeError):
    """A setting is missing, so the tally will not start."""


def _required(environ, name):
    value = environ.get(name)

    if not value:
        raise TallyNotConfigured(f"{name} is required")

    return value


def _token(environ):
    path = Path(_required(environ, ENV_TOKEN_FILE))

    if not path.is_file() or path.stat().st_size > MAX_TOKEN_FILE_BYTES:
        raise TallyNotConfigured("Token file is not usable")

    token = path.read_text(encoding="utf-8").strip()

    if len(token) < MIN_TOKEN_LENGTH:
        raise TallyNotConfigured("Token is too short")

    return token


def _divisions(environ):
    names = [
        part.strip()
        for part in _required(environ, ENV_DIVISIONS).split(",")
        if part.strip()
    ]

    if not names or len(names) > MAX_DIVISIONS:
        raise TallyNotConfigured(f"{ENV_DIVISIONS} is not usable")

    return sorted(set(names))


def _results_target(environ):
    """None when no receiver is set, else (url, ca, cert, key)."""

    url = environ.get(ENV_RESULTS_URL)

    if not url:
        return None

    return (
        url,
        _required(environ, ENV_RESULTS_CA),
        _required(environ, ENV_RESULTS_CERT),
        _required(environ, ENV_RESULTS_KEY),
    )


def create_app(environ=None, *, crypto=None):
    environ = os.environ if environ is None else environ

    election_id = _required(environ, ENV_ELECTION_ID)
    divisions = _divisions(environ)
    token = _token(environ)
    target = _results_target(environ)

    app = Flask(__name__)
    app.config.update(
        SQLALCHEMY_DATABASE_URI=_required(environ, ENV_BALLOT_DB_URL),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=1024,
    )
    db.init_app(app)

    crypto = crypto or crypto_agility.build_service_from_env(environ)
    crypto_agility.configure(crypto)
    audit.configure(audit.build_audit_log_from_env(environ))

    state = {"version": 0, "bulletin": None}
    lock = threading.Lock()

    def allowed():
        header = request.headers.get("Authorization", "")
        scheme, _, given = header.partition(" ")

        return scheme == "Bearer" and hmac.compare_digest(
            given.encode("utf-8"), token.encode("utf-8")
        )

    @app.post("/publish")
    def publish():
        if not allowed():
            return jsonify(error="Not allowed"), 401

        with lock:
            version = state["version"] + 1

            try:
                package = build_bulletin(crypto, election_id, divisions, version)
            except TallyRefused:
                logger.warning("tally_refused election=%s", election_id)
                return jsonify(error="Tally refused"), 409

            state["version"] = version
            state["bulletin"] = package

        delivered = None

        if target:
            url, cafile, certfile, keyfile = target

            try:
                status, _ = send_results(
                    package["result"], url,
                    cafile=cafile, certfile=certfile, keyfile=keyfile,
                )
                delivered = status == 200
            except ExportFailed:
                logger.warning("result_delivery_failed")
                delivered = False

        return jsonify(status="published", version=version, delivered=delivered)

    @app.get("/bulletin")
    def bulletin():
        if not allowed():
            return jsonify(error="Not allowed"), 401

        if state["bulletin"] is None:
            return jsonify(error="Nothing published yet"), 404

        return jsonify(state["bulletin"])

    @app.get("/bulletin/checks")
    def bulletin_checks():
        if not allowed():
            return jsonify(error="Not allowed"), 401

        package = state["bulletin"]

        if package is None:
            return jsonify(error="Nothing published yet"), 404

        checks = verify_bulletin(crypto, package)
        body = package["bulletin"]
        result = package["result"]["result"]

        return jsonify(
            election_id=body["election_id"],
            version=body["version"],
            commitment=body["commitment"],
            ballots_counted=result["ballots_counted"],
            divisions=result["divisions"],
            checks=[{"name": name, "passed": ok} for name, ok in checks],
            all_passed=all_passed(checks),
        )

    app.register_blueprint(health_blueprint)
    app.register_blueprint(create_verify_blueprint())

    return register_security_headers(app)


_app = None


def __getattr__(name):
    # Built on first access (gunicorn's "verification.wsgi:app").
    global _app

    if name == "app":
        if _app is None:
            _app = create_app()

        return _app

    raise AttributeError(name)
