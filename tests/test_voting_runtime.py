"""Explicit synthetic demo setup reuses candidate finalisation and real crypto."""

import json

import pytest
from flask import Flask

import app as application
import audit
import crypto_agility
from admin.candidates import final_candidate_list
from admin.models import PendingOperation
from ballot_integrity import verify_ballot_chain
from records import db
from voting_runtime import configure_voting_demo
from test_ballot_credentials import seed_voter
from test_voting_page import BallotPage
from test_voting_routes import HTTPS_URL, issue, vote, voting_client


@pytest.mark.parametrize("flags,uri", [
    ({}, "sqlite:///:memory:"), ({"EVP_LOCAL_LAB": "1"}, "sqlite:///:memory:"),
    ({"EVP_LOCAL_LAB": "1", "EVP_VOTING_DEMO": "1"}, "sqlite:///persistent.db"),
])
def test_bootstrap_cannot_run_outside_explicit_memory_lab(flags, uri):
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = uri
    with pytest.raises(RuntimeError, match="explicit in-memory lab"):
        configure_voting_demo(app, flags)


def test_bootstrap_finalises_external_list_and_supports_http_vote(voting_client, tmp_path, monkeypatch):
    client, _ = voting_client
    candidates = tmp_path / "candidates.json"
    candidates.write_text(json.dumps({"candidates": [
        dict(name="Taylor Green", party="Independent", position_in_group=1),
        dict(name="Morgan Smith", party="Example Party", position_in_group=2),
    ]}), encoding="utf-8")
    environ = dict(
        EVP_LOCAL_LAB="1", EVP_VOTING_DEMO="1", EVP_CRYPTO_DEV_KEYS="1",
        EVP_DEMO_CANDIDATES_FILE=str(candidates),
        EVP_AUDIT_DB_URL="sqlite:///" + str(tmp_path / "audit.db"),
        EVP_AUDIT_ARCHIVE=str(tmp_path / "checkpoints.jsonl"),
    )
    monkeypatch.setattr(crypto_agility, "_service", None)
    monkeypatch.setattr(audit, "_audit_log", None)
    with application.app.app_context():
        db.drop_all()
        db.create_all()
        seed_voter()
    configure_voting_demo(application.app, environ)
    audit_log = audit.get_audit_log()
    try:
        with application.app.app_context():
            assert [candidate.name for candidate in final_candidate_list("Melbourne")] == [
                "Taylor Green", "Morgan Smith"
            ]
            operation = PendingOperation.query.one()
            assert operation.status == "EXECUTED"
            assert operation.proposer_id != operation.approver_id
        assert len(audit_log.list_events("admin")) == 3
        page = client.get("/vote", base_url=HTTPS_URL)
        assert page.status_code == 200
        parsed = BallotPage()
        parsed.feed(page.get_data(as_text=True))
        credential = issue(client).get_json()["credential"]
        assert vote(client, credential, parsed.candidates[0]).status_code == 200
        with application.app.app_context():
            assert verify_ballot_chain("election-2026", "Melbourne") is True
    finally:
        audit_log.engine.dispose()
