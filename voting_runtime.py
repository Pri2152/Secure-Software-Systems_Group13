"""Explicit local-only candidate bootstrap for the in-memory gateway demo."""

import os
import secrets
import time
from pathlib import Path

import audit
import crypto_agility
from admin.accounts import create_staff_account
from admin.candidates import add_draft_candidate
from admin.dual_authorisation import DualAuthorisationService
from admin.models import Candidate
from admin.operations import OP_FINALISE
from ballot_models import VotingEligibility
from ballot_protection import parse_json
from records import db


def configure_voting_demo(app, environ=None):
    """Seed external synthetic candidates via the existing two-person service."""
    environ = os.environ if environ is None else environ
    if (
        environ.get("EVP_LOCAL_LAB") != "1" or environ.get("EVP_VOTING_DEMO") != "1"
        or app.config["SQLALCHEMY_DATABASE_URI"] != "sqlite:///:memory:"
    ):
        raise RuntimeError("Voting demo requires explicit in-memory lab mode")
    path = Path(environ.get("EVP_DEMO_CANDIDATES_FILE", "/run/evp/demo-candidates.json"))
    if not path.is_file() or path.stat().st_size > 65536:
        raise RuntimeError("Synthetic candidate configuration unavailable")
    data = parse_json(path.read_text(encoding="utf-8"))
    if (
        not isinstance(data, dict) or set(data) != {"candidates"}
        or not isinstance(data["candidates"], list) or not 1 <= len(data["candidates"]) <= 50
        or any(not isinstance(candidate, dict)
               or set(candidate) != {"name", "party", "position_in_group"}
               for candidate in data["candidates"])
    ):
        raise RuntimeError("Invalid synthetic candidate configuration")
    crypto = crypto_agility.build_service_from_env(environ)
    crypto_agility.configure(crypto)
    audit_log = audit.build_audit_log_from_env(environ)
    audit.configure(audit_log)
    with app.app_context():
        if Candidate.query.first() is not None:
            raise RuntimeError("Voting demo requires an unseeded candidate list")
        assignments = db.session.execute(db.select(VotingEligibility.electoral_division).where(
            VotingEligibility.election_id == app.config["VOTING_ELECTION_ID"]
        ).distinct()).scalars().all()
        if len(assignments) != 1:
            raise RuntimeError("Synthetic election assignment unavailable")
        division = assignments[0]
        for candidate in data["candidates"]:
            add_draft_candidate(db.session, division=division, **candidate)
        for staff_id, name in (("alex.rivera", "Alex Rivera"), ("jamie.chen", "Jamie Chen")):
            create_staff_account(
                db.session, staff_id=staff_id, full_name=name, role="delegate",
                password=secrets.token_urlsafe(32), cert_fingerprint=secrets.token_hex(32),
            )
        db.session.commit()
        workflow = DualAuthorisationService(db_session=lambda: db.session, crypto=crypto,
                                             audit=audit.record_event, clock=time.time)
        proposal = workflow.propose("alex.rivera", OP_FINALISE, {"division": division})
        workflow.approve(proposal, "jamie.chen", proposal.payload_hash)
