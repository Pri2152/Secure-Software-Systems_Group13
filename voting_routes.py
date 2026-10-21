"""Thin Workstream C controllers; existing services own voting decisions."""

from flask import Blueprint, current_app, jsonify, request, session
from flask_wtf.csrf import CSRFError
from werkzeug.exceptions import RequestEntityTooLarge

from ballot_credentials import (
    CredentialError, accept_ballot_with_credential, issue_ballot_credential,
)
from records import db


WEB_BALLOT_PAYLOAD = '{"format":"single-choice-web-v1"}'


def create_voting_blueprint(require_active_session):
    bp = Blueprint("voting", __name__, url_prefix="/vote",
                   template_folder="templates", static_folder="static/voting",
                   static_url_path="/assets")

    @bp.after_request
    def private_response(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @bp.errorhandler(CSRFError)
    def csrf_failure(error):
        return jsonify(error="Invalid request"), 400

    @bp.errorhandler(RequestEntityTooLarge)
    def oversized_request(error):
        return jsonify(error="Invalid request"), 413

    @bp.post("/credentials")
    @require_active_session
    def credentials():
        if not request.is_json:
            return jsonify(error="JSON request required"), 415
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or data:
            return jsonify(error="Invalid request"), 400
        try:
            credential = issue_ballot_credential(
                session.get("voter_id"), current_app.config["VOTING_ELECTION_ID"]
            )
            return jsonify(credential=credential), 200
        except CredentialError:
            return jsonify(error="Voting unavailable"), 409
        except Exception:
            db.session.rollback()
            return jsonify(error="Voting unavailable"), 503

    @bp.post("/ballots")
    def ballots():
        # CSRF remains enabled; identity is never an acceptance argument.
        if not request.is_json:
            return jsonify(error="JSON request required"), 415
        data = request.get_json(silent=True)
        if (
            not isinstance(data, dict) or set(data) != {"credential", "candidate_id"}
            or not isinstance(data["credential"], str) or len(data["credential"]) != 43
            or type(data["candidate_id"]) is not int or data["candidate_id"] <= 0
        ):
            return jsonify(error="Invalid request"), 400
        try:
            reference = accept_ballot_with_credential(
                data["credential"], data["candidate_id"], WEB_BALLOT_PAYLOAD
            )
        except CredentialError:
            return jsonify(error="Vote could not be accepted"), 409
        except Exception:
            db.session.rollback()
            return jsonify(error="Vote could not be accepted"), 503
        session.clear()
        return jsonify(status="accepted", confirmation_reference=reference), 200

    return bp
