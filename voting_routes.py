"""Thin Workstream C controllers; existing services own voting decisions."""

from flask import Blueprint, current_app, jsonify, render_template, request, session
from flask_wtf.csrf import CSRFError
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

from ballot_credentials import (
    CredentialError, accept_ballot_with_credential, issue_ballot_credential,
)
from records import db
from ballot_service import EligibilityError, get_ballot_candidates, get_voting_eligibility
from ballot_protection import HASH_PATTERN, parse_json


WEB_BALLOT_PAYLOAD = '{"format":"single-choice-web-v1"}'


def json_body():
    try:
        return parse_json(request.get_data(cache=False))
    except (ValueError, TypeError):
        raise BadRequest() from None


def create_voting_blueprint(require_active_session):
    bp = Blueprint("voting", __name__, url_prefix="/vote",
                   template_folder="templates", static_folder="static/voting",
                   static_url_path="/assets")

    @bp.before_request
    def reject_query_handoff():
        if request.args:
            return jsonify(error="Invalid request"), 400

    @bp.after_request
    def private_response(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
        )
        return response

    @bp.get("")
    @require_active_session
    def page():
        try:
            election_id = current_app.config["VOTING_ELECTION_ID"]
            eligibility = get_voting_eligibility(session.get("voter_id"), election_id)
            candidates = get_ballot_candidates(eligibility)
            if not candidates:
                raise EligibilityError("Voting unavailable")
            return render_template("voting/ballot.html", election_id=election_id,
                                   division=eligibility.electoral_division, candidates=candidates)
        except EligibilityError:
            db.session.rollback()
            return render_template("voting/unavailable.html"), 409
        except Exception:
            db.session.rollback()
            return render_template("voting/unavailable.html"), 503

    @bp.errorhandler(CSRFError)
    @bp.errorhandler(BadRequest)
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
        data = json_body()
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
        data = json_body()
        if (
            not isinstance(data, dict) or set(data) != {"credential", "candidate_id"}
            or not isinstance(data["credential"], str) or len(data["credential"]) != 43
            or type(data["candidate_id"]) is not int or data["candidate_id"] <= 0
        ):
            return jsonify(error="Invalid request"), 400
        recorded = []
        try:
            reference = accept_ballot_with_credential(
                data["credential"], data["candidate_id"], WEB_BALLOT_PAYLOAD,
                on_recorded=recorded.append,
            )
        except CredentialError:
            return jsonify(error="Vote could not be accepted"), 409
        except Exception:
            db.session.rollback()
            return jsonify(error="Vote could not be accepted"), 503
        session.clear()
        reply = {"status": "accepted", "confirmation_reference": reference}
        # SR-11: the public hash of the new record is the voter's tracking
        # code. It is not linked to the choice, so it is no receipt (SR-09).
        if recorded and isinstance(recorded[0], str) and HASH_PATTERN.fullmatch(recorded[0]):
            reply["tracking_code"] = recorded[0]
        return jsonify(reply), 200

    return bp
