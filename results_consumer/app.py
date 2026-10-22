"""
SR-18: receiver for signed election results.

It only accepts a result when the signature is good, the election id
matches and the version is newer than the last one it accepted.
It needs only the public key, never the private key.
"""

import logging
import threading

from flask import Flask, jsonify, request

from verification.headers import register_security_headers
from verification.results import ResultRejected, verify_package


logger = logging.getLogger("evp.results_consumer")

MAX_BODY_BYTES = 64 * 1024


class ResultsState:
    """Remembers accepted results. The lock keeps updates one at a time."""

    def __init__(self):
        self.lock = threading.Lock()
        self.last_version = 0
        self.accepted = []


def create_app(*, crypto, election_id, state=None):
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    state = state if state is not None else ResultsState()
    app.config["RESULTS_STATE"] = state

    @app.post("/results")
    def receive():
        if not request.is_json:
            return jsonify(error="JSON request required"), 415

        package = request.get_json(silent=True)

        with state.lock:
            try:
                result = verify_package(
                    crypto,
                    package,
                    election_id=election_id,
                    last_version=state.last_version,
                )
            except ResultRejected as problem:
                # reason goes to the log only, never back to the sender
                logger.warning("result_rejected reason=%s", problem)
                status = 409 if str(problem) == "version_not_newer" else 400
                return jsonify(error="Result rejected"), status

            state.last_version = result["version"]
            state.accepted.append(result)

        return jsonify(status="accepted", version=result["version"]), 200

    return register_security_headers(app)
