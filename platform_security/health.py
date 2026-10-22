"""
SR-19: Liveness endpoint for container health checks.

GET /healthz returns {"status": "ok"} so Docker can tell a
running replica from a stuck one.

Security controls:
- No login, no session, no database access and no data:
  the body is always exactly {"status": "ok"}
- Answered before Workstream A's SR-07 mission check, but only
  for GET or HEAD on exactly /healthz; every other request still
  goes through that check unchanged
- Not routed by the Nginx gateway (nginx/conf.d/evp.conf), so
  only the container's own health check reaches it
- Sets no cookie and is never cached

Local academic prototype.
"""

from flask import Blueprint, jsonify, request


HEALTH_PATH = "/healthz"
HEALTH_METHODS = frozenset({"GET", "HEAD"})

health_blueprint = Blueprint("health", __name__)


@health_blueprint.get(HEALTH_PATH)
def healthz():
    response = jsonify(status="ok")
    response.headers["Cache-Control"] = "no-store"

    return response


def _answer_health_check():
    """
    Runs before every other before_request handler. Returns the
    health response for GET/HEAD /healthz only; None otherwise,
    so all other requests carry on through the normal checks.
    """

    if request.path == HEALTH_PATH and request.method in HEALTH_METHODS:
        return healthz()

    return None


@health_blueprint.record_once
def _run_first(state):
    # The container's health check calls 127.0.0.1 directly, not
    # through the gateway, so SR-07's gateway check would refuse it.
    state.app.before_request_funcs.setdefault(None, []).insert(
        0, _answer_health_check
    )
