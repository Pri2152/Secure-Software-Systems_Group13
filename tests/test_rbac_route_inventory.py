
"""
SR-04 endpoint inventory tests.

Every route on the real application must be public
by explicit decision, or protected by require_permission
(SR-04) or require_active_session (SR-16). A new route
without either fails the build.
"""

import pytest
from flask import Flask

import app as application

from platform_security.rbac import require_permission
from platform_security.route_inventory import (
    find_unknown_public_endpoints,
    find_unprotected_routes,
    is_protected_view,
)


PUBLIC_ENDPOINTS = frozenset({
    # Flask's built-in static file handler; serves no
    # voter data and the repository has no static files.
    "static",
    # Plain landing text; no data, no state change.
    "home",
    # Must be public so a voter can obtain a CSRF
    # token before logging in (SR-16).
    "login_csrf",
    # Must be public so a voter can log in; protected
    # by CSRF, MFA and rate limiting (SR-01).
    "login",
})


# Unprotected today and not public by design. Kept
# visible here, not deleted, until Binsa decides.
PENDING_REVIEW = frozenset({
    # Workstream A's CSRF test target, used by
    # tests/test_sessions.py. POST with no session check.
    "test_action",
})


def test_real_app_has_no_unexpected_unprotected_routes():
    unprotected = find_unprotected_routes(
        application.app,
        PUBLIC_ENDPOINTS,
    )

    found = {rule.endpoint for rule in unprotected}

    # Fails on any new unprotected route, and also when a
    # pending route is fixed so this list must be updated.
    assert found == PENDING_REVIEW, (
        "Unprotected routes: "
        + ", ".join(str(rule) for rule in unprotected)
    )


def test_public_list_has_no_stale_entries():
    assert find_unknown_public_endpoints(
        application.app,
        PUBLIC_ENDPOINTS | PENDING_REVIEW,
    ) == []


def test_public_and_pending_lists_do_not_overlap():
    assert not PUBLIC_ENDPOINTS & PENDING_REVIEW


def protected_real_rules():
    return [
        rule
        for rule in application.app.url_map.iter_rules()
        if is_protected_view(
            application.app.view_functions[rule.endpoint]
        )
    ]


def test_real_app_has_protected_routes():
    endpoints = {rule.endpoint for rule in protected_real_rules()}

    assert {
        "session_status",
        "logout",
        "voter_records.view_enrolment",
        "voter_records.view_address",
        "voter_records.update_address",
    } <= endpoints


@pytest.mark.parametrize(
    "rule",
    protected_real_rules(),
    ids=lambda rule: rule.endpoint,
)
def test_marked_routes_really_require_a_session(rule, monkeypatch):
    # The marker must match behaviour: without a session
    # every protected route answers 401.
    monkeypatch.setitem(application.app.config, "TESTING", True)
    monkeypatch.setitem(
        application.app.config, "WTF_CSRF_ENABLED", False
    )

    path = rule.rule

    for argument in rule.arguments:
        path = path.replace(f"<int:{argument}>", "1")

    method = sorted(rule.methods - {"HEAD", "OPTIONS"})[0]

    with application.app.test_client() as client:
        response = client.open(
            path,
            method=method,
            base_url="https://localhost",
        )

    assert response.status_code == 401


def test_session_marker_does_not_change_behaviour():
    assert application.require_active_session(
        lambda: None
    ).requires_active_session is True


# Throwaway application

@pytest.fixture
def throwaway_app():
    test_app = Flask(__name__)
    test_app.config["SECRET_KEY"] = "test-only-key"

    @test_app.get("/")
    def home():
        return "home"

    @test_app.get("/admin/export")
    def export_everything():
        return "every voter record"

    @test_app.post("/results/publish")
    @require_permission("results.publish")
    def publish_results():
        return "published"

    @test_app.get("/me")
    @application.require_active_session
    def my_profile():
        return "own profile"

    return test_app


def test_check_catches_unprotected_route(throwaway_app):
    unprotected = find_unprotected_routes(
        throwaway_app, {"static", "home"}
    )

    assert [rule.endpoint for rule in unprotected] == [
        "export_everything"
    ]
    assert unprotected[0].rule == "/admin/export"


def test_unlisted_public_route_is_reported(throwaway_app):
    found = {
        rule.endpoint
        for rule in find_unprotected_routes(throwaway_app, set())
    }

    assert found == {"static", "home", "export_everything"}


def test_blueprint_route_is_checked(throwaway_app):
    from flask import Blueprint

    bp = Blueprint("ballot", __name__, url_prefix="/ballot")

    @bp.post("/cast")
    def cast():
        return "cast"

    throwaway_app.register_blueprint(bp)

    found = {
        rule.endpoint
        for rule in find_unprotected_routes(
            throwaway_app, {"static", "home"}
        )
    }

    assert "ballot.cast" in found


@pytest.mark.parametrize("attribute, value", [
    ("requires_active_session", "yes"),
    ("requires_active_session", 1),
    ("required_permission", ""),
    ("required_permission", None),
    ("required_permission", ["results.publish"]),
])
def test_fake_or_empty_marker_is_not_protection(attribute, value):
    def view():
        return "data"

    setattr(view, attribute, value)

    assert is_protected_view(view) is False


def test_unknown_public_endpoint_is_reported(throwaway_app):
    assert find_unknown_public_endpoints(
        throwaway_app, {"home", "logni"}
    ) == ["logni"]
