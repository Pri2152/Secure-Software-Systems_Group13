
"""
SR-19 tests for GET /healthz (platform_security/health.py).

- 200 {"status": "ok"} without a session, and nothing else
- Answers before Workstream A's SR-07 gateway check, but only
  for GET/HEAD /healthz; every other request is still checked
- Works in the Docker set-up (gateway_runtime with SR-07 on)
"""

import ast
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import app as application
from platform_security import health
from test_platform_gateway_trust import subprocess_env


REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def client():
    with application.app.test_client() as test_client:
        yield test_client


@pytest.fixture
def gateway_enforced(monkeypatch):
    """SR-07 on, as in Docker, with a request that is not from Nginx."""

    monkeypatch.setitem(application.app.config, "SR07_GATEWAY_ENFORCED", True)
    monkeypatch.setitem(application.app.config, "MISSION_ACCESS_POLICY",
                        object())


def test_healthz_returns_ok_without_session(client):
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}
    assert response.get_data(as_text=True).strip() == '{"status":"ok"}'


def test_healthz_reveals_nothing_else(client):
    response = client.get("/healthz")

    assert "Set-Cookie" not in response.headers
    assert response.headers["Cache-Control"] == "no-store"
    assert response.mimetype == "application/json"

    for word in ("voter", "version", "python", "flask", "db", "session"):
        assert word not in response.get_data(as_text=True).lower()


def test_healthz_ignores_session_and_query(client):
    with client.session_transaction() as active_session:
        active_session["authenticated"] = True
        active_session["voter_id"] = "voter-001"

    response = client.get("/healthz?verbose=1&debug=true")

    assert response.get_json() == {"status": "ok"}


def test_head_healthz(client):
    assert client.head("/healthz").status_code == 200


def test_healthz_is_registered_on_the_app():
    endpoints = {rule.endpoint: rule.rule
                 for rule in application.app.url_map.iter_rules()}

    assert endpoints["health.healthz"] == "/healthz"


# Before SR-07

def test_healthz_answers_with_sr07_enforced(client, gateway_enforced):
    response = client.get("/healthz", environ_overrides={
        "REMOTE_ADDR": "127.0.0.1"})

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


@pytest.mark.parametrize("method, path", [
    ("get", "/"),
    ("get", "/session-status"),
    ("get", "/records/addresses/201"),
    ("get", "/healthz/"),
    ("get", "/healthzz"),
    ("get", "/HEALTHZ"),
    ("post", "/healthz"),
    ("put", "/healthz"),
    ("delete", "/healthz"),
])
def test_everything_else_still_goes_through_sr07(client, gateway_enforced,
                                                 method, path):
    response = getattr(client, method)(path, environ_overrides={
        "REMOTE_ADDR": "127.0.0.1"})

    # The fake policy object makes SR-07 fail closed (503); the point
    # is that the health shortcut did not answer these requests.
    assert response.status_code in (403, 503), path
    assert response.get_json() != {"status": "ok"}


def test_health_shortcut_runs_first():
    first = application.app.before_request_funcs[None][0]

    assert first is health._answer_health_check


def test_health_shortcut_is_installed_only_once():
    funcs = application.app.before_request_funcs[None]

    assert funcs.count(health._answer_health_check) == 1


# Docker set-up: gateway_runtime with SR-07 enforced

DOCKER_PROBE = textwrap.dedent("""
    import json, pathlib

    fake_files = {
        "/run/evp/registered_fingerprints.txt": "ab" * 32 + "\\n",
        "/run/evp/demo-voter.json": json.dumps({
            "account_id": "demo-voter",
            "password": "synthetic-test-only",
            "totp_secret": "JBSWY3DPEHPK3PXP",
        }),
    }
    original = pathlib.Path.read_text

    def fake_read_text(self, *args, **kwargs):
        if str(self) in fake_files:
            return fake_files[str(self)]
        return original(self, *args, **kwargs)

    pathlib.Path.read_text = fake_read_text

    import gateway_runtime

    client = gateway_runtime.application.test_client()
    local = {"REMOTE_ADDR": "127.0.0.1"}
    results = {}
    for path in ("/healthz", "/session-status", "/records/addresses/801"):
        response = client.get(path, environ_overrides=local)
        results[path] = [response.status_code, response.get_json()]
    print(json.dumps(results))
""")


def test_docker_health_check_passes_and_sr07_still_applies():
    result = subprocess.run(
        [sys.executable, "-c", DOCKER_PROBE],
        cwd=REPO_ROOT,
        env=subprocess_env(
            EVP_LOCAL_LAB="1",
            EVP_CRYPTO_DEV_KEYS="1",
            EVP_TRUSTED_GATEWAY_NETWORKS="172.30.0.10/32",
        ),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr

    results = json.loads(result.stdout.splitlines()[-1])

    assert results["/healthz"] == [200, {"status": "ok"}]
    assert results["/session-status"] == [403, {"error": "Access denied"}]
    assert results["/records/addresses/801"] == [403, {"error": "Access denied"}]


def test_health_module_has_sr19_docstring():
    source = (REPO_ROOT / "platform_security" / "health.py").read_text()
    docstring = ast.get_docstring(ast.parse(source))

    assert docstring.startswith("SR-19")
    assert "Security controls:" in docstring
