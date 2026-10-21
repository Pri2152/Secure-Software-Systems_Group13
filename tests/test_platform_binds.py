
"""
SR-20 and SR-04 tests for the shared application.

- Ballot and audit database binds only when configured
- Voter role set in the server-side session at login

Reuses the Workstream A integration helpers.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import app as application

from test_main_integration import environment, login  # noqa: F401


REPO_ROOT = Path(__file__).resolve().parent.parent


BIND_VARIABLES = ("EVP_BALLOT_DB_URL", "EVP_AUDIT_DB_URL")

# Runs in a fresh interpreter, so the shared app is not re-imported.
# Prints the configured binds, the engine names, and which engines
# can see a table created only on the ballot engine.
PROBE = """
import json
import app
from records import db
from sqlalchemy import inspect, text

with app.app.app_context():
    engines = db.engines
    seen = {}

    if "ballot" in engines:
        with engines["ballot"].begin() as connection:
            connection.execute(text("CREATE TABLE bind_probe (id INTEGER)"))

        seen = {
            str(name): inspect(engine).has_table("bind_probe")
            for name, engine in engines.items()
        }

    print(json.dumps({
        "binds": app.app.config["SQLALCHEMY_BINDS"],
        "engines": sorted(str(name) for name in engines),
        "distinct": len({id(engine) for engine in engines.values()}),
        "seen": seen,
    }))
"""


def run_probe(**variables):
    child_env = {
        key: value for key, value in os.environ.items()
        if key not in BIND_VARIABLES
    }
    child_env.update(variables)

    result = subprocess.run(
        [sys.executable, "-c", PROBE],
        cwd=REPO_ROOT,
        env=child_env,
        capture_output=True,
        text=True,
        check=True,
    )

    return json.loads(result.stdout.strip().splitlines()[-1])


def test_no_binds_by_default():
    probe = run_probe()

    assert probe["binds"] == {}
    assert probe["engines"] == ["None"]


def test_empty_variables_add_no_binds():
    probe = run_probe(EVP_BALLOT_DB_URL="", EVP_AUDIT_DB_URL="")

    assert probe["binds"] == {}


def test_both_binds_present_and_separate_when_set(tmp_path):
    ballot_url = f"sqlite:///{tmp_path / 'ballot.db'}"
    audit_url = f"sqlite:///{tmp_path / 'audit.db'}"

    probe = run_probe(
        EVP_BALLOT_DB_URL=ballot_url, EVP_AUDIT_DB_URL=audit_url
    )

    assert probe["binds"] == {"ballot": ballot_url, "audit": audit_url}
    assert probe["engines"] == ["None", "audit", "ballot"]
    assert probe["distinct"] == 3
    assert probe["seen"] == {"None": False, "ballot": True, "audit": False}


def test_each_bind_is_independent(tmp_path):
    ballot_url = f"sqlite:///{tmp_path / 'ballot.db'}"

    probe = run_probe(EVP_BALLOT_DB_URL=ballot_url)

    assert probe["binds"] == {"ballot": ballot_url}


def test_main_database_unchanged():
    assert (
        application.app.config["SQLALCHEMY_DATABASE_URI"]
        == "sqlite:///:memory:"
    )


def test_login_sets_voter_role(environment):  # noqa: F811
    client, now = environment

    assert login(client, now).status_code == 200

    with client.session_transaction() as active_session:
        assert active_session["authenticated"] is True
        assert active_session["voter_id"] == "voter-001"
        assert active_session["role"] == "voter"


def test_login_replaces_any_earlier_role(environment):  # noqa: F811
    client, now = environment

    # A role left in a pre-login session must not survive login.
    with client.session_transaction() as active_session:
        active_session["role"] = "administrator"

    assert login(client, now).status_code == 200

    with client.session_transaction() as active_session:
        assert active_session["role"] == "voter"


def test_failed_login_sets_no_role(environment):  # noqa: F811
    client, now = environment

    assert login(client, now, password="WrongPassword").status_code == 401

    with client.session_transaction() as active_session:
        assert "role" not in active_session
