
"""
SR-20 and SR-04 tests for the shared application.

- Separate ballot and audit database binds
- Voter role set in the server-side session at login

Reuses the Workstream A integration helpers.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import inspect, text

import app as application

from records import db
from test_main_integration import environment, login  # noqa: F401


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_three_separate_engines():
    with application.app.app_context():
        engines = db.engines

        assert set(engines) == {None, "ballot", "audit"}
        assert len({id(engine) for engine in engines.values()}) == 3


def test_binds_default_to_in_memory_sqlite():
    binds = application.app.config["SQLALCHEMY_BINDS"]

    for name, variable in (
        ("ballot", "EVP_BALLOT_DB_URL"),
        ("audit", "EVP_AUDIT_DB_URL"),
    ):
        assert binds[name] == os.environ.get(
            variable, "sqlite:///:memory:"
        )

    assert (
        application.app.config["SQLALCHEMY_DATABASE_URI"]
        == "sqlite:///:memory:"
    )


def test_bind_databases_do_not_share_tables():
    with application.app.app_context():
        with db.engines["ballot"].begin() as connection:
            connection.execute(
                text("CREATE TABLE bind_probe (id INTEGER)")
            )

        try:
            assert inspect(db.engines["ballot"]).has_table("bind_probe")
            assert not inspect(db.engines["audit"]).has_table("bind_probe")
            assert not inspect(db.engines[None]).has_table("bind_probe")
        finally:
            with db.engines["ballot"].begin() as connection:
                connection.execute(text("DROP TABLE bind_probe"))


def test_bind_urls_come_from_environment(tmp_path):
    # A fresh interpreter, so the shared app is not re-imported.
    child_env = dict(
        os.environ,
        EVP_BALLOT_DB_URL=f"sqlite:///{tmp_path / 'ballot.db'}",
        EVP_AUDIT_DB_URL=f"sqlite:///{tmp_path / 'audit.db'}",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import json, app; "
            "print(json.dumps(app.app.config['SQLALCHEMY_BINDS']))",
        ],
        cwd=REPO_ROOT,
        env=child_env,
        capture_output=True,
        text=True,
        check=True,
    )

    assert json.loads(result.stdout.strip().splitlines()[-1]) == {
        "ballot": child_env["EVP_BALLOT_DB_URL"],
        "audit": child_env["EVP_AUDIT_DB_URL"],
    }


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
