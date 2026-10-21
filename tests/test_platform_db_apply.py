
"""
SR-04 / SR-06 / SR-17 / SR-20 tests for
deploy/scripts/apply_db_security.sh and roles_plan.py.

Static checks on the script, then behaviour checks that
run a copy of it against a fake `docker` command which
records every call and the SQL piped into it. No real
containers or secrets are used.
"""

import ast
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "deploy" / "scripts"
SCRIPT_PATH = SCRIPTS / "apply_db_security.sh"
PLAN_PATH = SCRIPTS / "roles_plan.py"
README_PATH = REPO_ROOT / "deploy" / "README.md"

PASSWORDS = {
    "voter_access_db_password": "V" * 20 + "oterAccessPw_123456789",
    "ballot_db_password": "B" * 20 + "allotWriterPw_12345678",
    "audit_db_password": "A" * 20 + "uditWriterPw_123456789",
    "tally_db_password": "T" * 20 + "allyReaderPw_123456789",
}

ALL_TABLES = (
    "identity_db.enrolment_records identity_db.address_records "
    "identity_db.pending_operations ballot_db.ballots "
    "ballot_db.ballot_keys audit_db.audit_log"
)
NO_BALLOT_TABLES = (
    "identity_db.enrolment_records identity_db.address_records "
    "identity_db.pending_operations audit_db.audit_log"
)


def script_text():
    return SCRIPT_PATH.read_text(encoding="utf-8")


def code_lines():
    return [
        line for line in script_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def load_plan():
    spec = importlib.util.spec_from_file_location("roles_plan", PLAN_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


# Static checks

def test_script_exists_and_is_executable():
    assert SCRIPT_PATH.is_file()
    assert SCRIPT_PATH.stat().st_mode & stat.S_IXUSR


def test_script_uses_bash_and_strict_mode():
    assert script_text().startswith("#!/usr/bin/env bash\n")
    assert "set -euo pipefail" in code_lines()


def test_script_has_sr_docstring():
    header = script_text()[:600]

    for requirement in ("SR-04", "SR-06", "SR-17", "SR-20"):
        assert requirement in header
    assert "Security controls:" in header


def test_root_password_is_read_inside_the_container():
    text = "\n".join(code_lines())

    assert 'MYSQL_PWD="$(cat "$0")"' in text
    assert '"/run/secrets/$(root_secret_for "$service")"' in text
    assert "exec -T" in text

    # Never on a command line, never read on the host.
    assert "--password" not in text
    assert not re.search(r"mysql[^\n]*\s-p\S", text)
    assert "secrets/db_" not in text


def test_script_never_prints_or_stores_passwords():
    text = "\n".join(code_lines())

    for line in code_lines():
        if line.strip().startswith("echo"):
            assert "password" not in line.lower(), line
            assert "$(cat" not in line, line

    assert "set -x" not in text
    assert "mktemp" not in text
    assert "| tee" not in text


def test_script_applies_every_sql_file_to_the_right_container():
    text = "\n".join(code_lines())

    assert 'ROLES_SQL="$DEPLOY_DIR/db/roles.sql"' in text
    assert 'mysql_root db-audit < "$AUDIT_TRIGGERS_SQL"' in text
    assert 'mysql_root db-identity < "$DUAL_TRIGGERS_SQL"' in text
    assert '| mysql_root "$service"' in text


def test_script_does_not_touch_certificates():
    text = "\n".join(code_lines()).lower()

    for word in ("openssl", "certs", ".crt", ".pem", "x509"):
        assert word not in text


def test_plan_has_sr_docstring():
    header = ast.get_docstring(ast.parse(PLAN_PATH.read_text(encoding="utf-8")))

    assert "SR-04" in header and "SR-20" in header
    assert "Security controls:" in header


def test_readme_lists_commands_in_order():
    text = README_PATH.read_text(encoding="utf-8")
    section = text[text.index("## Database accounts and triggers"):]
    order = [
        "bash deploy/scripts/make_secrets.sh",
        "docker compose -f deploy/docker-compose.yml --profile full up -d --build",
        "bash deploy/scripts/apply_db_security.sh",
    ]

    positions = [section.index(command) for command in order]

    assert positions == sorted(positions)
    assert "skipped with a warning" in section


# roles_plan.py

@pytest.fixture
def secrets_dir(tmp_path):
    folder = tmp_path / "secrets"
    folder.mkdir()

    for name, value in PASSWORDS.items():
        (folder / name).write_text(value)

    return folder


ROLES_SQL = REPO_ROOT / "deploy" / "db" / "roles.sql"


def test_plan_sends_each_user_only_to_its_own_server(secrets_dir):
    plan = load_plan()
    expected = {
        "db-identity": {"voter_access"},
        "db-ballot": {"ballot_writer", "tally_reader"},
        "db-audit": {"audit_writer"},
    }

    for service, users in expected.items():
        sql = plan.render(ROLES_SQL, secrets_dir, service)
        mentioned = set(re.findall(r"'([a-z_]+)'@", sql))

        assert mentioned == users, service


def test_plan_grants_match_roles_sql(secrets_dir):
    plan = load_plan()
    audit = plan.render(ROLES_SQL, secrets_dir, "db-audit")

    assert (
        "GRANT SELECT, INSERT ON audit_db.audit_log TO 'audit_writer'@'%';"
        in audit
    )
    assert "UPDATE" not in audit.replace("ALTER USER", "")
    assert "DELETE" not in audit


def test_plan_fills_passwords_and_keeps_them_in_step(secrets_dir):
    plan = load_plan()
    sql = plan.render(ROLES_SQL, secrets_dir, "db-audit")
    password = PASSWORDS["audit_db_password"]

    assert "${" not in sql
    assert f"CREATE USER IF NOT EXISTS 'audit_writer'@'%' IDENTIFIED BY '{password}';" in sql
    assert f"ALTER USER 'audit_writer'@'%' IDENTIFIED BY '{password}';" in sql


def test_plan_skips_listed_tables(secrets_dir):
    plan = load_plan()
    sql = plan.render(
        ROLES_SQL, secrets_dir, "db-ballot",
        " ballot_db.ballots ballot_db.ballot_keys",
    )

    assert "GRANT" not in sql
    assert "CREATE USER IF NOT EXISTS 'ballot_writer'" in sql


def test_plan_targets_cover_every_grant():
    assert load_plan().targets(ROLES_SQL) == [
        "db-identity identity_db enrolment_records",
        "db-identity identity_db address_records",
        "db-ballot ballot_db ballots",
        "db-ballot ballot_db ballot_keys",
        "db-audit audit_db audit_log",
    ]


@pytest.mark.parametrize("bad", [
    "short",
    "x" * 31,
    "y" * 40 + "'; DROP DATABASE audit_db; --",
    "z" * 40 + " space",
])
def test_plan_refuses_weak_or_unsafe_passwords(secrets_dir, bad):
    plan = load_plan()
    (secrets_dir / "audit_db_password").write_text(bad)

    with pytest.raises(plan.PlanError) as error:
        plan.check(ROLES_SQL, secrets_dir)

    assert bad not in str(error.value)


def test_plan_refuses_missing_password_file(secrets_dir):
    plan = load_plan()
    (secrets_dir / "tally_db_password").unlink()

    with pytest.raises(plan.PlanError, match="tally_db_password"):
        plan.check(ROLES_SQL, secrets_dir)


@pytest.mark.parametrize("statement", [
    "DROP DATABASE audit_db;",
    "GRANT ALL ON audit_db.audit_log TO 'audit_writer'@'%';",
    "GRANT UPDATE, DROP ON audit_db.audit_log TO 'audit_writer'@'%';",
    "GRANT SELECT, SUPER ON audit_db.audit_log TO 'audit_writer'@'%';",
    "GRANT SELECT ON *.* TO 'audit_writer'@'%';",
    "GRANT SELECT ON other_db.t TO 'audit_writer'@'%';",
    "GRANT SELECT ON audit_db.audit_log TO 'stranger'@'%';",
    "GRANT SELECT ON identity_db.address_records TO 'audit_writer'@'%';",
])
def test_plan_refuses_unexpected_sql(tmp_path, statement):
    plan = load_plan()
    roles = tmp_path / "roles.sql"
    roles.write_text(ROLES_SQL.read_text() + "\n" + statement + "\n")

    with pytest.raises(plan.PlanError):
        plan.targets(roles)


# Behaviour against a fake docker

FAKE_DOCKER = textwrap.dedent('''\
    import json, os, re, sys

    args = sys.argv[1:]
    log = os.environ["FAKE_DOCKER_LOG"]

    def record(entry):
        with open(log, "a") as handle:
            handle.write(json.dumps(entry) + "\\n")

    if "ps" in args:
        record({{"argv": args}})
        print("\\n".join(os.environ["FAKE_RUNNING"].split()))
        sys.exit(0)

    if "exec" in args:
        service = args[args.index("-T") + 1]
        if "-e" in args:
            query = args[args.index("-e") + 1]
            schema, table = re.search(
                r"table_schema = '(\\w+)' AND table_name = '(\\w+)'", query
            ).groups()
            record({{"argv": args, "service": service, "query": True}})
            tables = os.environ["FAKE_TABLES"].split()
            print("1" if f"{{schema}}.{{table}}" in tables else "0")
            sys.exit(0)

        record({{"argv": args, "service": service, "stdin": sys.stdin.read()}})
        sys.exit(0)

    sys.exit(3)
''')


@pytest.fixture
def sandbox(tmp_path):
    scripts = tmp_path / "deploy" / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(SCRIPT_PATH, scripts / SCRIPT_PATH.name)
    shutil.copy2(PLAN_PATH, scripts / PLAN_PATH.name)
    shutil.copytree(REPO_ROOT / "deploy" / "db", tmp_path / "deploy" / "db")

    secrets = tmp_path / "deploy" / "secrets"
    secrets.mkdir()
    for name, value in PASSWORDS.items():
        (secrets / name).write_text(value)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (tmp_path / "fake_docker.py").write_text(FAKE_DOCKER.format())
    docker = bin_dir / "docker"
    # A shell wrapper, because the repository path contains spaces.
    docker.write_text(
        f'#!/bin/sh\nexec "{sys.executable}" "{tmp_path / "fake_docker.py"}" "$@"\n'
    )
    docker.chmod(0o755)

    return tmp_path


def run_apply(sandbox, tables=ALL_TABLES,
              running="db-identity db-ballot db-audit"):
    log = sandbox / "docker.log"
    log.touch()

    result = subprocess.run(
        ["bash", str(sandbox / "deploy" / "scripts" / SCRIPT_PATH.name)],
        cwd=sandbox,
        env=dict(
            os.environ,
            PATH=f"{sandbox / 'bin'}{os.pathsep}{os.environ['PATH']}",
            FAKE_DOCKER_LOG=str(log),
            FAKE_TABLES=tables,
            FAKE_RUNNING=running,
        ),
        capture_output=True,
        text=True,
    )
    calls = [json.loads(line) for line in log.read_text().splitlines()]

    return result, calls


def applied(calls):
    return [(call["service"], call["stdin"]) for call in calls if "stdin" in call]


def test_applies_roles_then_triggers_to_the_right_containers(sandbox):
    result, calls = run_apply(sandbox)

    assert result.returncode == 0, result.stderr

    sent = applied(calls)

    assert [service for service, _ in sent] == [
        "db-identity", "db-ballot", "db-audit", "db-audit", "db-identity",
    ]
    assert "audit_log_no_update" in sent[3][1]
    assert "pending_operations_two_person_insert" in sent[4][1]
    assert "GRANT SELECT, INSERT ON ballot_db.ballots" in sent[1][1]
    assert "WARNING" not in result.stderr


def test_each_container_gets_only_its_own_password(sandbox):
    _, calls = run_apply(sandbox)
    sent = dict(applied(calls)[:3])

    assert PASSWORDS["voter_access_db_password"] in sent["db-identity"]
    assert PASSWORDS["audit_db_password"] in sent["db-audit"]

    for service, sql in sent.items():
        others = {
            "db-identity": ("ballot_db_password", "tally_db_password",
                            "audit_db_password"),
            "db-ballot": ("voter_access_db_password", "audit_db_password"),
            "db-audit": ("voter_access_db_password", "ballot_db_password",
                         "tally_db_password"),
        }[service]

        for name in others:
            assert PASSWORDS[name] not in sql, (service, name)


def test_passwords_never_printed_or_on_a_command_line(sandbox):
    result, calls = run_apply(sandbox)
    argv = json.dumps([call["argv"] for call in calls])

    for password in PASSWORDS.values():
        assert password not in result.stdout
        assert password not in result.stderr
        assert password not in argv


def test_root_password_comes_from_container_secret(sandbox):
    _, calls = run_apply(sandbox)

    for call in calls:
        if "service" not in call:
            continue

        secret = f"/run/secrets/{call['service'].replace('-', '_')}_root_password"
        assert secret in call["argv"]
        assert "-uroot" in call["argv"][-1] or "-uroot" in " ".join(call["argv"])


def test_missing_ballot_tables_are_skipped_with_warning(sandbox):
    result, calls = run_apply(sandbox, tables=NO_BALLOT_TABLES)

    assert result.returncode == 0, result.stderr
    assert (
        "WARNING: skipping GRANTs on ballot_db.ballots: "
        "the table does not exist yet." in result.stderr
    )
    assert "ballot_db.ballot_keys" in result.stderr

    ballot_sql = dict(applied(calls)[:3])["db-ballot"]

    assert "GRANT" not in ballot_sql
    assert "GRANT SELECT, INSERT ON audit_db.audit_log" in dict(
        applied(calls)[:3]
    )["db-audit"]


@pytest.mark.parametrize("missing", [
    "audit_db.audit_log",
    "identity_db.pending_operations",
])
def test_missing_trigger_table_stops_before_applying(sandbox, missing):
    tables = ALL_TABLES.replace(missing, "")

    result, calls = run_apply(sandbox, tables=tables)

    assert result.returncode != 0
    assert missing in result.stderr
    assert applied(calls) == []


def test_database_not_running_stops_before_applying(sandbox):
    result, calls = run_apply(sandbox, running="db-identity db-audit")

    assert result.returncode != 0
    assert "db-ballot is not running" in result.stderr
    assert applied(calls) == []


def test_missing_password_stops_before_docker_is_used(sandbox):
    (sandbox / "deploy" / "secrets" / "ballot_db_password").unlink()

    result, calls = run_apply(sandbox)

    assert result.returncode != 0
    assert "ballot_db_password" in result.stderr
    assert calls == []


def test_unknown_argument_is_rejected(sandbox):
    result = subprocess.run(
        ["bash", str(sandbox / "deploy" / "scripts" / SCRIPT_PATH.name),
         "--force"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
