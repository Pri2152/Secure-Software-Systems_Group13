
"""
SR-19 tests for backups and the restore drill.

- Static checks on deploy/docker-compose.yml, backup.sh and
  restore.sh (interval, retention, separate volume, strict
  mode, verification step)
- backup.sh run once against a fake mysqldump
- restore.sh run against a fake docker that records every
  call, so the order of operations can be checked
No real containers or secrets are used.
"""

import gzip
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
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
DEPLOY = REPO_ROOT / "deploy"
BACKUP_SCRIPT = DEPLOY / "scripts" / "backup.sh"
RESTORE_SCRIPT = DEPLOY / "scripts" / "restore.sh"
COMPOSE_PATH = DEPLOY / "docker-compose.yml"
README_PATH = DEPLOY / "README.md"

DATABASES = {
    "identity_db": ("db-identity", "db_identity_root_password"),
    "ballot_db": ("db-ballot", "db_ballot_root_password"),
    "audit_db": ("db-audit", "db_audit_root_password"),
}
STAMP = "20261021T093000Z"


@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def backup(compose):
    return compose["services"]["backup"]


def code_lines(path):
    return [line for line in path.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


# Compose: schedule, retention, volume

def test_backup_runs_every_15_minutes(backup):
    assert backup["environment"]["BACKUP_INTERVAL_SECONDS"] == "900"
    assert 'INTERVAL_SECONDS="${BACKUP_INTERVAL_SECONDS:-900}"' in (
        BACKUP_SCRIPT.read_text()
    )


def test_backup_keeps_96_copies(backup):
    assert backup["environment"]["BACKUP_KEEP"] == "96"
    assert 'KEEP="${BACKUP_KEEP:-96}"' in BACKUP_SCRIPT.read_text()


def test_backups_have_their_own_volume(compose, backup):
    assert "backups:/backups" in backup["volumes"]
    assert "backups" in compose["volumes"]

    for name, service in compose["services"].items():
        mounts = " ".join(str(volume) for volume in service.get("volumes", []))

        if name == "backup":
            for data in ("identity_data", "ballot_data", "audit_data"):
                assert data not in mounts
        else:
            assert "backups:" not in mounts, name


def test_backup_runs_the_script_read_only(backup):
    assert backup["entrypoint"] == ["bash", "/usr/local/bin/evp-backup.sh"]
    assert "./scripts/backup.sh:/usr/local/bin/evp-backup.sh:ro" in backup["volumes"]


def test_backup_reads_passwords_from_secret_files(backup):
    assert set(backup["secrets"]) == {
        secret for _, secret in DATABASES.values()
    }

    for key in backup["environment"]:
        assert "PASSWORD" not in key


def test_backup_service_is_hardened_and_watched(backup):
    assert backup["restart"] == "unless-stopped"
    assert backup["read_only"] is True
    assert backup["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in backup["security_opt"]
    assert "-mmin -30" in " ".join(backup["healthcheck"]["test"])
    assert "profiles" not in backup


def test_backup_reaches_only_the_database_networks(backup):
    assert set(backup["networks"]) == {"identity_net", "ballot_net", "audit_net"}


# backup.sh (static)

def test_backup_script_strict_and_documented():
    text = BACKUP_SCRIPT.read_text()

    assert text.startswith("#!/usr/bin/env bash\n")
    assert "SR-19" in text[:200] and "Security controls:" in text
    assert "set -euo pipefail" in code_lines(BACKUP_SCRIPT)
    assert BACKUP_SCRIPT.stat().st_mode & stat.S_IXUSR


def test_backup_uses_single_transaction_for_each_database():
    text = BACKUP_SCRIPT.read_text()

    assert "--single-transaction" in text
    for database, (host, secret) in DATABASES.items():
        assert f"{database}:{host}:{secret}" in text


def test_backup_never_puts_passwords_on_the_command_line():
    text = "\n".join(code_lines(BACKUP_SCRIPT))

    assert 'MYSQL_PWD="$(cat "$SECRETS_DIR/$secret")" mysqldump' in text
    assert "--password" not in text
    assert not re.search(r"\s-p\S", text)  # e.g. -pSECRET


# restore.sh (static)

def test_restore_script_strict_and_documented():
    text = RESTORE_SCRIPT.read_text()

    assert text.startswith("#!/usr/bin/env bash\n")
    assert "SR-19" in text[:200] and "Security controls:" in text
    assert "set -euo pipefail" in code_lines(RESTORE_SCRIPT)
    assert RESTORE_SCRIPT.stat().st_mode & stat.S_IXUSR


def test_restore_has_verification_step():
    text = RESTORE_SCRIPT.read_text()

    assert "# 5. Verify the restored data." in text
    assert "log.verify_chain(stream)" in text
    assert "verify_ballot_store" in text
    assert "is not merged yet" in text


def test_restore_reports_timing():
    text = RESTORE_SCRIPT.read_text()

    for phrase in ("started at", "ended at", "Total duration", "RTO_SECONDS=7200"):
        assert phrase in text


def test_readme_has_drill_commands():
    text = README_PATH.read_text()
    section = text[text.index("## Backup and restore drill"):
                   text.index("## Key rotation")]

    for command in (
        "docker compose -f deploy/docker-compose.yml exec backup bash "
        "/usr/local/bin/evp-backup.sh --once",
        "docker compose -f deploy/docker-compose.yml run --rm --no-deps "
        "--entrypoint ls backup -1 /backups",
        "bash deploy/scripts/restore.sh 20261021T093000Z",
    ):
        assert command in section


# Shell wrapper for fake tools (the repo path contains spaces)

def install_fake(bin_dir, name, script):
    source = bin_dir / f"fake_{name}.py"
    source.write_text(script)
    tool = bin_dir / name
    tool.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{source}" "$@"\n')
    tool.chmod(0o755)


# backup.sh behaviour

FAKE_MYSQLDUMP = textwrap.dedent('''\
    import json, os, sys
    args = sys.argv[1:]
    database = args[args.index("--databases") + 1]
    with open(os.environ["FAKE_LOG"], "a") as log:
        log.write(json.dumps({"argv": args,
                              "password": os.environ.get("MYSQL_PWD")}) + "\\n")
    if database == os.environ.get("FAKE_FAIL_DB"):
        sys.exit(2)
    sys.stdout.write(f"-- dump of {database}\\n")
''')


@pytest.fixture
def backup_sandbox(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    install_fake(bin_dir, "mysqldump", FAKE_MYSQLDUMP)

    secrets = tmp_path / "secrets"
    secrets.mkdir()
    for database, (_, secret) in DATABASES.items():
        (secrets / secret).write_text(f"root-pw-{database}-0123456789")

    backups = tmp_path / "backups"
    backups.mkdir()

    return tmp_path


def run_backup(sandbox, *arguments, **env):
    log = sandbox / "mysqldump.log"
    log.touch()
    result = subprocess.run(
        ["bash", str(BACKUP_SCRIPT), *arguments],
        env={**os.environ,
             "PATH": f"{sandbox / 'bin'}{os.pathsep}{os.environ['PATH']}",
             "BACKUP_DIR": str(sandbox / "backups"),
             "BACKUP_SECRETS_DIR": str(sandbox / "secrets"),
             "FAKE_LOG": str(log), **env},
        capture_output=True, text=True,
    )
    calls = [json.loads(line) for line in log.read_text().splitlines()]

    return result, calls


def backup_folders(sandbox):
    return sorted(path.name for path in (sandbox / "backups").iterdir())


def test_one_backup_holds_all_three_databases(backup_sandbox):
    result, calls = run_backup(backup_sandbox, "--once")

    assert result.returncode == 0, result.stderr

    [stamp] = backup_folders(backup_sandbox)

    assert re.fullmatch(r"\d{8}T\d{6}Z", stamp)

    for database in DATABASES:
        dump = backup_sandbox / "backups" / stamp / f"{database}.sql.gz"
        assert gzip.decompress(dump.read_bytes()).decode() == (
            f"-- dump of {database}\n"
        )
        assert stat.S_IMODE(dump.stat().st_mode) == 0o600

    for call, (database, (host, _)) in zip(calls, DATABASES.items()):
        assert "--single-transaction" in call["argv"]
        assert f"--host={host}" in call["argv"]
        assert call["argv"][-2:] == ["--databases", database]


def test_passwords_come_from_secret_files_not_arguments(backup_sandbox):
    result, calls = run_backup(backup_sandbox, "--once")

    for call, database in zip(calls, DATABASES):
        assert call["password"] == f"root-pw-{database}-0123456789"
        assert call["password"] not in " ".join(call["argv"])
        assert call["password"] not in result.stdout + result.stderr


def test_keeps_only_the_newest_96(backup_sandbox):
    for day in range(1, 5):
        for hour in range(25):
            (backup_sandbox / "backups" / f"202601{day:02d}T{hour:02d}0000Z").mkdir()

    result, _ = run_backup(backup_sandbox, "--once")
    folders = backup_folders(backup_sandbox)

    assert result.returncode == 0, result.stderr
    # 100 old backups + the new one = 101; the 5 oldest are removed.
    assert len(folders) == 96
    assert folders[0] == "20260101T050000Z"
    assert folders[-1] > "20260104T240000Z"  # the new one is kept


def test_failed_dump_leaves_no_partial_backup(backup_sandbox):
    (backup_sandbox / "backups" / "20260101T000000Z").mkdir()

    result, _ = run_backup(backup_sandbox, "--once", FAKE_FAIL_DB="ballot_db")

    assert result.returncode != 0
    assert "failed while dumping ballot_db" in result.stderr
    assert backup_folders(backup_sandbox) == ["20260101T000000Z"]


def test_interrupted_partial_backup_is_cleaned_up(backup_sandbox):
    (backup_sandbox / "backups" / ".partial-20260101T000000Z").mkdir()

    run_backup(backup_sandbox, "--once")

    assert not any(name.startswith(".partial")
                   for name in backup_folders(backup_sandbox))


@pytest.mark.parametrize("setting", ["BACKUP_KEEP", "BACKUP_INTERVAL_SECONDS"])
@pytest.mark.parametrize("value", ["0", "-1", "abc", ""])
def test_bad_settings_are_refused(backup_sandbox, setting, value):
    result, calls = run_backup(backup_sandbox, "--once", **{setting: value})

    if value == "":
        # Empty means "use the default".
        assert result.returncode == 0
    else:
        assert result.returncode == 2
        assert calls == []


# restore.sh behaviour

FAKE_DOCKER = textwrap.dedent('''\
    import json, os, sys
    args = sys.argv[1:]
    state_path = os.environ["FAKE_STATE"]
    with open(state_path) as handle:
        running = handle.read().split()

    def record(**entry):
        with open(os.environ["FAKE_LOG"], "a") as log:
            log.write(json.dumps({"argv": args, **entry}) + "\\n")

    def save(services):
        with open(state_path, "w") as handle:
            handle.write(" ".join(services))

    if "ps" in args:
        record(kind="ps")
        print("\\n".join(running))
    elif "stop" in args:
        names = args[args.index("stop") + 1:]
        record(kind="stop", services=names)
        save([s for s in running if s not in names])
    elif "start" in args:
        names = args[args.index("start") + 1:]
        record(kind="start", services=names)
        save(running + names)
    elif "run" in args:
        if "-t" in args:
            record(kind="gzip-test")
            sys.exit(1 if os.environ.get("FAKE_DAMAGED") else 0)
        path = args[-1]
        record(kind="read", path=path)
        sys.stdout.write(f"-- dump from {path}\\n")
    elif "exec" in args:
        service = args[args.index("-T") + 1]
        data = sys.stdin.read() if not sys.stdin.isatty() else ""
        record(kind="exec", service=service, stdin=data)
        if service == os.environ.get("FAKE_MYSQL_FAIL"):
            sys.exit(1)
        if service == "admin-audit":
            sys.exit(int(os.environ.get("FAKE_AUDIT_EXIT", "0")))
        if service == "ballot":
            sys.exit(int(os.environ.get("FAKE_BALLOT_EXIT", "0")))
    else:
        sys.exit(3)
''')

ALL_RUNNING = ("gateway voter-access-1 voter-access-2 admin-audit backup "
               "db-identity db-ballot db-audit")


@pytest.fixture
def restore_sandbox(tmp_path):
    scripts = tmp_path / "deploy" / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(RESTORE_SCRIPT, scripts / RESTORE_SCRIPT.name)

    audit = tmp_path / "audit"
    audit.mkdir()
    (audit / "chain.py").write_text("")
    (audit / "__init__.py").write_text("def verify_chain(stream): ...\n")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    install_fake(bin_dir, "docker", FAKE_DOCKER)

    return tmp_path


def run_restore(sandbox, stamp=STAMP, running=ALL_RUNNING, **env):
    log = sandbox / "docker.log"
    log.write_text("")
    state = sandbox / "running.txt"
    state.write_text(running)

    result = subprocess.run(
        ["bash", str(sandbox / "deploy" / "scripts" / RESTORE_SCRIPT.name),
         stamp],
        env={**os.environ,
             "PATH": f"{sandbox / 'bin'}{os.pathsep}{os.environ['PATH']}",
             "FAKE_LOG": str(log), "FAKE_STATE": str(state), **env},
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    calls = [json.loads(line) for line in log.read_text().splitlines()]

    return result, calls


def kinds(calls):
    return [call["kind"] for call in calls]


def test_restore_order_of_operations(restore_sandbox):
    result, calls = run_restore(restore_sandbox)

    assert result.returncode == 0, result.stderr
    assert kinds(calls) == [
        "gzip-test", "ps", "stop",
        "read", "exec", "read", "exec", "read", "exec",
        "start", "ps", "exec",
    ]


def test_restore_stops_only_running_app_services(restore_sandbox):
    _, calls = run_restore(restore_sandbox)
    [stop] = [call for call in calls if call["kind"] == "stop"]
    [start] = [call for call in calls if call["kind"] == "start"]

    assert stop["services"] == ["voter-access-1", "voter-access-2",
                                "admin-audit", "backup"]
    assert start["services"] == stop["services"]


def test_each_database_restored_into_its_own_container(restore_sandbox):
    _, calls = run_restore(restore_sandbox)
    restores = [call for call in calls
                if call["kind"] == "exec" and call["service"].startswith("db-")]

    assert [call["service"] for call in restores] == [
        "db-identity", "db-ballot", "db-audit"]

    for call, (database, (_, secret)) in zip(restores, DATABASES.items()):
        assert call["stdin"] == f"-- dump from /backups/{STAMP}/{database}.sql.gz\n"
        assert f"/run/secrets/{secret}" in call["argv"]


def test_audit_chain_is_verified_after_restart(restore_sandbox):
    result, calls = run_restore(restore_sandbox)
    [check] = [call for call in calls
               if call["kind"] == "exec" and call["service"] == "admin-audit"]

    assert "log.verify_chain(stream)" in check["stdin"]
    assert "Audit chain check passed" in result.stdout


def test_ballot_check_warns_when_not_merged(restore_sandbox):
    result, _ = run_restore(restore_sandbox)

    assert ("WARNING: Workstream C's verify_ballot_store is not merged yet"
            in result.stderr)


def test_ballot_check_runs_when_merged(restore_sandbox):
    ballot = restore_sandbox / "ballot"
    ballot.mkdir()
    (ballot / "__init__.py").write_text("def verify_ballot_store(): ...\n")

    result, calls = run_restore(restore_sandbox,
                                running=ALL_RUNNING + " ballot")

    assert result.returncode == 0, result.stderr
    assert any(call.get("service") == "ballot" for call in calls)
    assert "Ballot store check passed" in result.stdout


def test_failed_ballot_check_fails_the_drill(restore_sandbox):
    ballot = restore_sandbox / "ballot"
    ballot.mkdir()
    (ballot / "__init__.py").write_text("def verify_ballot_store(): ...\n")

    result, _ = run_restore(restore_sandbox, running=ALL_RUNNING + " ballot",
                            FAKE_BALLOT_EXIT="1")

    assert result.returncode == 1
    assert "Ballot store check FAILED" in result.stderr


def test_audit_warning_when_not_merged(restore_sandbox):
    shutil.rmtree(restore_sandbox / "audit")

    result, _ = run_restore(restore_sandbox)

    assert result.returncode == 0
    assert ("WARNING: Workstream B's audit chain check is not merged yet"
            in result.stderr)


def test_broken_audit_chain_fails_the_drill(restore_sandbox):
    result, _ = run_restore(restore_sandbox, FAKE_AUDIT_EXIT="1")

    assert result.returncode == 1
    assert "Audit chain check FAILED" in result.stderr
    assert "Total duration" in result.stdout


def test_prints_start_end_and_duration(restore_sandbox):
    result, _ = run_restore(restore_sandbox)

    assert re.search(rf"Restore of backup {STAMP} started at "
                     r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC", result.stdout)
    assert re.search(rf"Restore of backup {STAMP} ended at "
                     r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC", result.stdout)
    assert re.search(r"Total duration: \d+m \d\ds \(within the 2 hour RTO\)",
                     result.stdout)


def test_damaged_backup_changes_nothing(restore_sandbox):
    result, calls = run_restore(restore_sandbox, FAKE_DAMAGED="1")

    assert result.returncode == 1
    assert "missing or damaged; nothing was changed" in result.stderr
    assert kinds(calls) == ["gzip-test"]


def test_failed_restore_leaves_services_stopped(restore_sandbox):
    result, calls = run_restore(restore_sandbox, FAKE_MYSQL_FAIL="db-ballot")

    assert result.returncode != 0
    assert "Restore FAILED" in result.stderr
    assert "left stopped: voter-access-1 voter-access-2 admin-audit backup" in (
        result.stderr
    )
    assert "start" not in kinds(calls)


@pytest.mark.parametrize("stamp", ["latest", "2026-10-21", "../etc",
                                   "20261021T093000", "20261021T093000Z;rm"])
def test_bad_timestamp_is_refused(restore_sandbox, stamp):
    result, calls = run_restore(restore_sandbox, stamp=stamp)

    assert result.returncode == 2
    assert calls == []
