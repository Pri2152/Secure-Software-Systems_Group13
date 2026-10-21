
"""
SR-04 / SR-20 static tests for deploy/db/roles.sql.

Checks least-privilege GRANTs per service, the
insert-only ballot table, the append-only audit log, and that no
literal password is committed.
"""

import re
from pathlib import Path

import pytest


ROLES_PATH = (
    Path(__file__).resolve().parent.parent
    / "deploy" / "db" / "roles.sql"
)

EXPECTED_USERS = {
    "voter_access",
    "ballot_writer",
    "audit_writer",
    "tally_reader",
}

GRANT_PATTERN = re.compile(
    r"GRANT\s+(?P<privileges>.+?)\s+ON\s+(?P<target>\S+)\s+"
    r"TO\s+'(?P<user>[^']+)'@'[^']+'\s*(?P<rest>.*)",
    re.IGNORECASE | re.DOTALL,
)

CREATE_USER_PATTERN = re.compile(
    r"CREATE\s+USER\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    r"'(?P<user>[^']+)'@'[^']+'\s+IDENTIFIED\s+BY\s+'(?P<password>[^']*)'",
    re.IGNORECASE,
)


def statements():
    text = ROLES_PATH.read_text(encoding="utf-8")
    text = re.sub(r"--[^\n]*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)

    return [
        " ".join(statement.split())
        for statement in text.split(";")
        if statement.strip()
    ]


def grants():
    found = []

    for statement in statements():
        if not statement.upper().startswith("GRANT"):
            continue

        match = GRANT_PATTERN.fullmatch(statement)
        assert match, f"Unparsed GRANT: {statement}"

        privileges = {
            privilege.strip().upper()
            for privilege in match["privileges"].split(",")
        }

        found.append((
            match["user"],
            privileges,
            match["target"].replace("`", "").lower(),
            match["rest"],
        ))

    return found


def privileges_for(user, target):
    return set().union(*(
        privileges
        for grant_user, privileges, grant_target, _ in grants()
        if grant_user == user and grant_target == target
    ))


def test_file_parses_into_grants():
    assert len(grants()) >= 6


def test_one_user_per_service():
    created = [
        CREATE_USER_PATTERN.search(statement)["user"]
        for statement in statements()
        if statement.upper().startswith("CREATE USER")
    ]

    assert sorted(created) == sorted(EXPECTED_USERS)


def test_every_grant_targets_a_created_user():
    assert {user for user, _, _, _ in grants()} <= EXPECTED_USERS


def test_no_grant_all():
    for _, privileges, _, _ in grants():
        assert "ALL" not in privileges
        assert "ALL PRIVILEGES" not in privileges

    for statement in statements():
        assert not re.search(r"\bGRANT\s+ALL\b", statement, re.IGNORECASE)


def test_no_wildcard_grants():
    for _, _, target, _ in grants():
        database, _, table = target.partition(".")

        assert "*" not in database
        assert table and table != "*"


def test_no_grant_option():
    for _, _, _, rest in grants():
        assert "GRANT OPTION" not in rest.upper()


@pytest.mark.parametrize("privilege", ["SUPER", "FILE", "PROCESS",
                                       "CREATE USER", "DROP", "ALTER"])
def test_no_administrative_privileges(privilege):
    for _, privileges, _, _ in grants():
        assert privilege not in privileges


@pytest.mark.parametrize("target", [
    "ballot_db.ballots",
    "audit_db.audit_log",
])
def test_protected_tables_have_no_update_or_delete(target):
    for _, privileges, grant_target, _ in grants():
        if grant_target == target:
            assert not privileges & {"UPDATE", "DELETE", "DROP", "ALTER"}


def test_ballot_writer_can_only_add_ballots():
    assert privileges_for(
        "ballot_writer", "ballot_db.ballots"
    ) == {"SELECT", "INSERT"}


def test_audit_writer_can_only_read_and_append():
    # SELECT lets Workstream B read the last entry to chain the next.
    assert {
        target: privileges
        for user, privileges, target, _ in grants()
        if user == "audit_writer"
    } == {"audit_db.audit_log": {"SELECT", "INSERT"}}


def test_audit_log_can_never_be_changed_or_removed():
    for user, privileges, target, _ in grants():
        if target.startswith("audit_db."):
            assert user == "audit_writer", user
            assert not privileges & {"UPDATE", "DELETE", "DROP", "ALTER",
                                     "TRUNCATE", "INDEX", "TRIGGER",
                                     "REFERENCES", "CREATE"}, privileges


def test_tally_is_read_only():
    tally = [
        (privileges, target)
        for user, privileges, target, _ in grants()
        if user == "tally_reader"
    ]

    assert tally
    for privileges, target in tally:
        assert privileges == {"SELECT"}
        assert target.startswith("ballot_db.")


def test_voter_access_stays_in_identity_db():
    for user, privileges, target, _ in grants():
        if user == "voter_access":
            assert target.startswith("identity_db.")
            assert "DELETE" not in privileges


def test_only_voter_access_reaches_identity_db():
    for user, _, target, _ in grants():
        if target.startswith("identity_db."):
            assert user == "voter_access"


def test_passwords_are_environment_placeholders():
    passwords = {
        match["user"]: match["password"]
        for statement in statements()
        if (match := CREATE_USER_PATTERN.search(statement))
    }

    assert set(passwords) == EXPECTED_USERS

    for password in passwords.values():
        assert re.fullmatch(r"\$\{[A-Z][A-Z0-9_]*_PASSWORD\}", password)

    assert len(set(passwords.values())) == len(passwords)


def test_no_literal_password_anywhere():
    text = ROLES_PATH.read_text(encoding="utf-8")

    for match in re.finditer(
        r"(IDENTIFIED\s+(?:WITH\s+\S+\s+)?BY|PASSWORD\s*\()\s*'([^']*)'",
        text,
        re.IGNORECASE,
    ):
        assert re.fullmatch(r"\$\{[A-Z0-9_]+\}", match.group(2))

    assert not re.search(r"IDENTIFIED\s+BY\s+PASSWORD", text, re.IGNORECASE)
    assert not re.search(r"\bSET\s+PASSWORD\b", text, re.IGNORECASE)
