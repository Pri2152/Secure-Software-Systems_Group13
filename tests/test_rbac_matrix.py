
"""
SR-04 tests for the complete role-permission matrix.

EXPECTED_PERMISSIONS is written out by hand and is
deliberately not copied from ROLE_PERMISSIONS, so an
accidental grant or removal in rbac.py fails the build.

When Workstream B confirms the staff roles (SR-06),
update rbac.py, docs/RBAC_MATRIX.md and this table.
"""

import itertools

import pytest

from platform_security.rbac import ROLE_PERMISSIONS, has_permission


EXPECTED_PERMISSIONS = {
    "voter": {
        "records.read_own",
        "records.update_own_address",
        "ballot.request_entitlement",
    },
    "officer": {
        "roll.propose_bulk",
        "roll.approve_bulk",
        "candidates.read",
    },
    "delegate": {
        "candidates.enter",
        "candidates.propose_finalise",
        "candidates.approve_finalise",
        "candidates.propose_exclusion",
        "candidates.approve_exclusion",
    },
    "auditor": {
        "audit.read",
        "audit.verify",
        "tally.run",
        "bulletin.publish",
    },
    "administrator": {
        "staff.manage",
        "results.publish",
        "config.read",
    },
}


ROLES = sorted(EXPECTED_PERMISSIONS)

# Include any permission found only in the code, so an
# extra grant in rbac.py is also checked against the table.
ALL_PERMISSIONS = sorted(
    set().union(*EXPECTED_PERMISSIONS.values())
    | set().union(*ROLE_PERMISSIONS.values())
)


@pytest.mark.parametrize(
    "role, permission",
    list(itertools.product(ROLES, ALL_PERMISSIONS)),
)
def test_permission_granted_exactly_when_listed(role, permission):
    expected = permission in EXPECTED_PERMISSIONS[role]

    assert has_permission(role, permission) is expected


def test_code_defines_exactly_the_expected_roles():
    assert set(ROLE_PERMISSIONS) == set(EXPECTED_PERMISSIONS)


def test_code_matrix_matches_expected_table():
    assert {
        role: set(permissions)
        for role, permissions in ROLE_PERMISSIONS.items()
    } == EXPECTED_PERMISSIONS


@pytest.mark.parametrize("role", [
    "superuser",
    "root",
    "admin",
    "Administrator",
    "VOTER",
    " voter",
    "voter ",
    "",
])
@pytest.mark.parametrize("permission", ALL_PERMISSIONS)
def test_unknown_role_is_denied(role, permission):
    assert has_permission(role, permission) is False


@pytest.mark.parametrize("permission", ALL_PERMISSIONS)
def test_none_role_is_denied(permission):
    assert has_permission(None, permission) is False


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("permission", [
    "results.publish_all",
    "audit.delete",
    "records.read_all",
    "*",
    "",
    "Results.Publish",
    None,
])
def test_unknown_permission_is_denied(role, permission):
    assert has_permission(role, permission) is False


@pytest.mark.parametrize("role", [
    1,
    0,
    True,
    1.5,
    b"voter",
    ["voter"],
    ("voter",),
    {"voter"},
    {"role": "voter"},
])
@pytest.mark.parametrize("permission", ALL_PERMISSIONS)
def test_non_string_role_is_denied(role, permission):
    assert has_permission(role, permission) is False


@pytest.mark.parametrize("permission", [
    1,
    ["ballot.request_entitlement"],
    ("ballot.request_entitlement",),
    {"ballot.request_entitlement"},
])
def test_non_string_permission_is_denied(permission):
    assert has_permission("voter", permission) is False
