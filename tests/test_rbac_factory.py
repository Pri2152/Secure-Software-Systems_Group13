
"""
SR-04 tests for the secure access-object factory.

Low-privilege service objects must not even have
methods for high-privilege actions.
"""

import inspect

import pytest

from platform_security.factory import (
    AccessObjectFactory,
    AdministratorServices,
    AuditorServices,
    DelegateServices,
    OfficerServices,
    RoleServices,
    VoterServices,
    grants,
)
from platform_security.rbac import ROLE_PERMISSIONS


SERVICE_FOR_ROLE = {
    "voter": VoterServices,
    "officer": OfficerServices,
    "delegate": DelegateServices,
    "auditor": AuditorServices,
    "administrator": AdministratorServices,
}

ALL_SERVICES = list(SERVICE_FOR_ROLE.values())


def voter_session(role="voter", **extra):
    return {
        "authenticated": True,
        "voter_id": "voter-001",
        "role": role,
        **extra,
    }


def staff_session(role, **extra):
    return {
        "staff_authenticated": True,
        "staff_id": "staff-001",
        "role": role,
        **extra,
    }


def public_methods(service):
    return {
        name
        for name, member in inspect.getmembers(service)
        if not name.startswith("_") and callable(member)
    }


# Factory returns the right class

def test_voter_session_gets_voter_services():
    services = AccessObjectFactory.for_session(voter_session())

    assert type(services) is VoterServices
    assert services.actor_id == "voter-001"


@pytest.mark.parametrize(
    "role", ["officer", "delegate", "auditor", "administrator"]
)
def test_staff_session_gets_matching_services(role):
    services = AccessObjectFactory.for_session(staff_session(role))

    assert type(services) is SERVICE_FOR_ROLE[role]
    assert services.actor_id == "staff-001"


def test_every_role_has_a_service_class():
    assert set(SERVICE_FOR_ROLE) == set(ROLE_PERMISSIONS)


# Unknown, missing or mismatched roles

@pytest.mark.parametrize("role", [
    None, "", "superuser", "Administrator", 1, ["voter"],
])
def test_unknown_or_missing_role_raises(role):
    with pytest.raises(PermissionError):
        AccessObjectFactory.for_session(staff_session(role))


def test_session_without_role_raises():
    session = voter_session()
    del session["role"]

    with pytest.raises(PermissionError):
        AccessObjectFactory.for_session(session)


@pytest.mark.parametrize("session", [
    {},
    {"role": "administrator"},
    {"authenticated": "true", "role": "voter"},
    {"staff_authenticated": 1, "role": "administrator"},
])
def test_unauthenticated_session_raises(session):
    with pytest.raises(PermissionError):
        AccessObjectFactory.for_session(session)


@pytest.mark.parametrize("session", [None, "voter", ["voter"]])
def test_non_session_raises(session):
    with pytest.raises(PermissionError):
        AccessObjectFactory.for_session(session)


def test_voter_login_cannot_get_staff_services():
    with pytest.raises(PermissionError):
        AccessObjectFactory.for_session(voter_session("administrator"))


def test_staff_login_cannot_get_voter_services():
    with pytest.raises(PermissionError):
        AccessObjectFactory.for_session(staff_session("voter"))


def test_ambiguous_session_raises():
    with pytest.raises(PermissionError):
        AccessObjectFactory.for_session(
            voter_session("administrator", staff_authenticated=True)
        )


@pytest.mark.parametrize("session", [
    voter_session(voter_id=None),
    voter_session(voter_id="  "),
    staff_session("auditor", staff_id=None),
])
def test_missing_actor_id_raises(session):
    with pytest.raises(PermissionError):
        AccessObjectFactory.for_session(session)


# Low-privilege classes lack high-privilege methods

def test_voter_services_cannot_publish_results():
    assert not hasattr(VoterServices, "publish_results")
    assert not hasattr(VoterServices, "manage_staff")
    assert not hasattr(VoterServices, "run_tally")


def test_auditor_services_cannot_manage_staff():
    assert not hasattr(AuditorServices, "manage_staff")
    assert not hasattr(AuditorServices, "publish_results")


def test_officer_and_delegate_cannot_tally_or_publish():
    for service in (OfficerServices, DelegateServices):
        assert not hasattr(service, "run_tally")
        assert not hasattr(service, "publish_results")


def test_base_class_has_no_privileged_methods():
    assert public_methods(RoleServices) == set()


@pytest.mark.parametrize("service", ALL_SERVICES, ids=lambda s: s.__name__)
def test_methods_match_role_permissions_exactly(service):
    declared = {
        getattr(service, name).required_permission
        for name in public_methods(service)
    }

    assert declared == set(ROLE_PERMISSIONS[service.role])


@pytest.mark.parametrize("service", ALL_SERVICES, ids=lambda s: s.__name__)
@pytest.mark.parametrize("other", ALL_SERVICES, ids=lambda s: s.__name__)
def test_no_method_is_shared_between_roles(service, other):
    if service is not other:
        assert not public_methods(service) & public_methods(other)


def test_methods_cannot_be_added_to_an_instance():
    services = AccessObjectFactory.for_session(voter_session())

    with pytest.raises(AttributeError):
        services.publish_results = lambda: "published"


def test_class_with_ungranted_method_is_rejected():
    with pytest.raises(TypeError):
        class SneakyVoterServices(RoleServices):
            role = "voter"

            @grants("results.publish")
            def publish_results(self):
                return "published"


def test_class_with_unmarked_method_is_rejected():
    with pytest.raises(TypeError):
        class UnmarkedVoterServices(RoleServices):
            role = "voter"

            def export_roll(self):
                return "every record"


def test_class_with_unknown_role_is_rejected():
    with pytest.raises(TypeError):
        class SuperuserServices(RoleServices):
            role = "superuser"


def test_placeholders_fail_closed():
    services = AccessObjectFactory.for_session(staff_session("administrator"))

    with pytest.raises(NotImplementedError):
        services.publish_results()
