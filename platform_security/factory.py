
"""
SR-04: Secure factory for role-specific service objects.

Security controls:
- One service class per role; a class has no method
  for any permission its role does not hold, so a
  low-privilege object cannot call a privileged action
- Each method declares its permission, and the class
  is rejected at import if that permission is not in
  the role's ROLE_PERMISSIONS entry
- Role and login type read from the server-side
  session only, using the same rule as require_permission
- Unknown, missing or mismatched roles raise
  PermissionError (deny by default)

Methods are placeholders. Workstreams B, C and D
connect them to their services later.

Based on the course FactoryPatternPython lab.
Local academic prototype.
"""

from collections.abc import Mapping

from platform_security.rbac import (
    ROLE_PERMISSIONS,
    _login_type,
    _role_matches_login,
)


def grants(permission):
    """Mark a service method with the permission it needs."""

    def decorator(method):
        method.required_permission = permission
        return method

    return decorator


class RoleServices:
    """
    Base class. Holds only the caller identity and
    has no privileged methods of its own.
    """

    role = None

    __slots__ = ("actor_id",)

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        allowed = ROLE_PERMISSIONS.get(cls.role)

        if allowed is None:
            raise TypeError(
                f"{cls.__name__} has no known role"
            )

        for name, member in vars(cls).items():
            if name.startswith("_") or not callable(member):
                continue

            permission = getattr(
                member, "required_permission", None
            )

            if permission not in allowed:
                raise TypeError(
                    f"{cls.__name__}.{name} is not granted "
                    f"to role {cls.role!r}"
                )

    def __init__(self, actor_id):
        if not isinstance(actor_id, str) or not actor_id.strip():
            raise PermissionError(
                "A verified actor ID is required"
            )

        self.actor_id = actor_id

    def _pending(self, owner):
        raise NotImplementedError(
            f"Not yet connected to Workstream {owner}"
        )


class VoterServices(RoleServices):
    role = "voter"
    __slots__ = ()

    @grants("records.read_own")
    def read_own_records(self):
        self._pending("A")

    @grants("records.update_own_address")
    def update_own_address(self, address_text):
        self._pending("A")

    @grants("ballot.request_entitlement")
    def request_ballot_entitlement(self):
        self._pending("C")


class OfficerServices(RoleServices):
    role = "officer"
    __slots__ = ()

    @grants("roll.propose_bulk")
    def propose_bulk_roll_change(self, change):
        self._pending("B")

    @grants("roll.approve_bulk")
    def approve_bulk_roll_change(self, change_id):
        self._pending("B")

    @grants("candidates.read")
    def read_candidates(self):
        self._pending("B")


class DelegateServices(RoleServices):
    role = "delegate"
    __slots__ = ()

    @grants("candidates.enter")
    def enter_candidate(self, candidate):
        self._pending("B")

    @grants("candidates.propose_finalise")
    def propose_finalise_candidates(self):
        self._pending("B")

    @grants("candidates.approve_finalise")
    def approve_finalise_candidates(self, proposal_id):
        self._pending("B")

    @grants("candidates.propose_exclusion")
    def propose_candidate_exclusion(self, candidate_id):
        self._pending("B")

    @grants("candidates.approve_exclusion")
    def approve_candidate_exclusion(self, proposal_id):
        self._pending("B")


class AuditorServices(RoleServices):
    role = "auditor"
    __slots__ = ()

    @grants("audit.read")
    def read_audit_log(self):
        self._pending("B")

    @grants("audit.verify")
    def verify_audit_log(self):
        self._pending("B")

    @grants("tally.run")
    def run_tally(self):
        self._pending("D")

    @grants("bulletin.publish")
    def publish_bulletin(self):
        self._pending("D")


class AdministratorServices(RoleServices):
    role = "administrator"
    __slots__ = ()

    @grants("staff.manage")
    def manage_staff(self, change):
        self._pending("B")

    @grants("results.publish")
    def publish_results(self):
        self._pending("D")

    @grants("config.read")
    def read_config(self):
        self._pending("E")


class AccessObjectFactory:

    _SERVICES = {
        service.role: service
        for service in (
            VoterServices,
            OfficerServices,
            DelegateServices,
            AuditorServices,
            AdministratorServices,
        )
    }

    @classmethod
    def for_session(cls, session_obj):
        """
        Return the service object for the session's
        role. Pass the server-side session only.
        """

        if not isinstance(session_obj, Mapping):
            raise PermissionError("A session is required")

        login_type = _login_type(session_obj)

        if login_type is None:
            raise PermissionError("Authentication required")

        role = session_obj.get("role")

        if (
            not _role_matches_login(role, login_type)
            or role not in cls._SERVICES
        ):
            raise PermissionError("Role not permitted")

        actor_key = (
            "voter_id" if login_type == "voter" else "staff_id"
        )

        return cls._SERVICES[role](session_obj.get(actor_key))
