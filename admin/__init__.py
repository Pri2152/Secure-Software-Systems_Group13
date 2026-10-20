"""
SR-02: Privileged staff access (Workstream B).

Security controls:
- Person-linked staff accounts; generic or shared
  names are refused and each client certificate
  belongs to exactly one account
- Phishing-resistant login: a client certificate
  verified by the Nginx mTLS gateway (reusing
  Workstream A's SR-07 adapter) plus an Argon2id
  password, with one generic error and the SR-01
  rate limiter
- Staff sessions with exactly the SR-04 RBAC keys,
  session ID regeneration and a 10-minute idle timeout
- Just-in-time elevation: per permission, after
  step-up re-authentication, for at most 15 minutes,
  stored server-side; require_elevated protects every
  privileged route
- Every login, step-up, elevation, expiry and revoke
  is audited on the admin stream (SR-17)
- SR-06 maker-checker: candidate-list finalisation,
  court-ordered exclusion and bulk roll updates need a
  proposer and a different approver, both elevated;
  approval is bound to the payload digest and executes
  atomically once; database triggers back up the
  two-person rule; final candidate lists are read-only
  (final_candidate_list for Workstream C)

Wiring (e.g. in the admin compartment's wsgi.py):

    sessions = StaffSessions(audit=record_event)
    authenticator = StaffAuthenticator(
        db_session=lambda: db.session,
        rate_limiter=LoginRateLimiter(),
        audit=record_event,
    )
    elevation = ElevationService(
        db_session=lambda: db.session,
        sessions=sessions,
        require_permission=require_permission,   # SR-04 (E)
        has_permission=has_permission,           # SR-04 (E)
        audit=record_event,
    )
    app.register_blueprint(create_staff_blueprint(
        authenticator=authenticator,
        sessions=sessions,
        elevation=elevation,
    ))
    app.register_blueprint(create_operations_blueprint(
        sessions=sessions,
        elevation=elevation,
        service=DualAuthorisationService(
            db_session=lambda: db.session,
            crypto=crypto,
            audit=record_event,
            clock=sessions.clock,
        ),
    ))

    # Any other privileged route:
    @bp.post("/admin/something")
    @elevation.require_elevated("config.read")
    def something(): ...

Local academic prototype.
"""

from . import triggers  # noqa: F401  (SR-06 trigger backstop)
from .accounts import (
    STAFF_ROLES,
    StaffAccountError,
    create_staff_account,
    find_staff_account,
)
from .candidates import CandidateListNotFinal, final_candidate_list
from .dual_authorisation import DualAuthorisationService
from .elevation import ELEVATION_SECONDS, ElevationService
from .login import StaffAuthenticator
from .models import Candidate, ElevationGrant, PendingOperation, StaffAccount
from .operation_routes import create_operations_blueprint
from .routes import create_staff_blueprint
from .sessions import INACTIVITY_LIMIT_SECONDS, StaffSessions
