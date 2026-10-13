
# Workstream A — Secure Voter Access

## Overview

Workstream A implements security controls for the Electronic Voting Platform covering SR-01, SR-05, SR-07 and SR-16.

The implementation uses Python, Flask, Flask-SQLAlchemy, Nginx and Docker. A local integration environment demonstrates the security controls using synthetic voter credentials and test certificates.

## SR-01 — Secure Authentication

Implemented controls:
- Argon2id password hashing and verification.
- Time-based one-time password (TOTP) MFA.
- Account-based and source-based login rate limiting.
- Five failed attempts within a rolling 15-minute window.
- TOTP replay prevention.
- Authentication input validation.
- Security event logging.

## SR-05 — Object-Level Authorisation

Implemented controls:
- Authenticated access to voter records.
- Ownership checks for enrolment and address records.
- Prevention of access to other voters' records.
- Restricted modification of permitted address fields.
- CSRF protection for state-changing requests.

## SR-07 — Diplomatic-Mission Access

Implemented controls:
- HTTPS gateway using Nginx.
- Client certificate verification using mutual TLS.
- SHA-256 certificate fingerprint registration checks.
- Network allowlist policy for simulated overseas connections.
- Denial of unregistered and untrusted client certificates.
- Gateway-to-Flask access-policy integration.
- Audit logging of rejected requests.

The current deployment uses simulated country classification and example network addresses. Real diplomatic-mission deployment would require trusted geolocation, verified network ownership and stronger gateway-to-backend isolation.

## SR-16 — Secure Session Management

Implemented controls:
- Server-side sessions.
- Session identifier regeneration after authentication.
- Secure, HttpOnly and SameSite cookie settings.
- Ten-minute inactivity timeout.
- CSRF protection.
- Logout and session invalidation.

Session invalidation after casting a ballot requires integration with the group's voting workflow.

## Testing and Validation

The automated test suite completed with 139 passing tests.

Live Docker integration testing demonstrated:
1. Successful HTTPS access using a registered client certificate.
2. Rejection of missing and unregistered client certificates.
3. Successful password and TOTP authentication.
4. Access to the authenticated voter's own enrolment record.
5. Successful authenticated-session verification.
6. Successful logout.
7. Rejection of protected record access after logout.

The local live demonstration completed successfully.

## Limitations

- The country lookup and diplomatic-mission network are simulated.
- The local gateway trust boundary is not suitable for production deployment.
- Login rate limiting and MFA replay state are held in process-local memory.
- The prototype uses non-persistent, in-memory database storage.
- Test certificates and synthetic credentials are excluded from Git.
- The test deployment is not an operational election system.
- Integration with ballot casting and post-vote session invalidation remains dependent on the group's voting component.

## Key Files

- `app.py` — Main Flask application and security middleware.
- `auth.py` — Password and TOTP functionality.
- `login_flow.py` — Authentication coordination.
- `rate_limit.py` — Failed-login rate limiting.
- `records.py` — Voter data models.
- `record_routes.py` — Protected record endpoints.
- `mission_access.py` — Mission access policy.
- `gateway_security.py` — Trusted gateway metadata processing.
- `gateway_runtime.py` — Local demonstration configuration.
- `nginx/conf.d/evp.conf` — HTTPS and mTLS gateway.
- `Dockerfile.gateway` — Flask Docker image.
- `scripts/live_mfa_demo.py` — End-to-end security demonstration.

## GitHub

Implementation branch: `feature/workstream-a`

Pull request: #14

Latest integration commit: `26efca7`
