# Workstream E — Secure Platform Infrastructure

## Overview

Workstream E implements the platform-wide security controls for the Electronic Voting Platform covering SR-04, SR-13, SR-19 and SR-20.

The implementation uses Python, Flask, Flask-SQLAlchemy, MySQL, Nginx, Docker Compose and GitHub Actions. It builds on Workstream A's gateway and voter records and Workstream B's crypto service, audit log and staff administration. A local Docker stack demonstrates the controls with synthetic data, locally generated keys and Workstream A's test certificates. Workstream E does not create or change TLS certificates or TLS settings.

## SR-04 — Role-Based Access Control

Implemented controls:
- Five roles (voter, officer, delegate, auditor, administrator) with explicit permission lists in `platform_security/rbac.py`; anything not listed is denied.
- An immutable role-to-permission matrix, mirrored in `docs/RBAC_MATRIX.md` and checked against the code on every build.
- A `require_permission` decorator: 401 without a login, 403 without the permission, with every denial recorded as an `AUTHZ_DENIED` audit event.
- The role is read only from the server-side session and must match the login type (voter or staff); a session that claims both is denied.
- A route inventory test that fails the build if any route is neither protected nor on a reviewed public list.
- A secure factory that gives each role only its own service methods.
- Least-privilege database accounts, one per service, with table- and column-level grants and no account allowed to create, alter or drop tables.

Key design decisions:
- The matrix was reviewed and approved by Workstream B (SR-06). Different-person approval for propose/approve pairs stays with SR-06; "own record" checks stay with SR-05.
- A failing audit hook still denies the request (fail closed).
- The staff admin account can change only `enrolment_status` on voter records and see only the id column of addresses. Its tables are created as root, so it never needs schema privileges.

## SR-13 — Encryption at Rest and Key Rotation

Implemented controls:
- An `EncryptedText` SQLAlchemy column type that encrypts on write and decrypts on read through Workstream B's `crypto_agility` service (AES-256-GCM), and stores a JSON envelope `{alg, kid, v, nonce, ct}`.
- `EnrolmentRecord.contact_email` and `AddressRecord.address_text` (Workstream A) use it, agreed with Workstream A. Ownership queries still filter on the plaintext `id` and `owner_voter_id`, so SR-05 is unchanged.
- Fail closed: with no provider, or no usable PII key, every read and write raises, and voter-access refuses to start.
- A tampered ciphertext fails to decrypt, and the record route returns only a generic error.
- Keys come from files in `deploy/secrets/keys/` (git-ignored), described by a manifest. Each compartment mounts only its own keys as Docker secrets.
- `deploy/scripts/rotate_pii_key.py` re-encrypts every row under a new key version in batches, checks every row with the new key before switching, and never removes the old key.

Key design decisions:
- No crypto library is used directly. Algorithms and key versions stay with SR-14 (Workstream B), and the key version travels in every envelope.
- The provider is registered at compartment start-up, never on import, so tests and CI need no keys.
- The envelope is bound to its key and purpose, not to its row. Moving a ciphertext between rows is a documented limitation.

## SR-19 — Availability, DoS Resilience, Backup and Recovery

Implemented controls:
- Nginx limits per client address: public 10 requests/s, login 5/min, ballot 1/s, plus connection limits, a 16 KB body limit, a 10 s body timeout and status 429.
- Registered polling terminals are listed by address in a geo block and use a separate, higher limit, so public traffic cannot use up their allowance.
- Ballot requests are logged without the client address (supports SR-08).
- Two voter-access replicas behind an upstream with passive failover (`max_fails=3`, `fail_timeout=10s`), `restart: unless-stopped`, and a `GET /healthz` health check.
- Backups every 15 minutes with `mysqldump --single-transaction`, into a separate volume, keeping 96 (24 hours).
- A timed restore drill that verifies the restored data: Workstream B's audit chain, and Workstream C's ballot store when merged.
- Load and flood test tooling, with a registered terminal simulator under the `drill` profile.

Key design decisions:
- `ip_hash` keeps each client on one replica, because Workstream A's sessions are held per process.
- `/healthz` is answered before Workstream A's SR-07 gateway check for exactly `GET`/`HEAD /healthz`, and is blocked at the gateway, so only the containers' own health checks reach it.
- A restore checks every file before stopping anything, and leaves the services stopped if it fails.

## SR-20 — Compartmentalisation and Third-Party Components

Implemented controls:
- Separate containers for voter access, admin and audit, ballot, tally and the results receiver. Each database has its own container, volume and internal network, and only the gateway is published, on this PC only.
- Hardened containers: pinned images, a non-root app image, read-only file systems, no Linux capabilities and no privilege escalation.
- The Flask apps trust X-EVP-* gateway headers only from the gateway's fixed address.
- Secrets are generated with a CSPRNG into git-ignored files (folder 700, files 600) and mounted as Docker secrets; none are inline in Compose or committed.
- A CI pipeline on pushes to `main` and `feature/**` branches and on every pull request: all tests, `pip-audit` and a CycloneDX SBOM artifact. Dependabot covers pip and Docker images.
- A vulnerability policy (`SECURITY.md`) with private reporting and 24-hour (election period) / 72-hour remediation targets for critical issues.

Key design decisions:
- One image for every Python compartment, with no default command, so each container runs only its own entrypoint.
- Workstream B's private keys are not given to voter-access: voter-access mounts only the PII key; admin-audit mounts the PII and audit keys.
- Static policy tests (Compose, Nginx, SQL, Dockerfile) are mutation-checked: each was shown to fail when its rule was deliberately broken in a scratch copy.

## Testing and Validation

A fresh run of `python -m pytest -q` completed with 1,937 passing tests and 1 skipped (in Workstream B's `test_admin_wsgi.py`). Workstream E contributes 1,206 of them; Workstream A's 139 and Workstream B's 592 also pass.

| Requirement | Test files | Tests |
|---|---|---|
| SR-04 | `test_rbac_skeleton.py` (30), `test_rbac_matrix.py` (455), `test_rbac_decorator.py` (37), `test_rbac_route_inventory.py` (19), `test_rbac_factory.py` (65) | 606 |
| SR-13 | `test_field_crypto_type.py` (31), `test_platform_pii_encryption.py` (20), `test_field_encryption.py` (14), `test_key_rotation.py` (23), `test_demo_encryption_at_rest.py` (9) | 97 |
| SR-19 | `test_platform_nginx_config.py` (24), `test_platform_health.py` (19), `test_platform_backup.py` (44), `test_load_test_script.py` (49) | 136 |
| SR-20 | `test_platform_compose.py` (117), `test_platform_db_roles.py` (34), `test_platform_db_apply.py` (56), `test_platform_dockerfile.py` (34), `test_platform_gateway_trust.py` (45), `test_platform_scripts.py` (38), `test_platform_ci_config.py` (14), `test_platform_binds.py` (8), `test_platform_layout.py` (11), `test_platform_security_policy.py` (10) | 367 |
| **Total** | | **1,206** |

The database account tests (`test_platform_db_roles.py`, `test_platform_db_apply.py`) also cover SR-04's least-privilege accounts; each file is counted once.

### Drill results (21 October 2026, local Docker stack)

| Drill | Result |
|---|---|
| Flood | One address sent 6,734 requests in 3 s; 99.3% got 429 and only 50 reached the app (burst 20 plus 10 per second, as configured). The registered terminal (172.30.0.20) sent 118 requests in 60 s with no 429. |
| Failover | `voter-access-1` was stopped during a 60 s run of 10 clients (585,098 requests); there were no 502, 503 or 504 responses, and `voter-access-2` stayed healthy. |
| Backups | 13 scheduled backups 15 minutes apart (11:54 to 14:54 UTC), plus one on demand. |
| Restore | Backup `20261021T150628Z` restored all three databases in 9 s (target 2 h); the marker row came back; the audit chain check passed (0 entries in the demo); Workstream C's ballot store check was skipped because it is not merged. |
| Load | 50 clients for 30 s from one address: 342,146 requests, 11,394 requests/s, p95 9.6 ms; 49.9% got 429 and 50.0% got 404 (the gateway does not expose `/healthz`); only 318 reached the app, which answered 403 (no registered mission certificate, SR-07). |

These figures show the gateway shedding traffic from a single source on one laptop: almost every request was answered by Nginx's limits or its `/healthz` block, and very few reached the application. They do not measure capacity for 40,000 legitimate terminals, each with its own address and allowance, nor the 99.95% availability target. That would need a multi-host deployment, real terminal traffic patterns and a load test from many sources.

## Limitations

- Single Docker host: the replicas, databases and backups volume share one machine and disk. Production would use several hosts or zones, off-site backups, a CDN and traffic scrubbing.
- No hardware security module: keys are files protected by file permissions and container isolation.
- The load test is scaled down and runs from one address on one laptop; the 40,000-terminal and 99.95% targets are not demonstrated.
- Workstream A's login rate limiter, TOTP replay guard and sessions keep their state per process, so the two voter-access replicas do not share it; `ip_hash` and the gateway's login limit reduce, but do not close, this gap.
- The audit chain was empty in the restore drill, so the check passed trivially; it still needs a drill with real audit entries.
- Voter-access still stores its records in in-memory SQLite (`app.py`), so in Docker the encrypted columns protect demo records only until Workstream A moves to MySQL.
- `rotate_pii_key.py` cannot yet reach the Docker databases: they are on internal networks and no app account may change the encrypted columns.
- The backup service holds all three database root passwords; a dedicated backup account would be tighter.
- Waiting on other workstreams:
  - Workstream B: narrow `db.create_all()` in `admin/wsgi.py` to B's own tables, so the admin account no longer needs id-only access to address records.
  - Workstream C: the ballot service, its tables and grants, `verify_ballot_store` (interface still to confirm) and routing `/ballot/` to the ballot compartment.
  - Workstream D: the tally and results-consumer services.
  - Workstreams A and B: no client IP for ballot requests in Nginx's error log or the `X-EVP-Source-IP` header (SR-08).
  - A repository admin: turn on private vulnerability reporting and branch protection for `main`.

## Key Files

- `platform_security/rbac.py` — Role-permission matrix and `require_permission` decorator.
- `platform_security/route_inventory.py` — Unprotected-route detection.
- `platform_security/factory.py` — Per-role secure service factory.
- `platform_security/field_crypto.py` — `EncryptedText` column type and provider interface.
- `platform_security/crypto_setup.py` — Fail-closed start-up registration of the PII key.
- `platform_security/health.py` — `GET /healthz` health check.
- `docs/RBAC_MATRIX.md` — Role-permission matrix.
- `deploy/docker-compose.yml` — Compartments, networks, secrets, replicas, backups and drill service.
- `deploy/Dockerfile.app` — Non-root image for every Python compartment.
- `deploy/ENTRYPOINTS.md` — Compartment entrypoints.
- `deploy/db/roles.sql` — Least-privilege database accounts.
- `deploy/scripts/make_secrets.sh` and `deploy/scripts/make_keys.py` — Secret and key generation.
- `deploy/scripts/apply_db_security.sh`, `deploy/scripts/roles_plan.py`, `deploy/scripts/schema_sql.py` — Tables, accounts and triggers.
- `deploy/scripts/backup.sh` and `deploy/scripts/restore.sh` — Scheduled backups and restore drill.
- `deploy/scripts/rotate_pii_key.py` — PII key rotation.
- `deploy/README.md` — Deployment, drill and key rotation commands.
- `nginx/conf.d/evp.conf` — Rate limits, upstream failover and ballot logging (Workstream A's file, changed by agreement).
- `scripts/load_test.py` — Load and flood test.
- `scripts/demo_encryption_at_rest.py` — Encryption-at-rest demonstration.
- `.github/workflows/ci.yml` and `.github/dependabot.yml` — CI, dependency scanning and SBOM.
- `SECURITY.md` — Vulnerability reporting and remediation policy.

## GitHub

Implementation branch: `feature/workstream-e`

Draft pull request: #19

Issues: #15 (SR-04), #16 (SR-13), #17 (SR-19), #18 (SR-20)

Latest commit: `53c742b`
