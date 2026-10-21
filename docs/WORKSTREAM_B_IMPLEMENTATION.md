# Workstream B — Privileged Operations and Audit

## Overview

Workstream B implements security controls for the Electronic Voting Platform covering SR-02, SR-06, SR-14 and SR-17.

The implementation uses Python, Flask, Flask-SQLAlchemy, SQLAlchemy, the `cryptography` library and argon2-cffi. It is split into three packages:

- `crypto_agility/`: the central cryptographic service (SR-14), used by every workstream.
- `audit/`: the central tamper-evident audit log (SR-17).
- `admin/`: staff authentication and just-in-time elevation (SR-02), and dual authorisation (SR-06).

The `admin/wsgi.py` entrypoint runs them together as the admin-audit compartment (SR-20 layout). All data is synthetic, and all keys and certificates used in tests are generated during the test run.

## SR-02 — Phishing-Resistant Staff MFA and Just-in-Time Access

Implemented controls:
- Person-linked staff accounts. Generic or shared names (`admin`, `officer-01`, `test-user`, `root`, `staff99`, ...) are rejected.
- One client certificate per person. The certificate's SHA-256 fingerprint is unique per account, enforced in code and by a UNIQUE constraint.
- Two factors at login: a client certificate verified by the Nginx mTLS gateway, plus an Argon2id password.
- The certificate factor reuses Workstream A's SR-07 gateway adapter (`gateway_security.evaluate_gateway_request`) unchanged. Headers sent directly to the backend are not trusted.
- The same generic 401 for every failure. The specific reason is recorded only in the audit log.
- Workstream A's rate limiter is reused: 5 failures in 15 minutes per account and per source, then 429.
- A dummy Argon2id check for unknown accounts, so response time does not reveal which IDs exist.
- Staff sessions hold exactly the keys used by Workstream E's RBAC (`staff_authenticated`, `staff_id`, `role`) plus `last_activity`.
- Session hardening: session ID regenerated at login, 10-minute inactivity timeout, voter and mixed sessions refused.
- Sessions of deactivated or deleted accounts are ended on their next request (`STAFF_SESSION_REVOKED`).
- No standing privileges. A privileged permission needs an elevation grant:
  - requested per permission, and only for a permission the role holds under SR-04;
  - granted after step-up re-authentication with both the certificate and the password;
  - valid for at most 15 minutes and stored server-side;
  - revoked on request, at login, at logout, at idle expiry and on deactivation.
- `require_elevated(permission)` protects privileged routes. It combines the staff session check, SR-04 `require_permission` and an active grant.
- Staff account management (`staff.manage`) is itself an elevation-protected operation.
- Every login, step-up, elevation, expiry, revocation and refusal is recorded on the admin audit stream, without passwords.

## SR-06 — Dual Authorisation for Critical Electoral Operations

Implemented controls:
- A maker-checker workflow: PROPOSE, then APPROVE by a different named officer, then EXECUTE. It covers:
  - candidate-list finalisation (`FINALISE_CANDIDATE_LIST`);
  - court-ordered candidate exclusion (`EXCLUDE_CANDIDATE`, which needs a court order reference);
  - bulk roll updates (`BULK_ROLL_UPDATE`).
- Separate propose and approve permissions per operation type (Workstream E's SR-04 matrix). Each needs an active SR-02 elevation.
- The proposer can never approve their own operation.
- Strict payload validation. Proposals are completed with a server-side snapshot: for finalisation, the exact DRAFT candidate IDs.
- The payload is stored as canonical JSON with a self-describing digest made by `crypto_agility` (`sha256:<hex>`). The approver must submit the digest they reviewed, and the stored payload must still match it.
- Proposals expire after 24 hours. Rejected, expired and executed operations cannot be approved.
- Approval executes atomically in one transaction:
  - the operation is claimed with a conditional update;
  - the change is applied through the ORM;
  - the operation is marked EXECUTED.
  Any failure rolls everything back, so an operation runs at most once.
- Execution re-validates the payload against the current data. A candidate list that changed after the proposal is not finalised, and a bulk update with a missing record changes nothing.
- Database trigger backstop (SQLite in `admin/triggers.py`, MySQL in `deploy/db/dual_authorisation_triggers.sql`):
  - EXECUTED is refused unless two distinct officers are recorded;
  - executed operations cannot be changed or deleted.
- Final candidate lists are read-only at the ORM level: no new candidates, edits or deletions. The only change allowed is a dual-authorised FINAL to EXCLUDED.
- Workstream C reads a list through `final_candidate_list(division)`, which returns immutable values and refuses lists that are not final.
- Bulk roll updates change Workstream A's `EnrolmentRecord` through the ORM only.
- Every step is recorded on the admin audit stream with both officers' IDs and the payload digest.

## SR-14 — Crypto-Agility

Implemented controls:
- One central service (`from crypto_agility import crypto`) for hashing, HMAC, signatures, authenticated encryption, public-key sealing and password hashing.
- An algorithm registry with a secure factory. The crypto policy (configuration), not the calling code, picks the algorithm:
  - hash: SHA-256, SHA3-256
  - MAC: HMAC-SHA256, HMAC-SHA3-256
  - signature: Ed25519, ECDSA P-256
  - encryption: AES-256-GCM, ChaCha20-Poly1305
  - sealing: RSA-OAEP-3072 with AES-256-GCM
  - password: Argon2id parameter sets
- Self-describing outputs: `{"alg", "kid", "v", ...}` envelopes and `sha256:<hex>` hashes.
- Verification uses the algorithm named in the output, but only while the policy still allows it. Old outputs keep verifying after the default changes; removing an algorithm from the allow-list retires its outputs.
- Versioned key IDs (`<purpose>.<alg>.v<n>`) bound to their purpose and algorithm, which prevents key confusion. Key rotation keeps old versions available for verification.
- Keys are loaded from a secrets directory with a strictly validated manifest, or generated in memory for development only. With neither configured, crypto refuses to run.
- Strict envelope validation (exact fields, base64, size caps). `verify` never raises; `decrypt` and `open` raise on any tampering.
- An Argon2id rehash-on-login helper (`verify_and_upgrade`) for migrating outdated parameters.
- A reserved post-quantum signature slot (`ml-dsa-65`). It is registered but disabled, and the policy refuses to enable it.
- Compatible with Workstream E's field-encryption provider interface (SR-13) and with Workstream D's client-side seal format.

## SR-17 — Centralised, Tamper-Evident Audit Logging

Implemented controls:
- One master logging routine, `record_event(...)`, for every workstream.
- A secure-logger filter that removes passwords, TOTP codes, tokens, CSRF and session values, cookies, keys, ballot preferences and ciphertext before storage. Details are size-capped.
- Three separate streams: identity, ballot and admin. The ballot stream refuses an actor ID or source IP (protects SR-08).
- Server-side UTC timestamps from an injectable clock.
- Per-stream HMAC hash chains computed through SR-14. Each entry stores its MAC envelope, so entries made before an algorithm change still verify.
- A chain verifier that reports the exact sequence number of an edit, deletion, reordering, forged entry or duplicate.
- Database triggers block UPDATE and DELETE on the audit table (SQLite created with the table; MySQL in `deploy/db/audit_triggers.sql`).
- Signed checkpoints every 50 entries per stream, and on demand. They are appended to a separate archive file and catch truncation that the hash chain alone cannot.
- A logging handler that turns Workstream A's existing `evp.*` security log lines into identity audit events, without changing Workstream A's code.
- Auditor-only read and verify endpoints. They require `audit.read` / `audit.verify` and, in the compartment, an SR-02 elevation. Every access to the log is itself audited, and access is refused if that record cannot be written.

## Testing and Validation

The full automated test suite has 732 tests: 729 pass and 3 are skipped. The 3 skipped tests need Workstream E's `platform_security` package (PR #19); they pass when it is installed.

Workstream B tests:

| Requirement | Test files | Tests |
|---|---|---|
| SR-02 | `test_admin_accounts.py`, `test_admin_login.py`, `test_admin_sessions.py`, `test_admin_elevation.py`, `test_admin_attacks.py` | 154 |
| SR-06 | `test_admin_dual_models.py`, `test_admin_dual_routes.py`, `test_admin_dual_execution.py` | 94 |
| SR-14 | `test_crypto_registry.py`, `test_crypto_hash_mac.py`, `test_crypto_signing.py`, `test_crypto_encryption.py`, `test_crypto_key_loading.py`, `test_crypto_passwords_pqc.py` | 200 |
| SR-17 | `test_audit_logging.py`, `test_audit_chain.py`, `test_audit_triggers.py`, `test_audit_log_handler.py`, `test_audit_checkpoints.py`, `test_audit_routes.py` | 131 |
| SR-20 compartment | `test_admin_wsgi.py` | 14 |
| **Total** | | **593** |

Every control has positive and attack tests. Time windows (15-minute elevation, 10-minute idle timeout, 24-hour proposal expiry, 15-minute rate-limit window) are tested with injected clocks, without sleeping. Test databases are isolated in-memory or temporary SQLite databases.

## Live Demonstration Steps

The demonstration uses the test suite against the real HTTP endpoints. A Docker run of the admin-audit container depends on Workstream E's Compose file (PR #19).

1. Staff login with a password but no certificate, then with another officer's certificate, is rejected with 401. With the person's own certificate and password it succeeds. Creating an account named `admin` is rejected (`tests/test_admin_login.py`, `tests/test_admin_attacks.py`).
2. A privileged route without elevation returns 403. After step-up elevation it returns 200, and 15 minutes later (fake clock) it returns 403 again (`tests/test_admin_elevation.py`).
3. Delegate 1 proposes finalising a candidate list. Delegate 1's own approval is refused. Delegate 2, elevated, approves; the list becomes FINAL exactly once and is then read-only (`tests/test_admin_dual_routes.py`, `tests/test_admin_dual_execution.py`).
4. A direct SQL update setting the operation to EXECUTED with one officer is aborted by the trigger (`tests/test_admin_dual_execution.py`).
5. The audit log shows every step with actor and UTC time and no passwords. Editing one row makes the verifier report the exact broken sequence number. `DELETE FROM audit_log` is blocked by a trigger (`tests/test_audit_chain.py`, `tests/test_audit_triggers.py`).
6. Changing the signing algorithm from Ed25519 to ECDSA P-256 in the policy makes new signatures use ECDSA while old Ed25519 signatures still verify. Removing Ed25519 from the allow-list makes them fail (`tests/test_crypto_signing.py`).

Example:

```bash
python -m pytest tests/test_admin_attacks.py tests/test_admin_dual_execution.py -v
```

## Assumptions and Limitations

- Client certificates come from a local test CA generated for the demonstration. A production deployment would use a managed PKI, keep staff keys on smartcards and publish certificate revocation lists. Revocation checking is not implemented.
- No hardware security module is used. Keys are files in a secrets directory (Docker secrets) and are protected only by file permissions and container isolation.
- The post-quantum slot (`ml-dsa-65`) is reserved but disabled. Crypto-agility is demonstrated by switching between classical algorithms.
- The time source is the host clock, assumed to be NTP-synchronised. There is no external trusted timestamping service.
- The audit checkpoint archive is a file on a volume intended for a separate container. It stands in for write-once storage under separate administrative control and is not a real WORM device.
- An attacker who holds the audit HMAC key and full database access could rebuild the hash chain. The signed checkpoints in the separate archive limit this to entries after the last checkpoint.
- Two colluding officers can still approve an operation together. The audit trail and the Auditor role make this detectable, not impossible.
- Rate-limiting state and staff server-side sessions are held in process memory, as in Workstream A. A multi-process deployment needs a shared store.
- The MySQL trigger scripts are provided but are run by an administrator. Least-privilege database accounts depend on Workstream E's `deploy/db/roles.sql`.
- The admin-audit compartment requires Workstream E's SR-04 module and refuses to start without it.
- The prototype is not an operational election system. All voters, staff, candidates and certificates are synthetic.

## Key Files

- `crypto_agility/service.py` — Central crypto service and envelope validation.
- `crypto_agility/registry.py`, `crypto_agility/algorithms.py`, `crypto_agility/policy.py` — Registry, secure factory and configurable policy.
- `crypto_agility/keys.py` — Versioned key store and secrets-directory loading.
- `crypto_agility/passwords.py` — Argon2id parameter sets and rehash helper.
- `audit/log.py` — Master logging routine, reader and chain verification.
- `audit/chain.py` — Per-stream HMAC hash chains.
- `audit/filters.py` — Sensitive-data filter.
- `audit/checkpoints.py` — Signed checkpoint archive.
- `audit/handler.py` — Capture of Workstream A's security logs.
- `audit/routes.py` — Auditor endpoints.
- `admin/accounts.py`, `admin/models.py` — Staff accounts, candidates and pending operations.
- `admin/login.py`, `admin/gateway.py` — Certificate and password staff login.
- `admin/sessions.py`, `admin/elevation.py` — Staff sessions and just-in-time elevation.
- `admin/dual_authorisation.py`, `admin/operations.py`, `admin/execution.py` — Maker-checker workflow.
- `admin/candidates.py` — Read-only final candidate lists for Workstream C.
- `admin/triggers.py` — Two-person rule trigger backstop.
- `admin/wsgi.py` — Admin-audit compartment entrypoint.
- `deploy/db/audit_triggers.sql`, `deploy/db/dual_authorisation_triggers.sql` — MySQL triggers.

## GitHub

Implementation branch: `feature/workstream-b`

Pull requests: #20 (SR-14 and SR-17, merged); SR-02 and SR-06 follow on the same branch.
