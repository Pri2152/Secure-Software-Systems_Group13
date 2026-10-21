# SR-08: Ballot-voter unlinkability

## Status and requirement

Prototype-complete with the physical-store/service-credential limitation below.
SR-08 requires anonymous one-time authorisation after eligibility confirmation,
identity/ballot compartmentalisation, and retained records/logs without an
individual voter-to-ballot identifier or correlatable ballot metadata.

The selected solution is a random bearer credential, a hashed verifier held
only in the identity domain, a narrow ballot writer and metadata minimisation.
This is application-data unlinkability within the prototype's retained schema,
not mathematical anonymity or protection against a live compromised server.

## Architecture and interfaces

```text
Authenticated caller (trusted voter ID)
  -> issue_ballot_credential(voter_id, election_id)
  -> raw random credential returned once

Anonymous service caller (no voter ID)
  -> accept_ballot_with_credential(credential, candidate_id, opaque_payload)
  -> identity authorisation resolves verifier and rechecks eligibility
  -> conditional eligibility claim + credential DELETE
  -> store_anonymous_ballot(election_id, division, opaque_payload)
  -> one commit
```

`ballot_credentials.py` owns identity-side credential issuance and consumption.
`ballot_service.py` supplies shared SR-03 validation and conditional claiming.
`ballot_storage.py` receives only election, stored division and opaque payload;
it stages an independently random ballot ID without receiving identity,
credential/verifier, source IP, session ID or timestamp. It does not commit.
These are logical interfaces, not independently authenticated security processes.

No HTTP route, GUI or client transport is added. Future integration must obtain
issuance identity from a verified server-side session, keep bearer credentials
out of URLs/logs, and use the credential-facing operation for anonymous voting.
The old trusted-identity `accept_ballot` entrypoint remains for SR-03 compatibility;
it is not the anonymous public interface. Both reuse the same SQL claim and
candidate validation. Both own their current session transaction: callers must
not include unrelated pending writes or wrap them in a second commit boundary.

## Credential lifecycle and database controls

1. Issuance checks active enrolment, eligibility, election, stored electoral
   assignment and `has_voted=False` through the existing SR-03 service.
2. `secrets.token_urlsafe(32)` creates a 256-bit bearer credential (43 URL-safe
   characters). It is independent of identity, session, preferences and time.
3. The central SR-14 `crypto.hash` hashes a domain-separated byte string:
   `evp.ballot-credential.v1\0 || credential`. The high-entropy input makes a
   fast one-way digest appropriate; this is not password hashing. No new crypto
   implementation/package is introduced and no ballot encryption is performed.
4. `BallotCredential` persists only the verifier (primary key), voter ID,
   election ID and expiry. UNIQUE `(voter_id, election_id)` permits at most one
   row. Issuance atomically replaces any previous credential. A failed
   replacement rolls back and preserves the old credential; concurrent issuance
   may safely reject a contender or invalidate an earlier issued token.
5. Expiry is ten minutes from an aware UTC clock, stored as epoch seconds only
   in the identity domain. Acceptance rejects at `now >= expires_at`. The clock
   is injectable for deterministic tests; a naive datetime fails closed.
6. Consumption validates format, hashes the supplied credential, resolves the
   verifier and checks expiry. It revalidates current enrolment, eligibility,
   assignment, previous-vote status and the selected candidate against the
   stored division's immutable final list (draft/excluded/other-division choices
   fail). Client-supplied identity or division is never needed.
7. The SR-03 conditional SQL UPDATE requires the existing identity/election,
   unchanged assignment, active enrolment, eligible=True and has_voted=False.
   Exactly one affected row is required; Python pre-checks are not the final
   concurrency guard.
8. A conditional DELETE requires the same verifier and unexpired state, with
   exactly one affected row. Expiry is checked again after the status claim.
9. The ballot writer generates separate `secrets.token_hex(32)` randomness and
   stages the opaque payload. Status update, verifier deletion and ballot
   insertion share one SQLAlchemy session/transaction and one final commit.
10. Rejection or database/crypto failure rolls back; anonymous callers receive
    only `CredentialError("Credential authorisation failed")`. Unexpected
    programming errors roll back and propagate for diagnosis; caller integration
    must not serialize tracebacks. Nothing returns a ballot ID or receipt.

Crypto must be configured through the existing SR-14 environment/service. Tests
inject its real ephemeral-key service without changing global configuration.
Verifier lookup uses the configured default hash algorithm. Changing that
default invalidates outstanding credentials; reissue them (at most ten-minute
lifetime). Retirement/configuration failures fail closed. This prototype does
not implement multi-algorithm credential migration.

## Retained state and privacy boundary

| Domain | Retained after successful credential voting |
|---|---|
| Identity | Existing enrolment and eligibility including `has_voted=True`; no ballot ID, candidate choice, verifier or raw credential |
| Credential | Consumed row deleted; unused/expired rows can remain until replacement, without ballot metadata |
| Ballot | Random ballot ID, election, division, opaque payload; no identity, identity foreign key, credential/verifier, IP, session or timestamp |

There is no permanent shared **individual** identifier or voter-to-ballot join
table. Election and division remain common cohort context. Small cohorts,
single-voter divisions, population knowledge or observing insertion order may
permit inference; this prototype provides no batching, mixing or formal
anonymity guarantee. In-flight process memory necessarily resolves identity to
authorise the vote. Database journals/WAL, backups, forensic traces and a live
database administrator are outside the retained application-row guarantee;
credential deletion is not secure media erasure.

The payload remains caller-supplied opaque synthetic data. Trusted callers must
not embed identity or plaintext preferences in it. This ticket does not inspect
or cryptographically bind it to the separately validated selection. SR-10 must
provide authenticated encryption and its payload contract later.

## Tests and traceability

| Control | Automated evidence |
|---|---|
| Random issuance; verifier-only persistence | `test_ballot_credentials.py`: distinct credentials, expiry, no raw persistence, real crypto/configuration failures |
| Eligibility and one active credential | Issuance rejection matrix, replacement invalidation, database UNIQUE constraint; concurrent issuance test |
| Anonymous interface and current authorisation | `test_credential_acceptance.py`: no identity argument, replay rejection, malformed/unknown tokens, expiry boundary, changed identity state, candidate restrictions |
| No persistent individual join | `test_credential_privacy.py`: actual database schema inspection, two-voter end-to-end retained-table scan, deleted verifiers, no ballot ID outside ballot table, narrow writer call inspection |
| Metadata/log minimisation | No new logging/audit calls; privacy test captures logs across both successful votes and forbids audit emission |
| Atomic rollback | Injected insert failure observes `(has_voted=True, credential absent)`; commit failure flushes and observes `(True, 0 credentials, 1 ballot)`; fresh sessions must show `(False, 1 credential, 0 ballots)` and retry succeeds |
| Credential action failure | DELETE failure after status claim, expiry between pre-check and DELETE, and failed replacement all restore safe state |
| Genuine one-time contention | `test_credential_concurrency.py`: three file-backed SQLite races, two threads/app contexts/connections, barrier after candidate validation, real SQL UPDATE rowcounts `[0, 1]`, one DELETE and one ballot, replay rejected |
| SR-03 compatibility | All existing eligibility, acceptance, rollback and two-connection contention tests retained |

Tests never fake the winning UPDATE or replace database operations to assert
concurrency. SQL event listeners observe actual rowcounts; failure listeners
are used only for explicit rollback tests. Tests use synthetic opaque payloads,
not real encrypted ballots. Contention evidence covers local SQLite; other
database engines/isolation modes require separate deployment validation.

## Storage, logging and deployment limitations

Physical independent stores and independently authenticated database service
credentials remain a production architecture requirement. The local SQLite
prototype preserves SR-03 atomicity within one database transaction. Splitting
identity and ballots into unrelated SQLite commits would break that guarantee;
no distributed transaction or separate DB authentication is claimed here.

SR-08 emits no issuance/acceptance security log or audit event, intentionally
avoiding credential, verifier, voter, choice, ballot ID, ciphertext, IP and
precise acceptance timestamps. Existing Workstream B audit records use precise
server UTC timestamps, even on the ballot stream (which rejects actor IDs/IPs).
That subsystem is unchanged. Future ballot auditing requires a reviewed timing
policy before integration; this ticket does not guarantee anonymisation of
arbitrary shared audit events. SQL echo, debug tracebacks, proxy/access logs and
transport/session metadata must likewise be excluded or minimised in a future
anonymous HTTP deployment. They are not solved by this service-only change.

## Deferred work and review

SR-09 receipts/confirmations and SR-10 encryption, ballot hash chains, tamper
verification and tally integrity are deliberately absent. No new package,
teammate implementation changes, transport endpoint, migration system, push or
PR is required. Existing local data needs the new credential table created;
tests use fresh schemas, as does the demonstration runtime's `db.create_all`.

Review the credential-facing interface, SQL predicates/rowcounts, no-commit
writer, generic failures, caller identity/payload contract and limitations above
before publishing. Run using the project virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_ballot_credentials.py tests/test_credential_acceptance.py tests/test_credential_privacy.py tests/test_credential_concurrency.py tests/test_ballot_models.py tests/test_ballot_service.py tests/test_ballot_concurrency.py -q
.\.venv\Scripts\python.exe -m pytest -q
git --no-pager diff --check
```

Validated on this branch: 105 focused tests passed; full suite 834 passed,
3 skipped, with the existing Flask `test_app` collection warning only.
The focused total includes the unchanged SR-03 regression tests.
