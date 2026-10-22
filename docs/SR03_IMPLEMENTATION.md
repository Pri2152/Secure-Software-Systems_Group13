# SR-03: Eligibility and single-vote enforcement

## Requirement and scope

Before accepting a digital ballot, verify enrolment, election eligibility,
electoral assignment and absence of an accepted vote. Ballot insertion and
voting-status transition must commit atomically. Concurrent submissions must
leave exactly one accepted ballot; rollback must leave neither change.

This ticket adds a service boundary, not an HTTP voting endpoint. It reuses
Workstream A's enrolment data and Workstream B's final candidate API without
changing either implementation. SR-08, SR-09 and SR-10 remain separate work.

## Service contract

`ballot_service.accept_ballot(voter_id, election_id, candidate_id,
encrypted_ballot_json)` accepts a single candidate selection. The caller must
obtain voter identity from authenticated server-side state, never request JSON.
Use a session without unrelated pending writes: this function owns its commit
and rollback. Successful return means commit completed; rejection raises
`BallotAcceptanceError`, a subclass of the existing `EligibilityError`.

The payload must be a nonblank string of at most 65,536 characters. It is an
opaque storage argument supplied by the caller, not encryption implemented by
this ticket. Tests use `{"alg":"test","ct":"opaque"}`. The service neither
stores the candidate ID as plaintext nor proves that the opaque payload encodes
the selected candidate. Binding and authenticated encryption await SR-10.

## Requirement-to-control traceability

| Rule | Implementation and database control | Test evidence |
|---|---|---|
| Enrolled and eligible | Existing `get_voting_eligibility`; claim also requires active enrolment and `eligible=True` | Existing eligibility tests; acceptance rejection tests for removed/suspended/ineligible voters |
| Correct assignment | Existing stored division/state validation; claim requires unchanged assignment | Assignment tests and acceptance rejection test; prototype supports Melbourne/VIC only |
| Trusted candidate | `get_ballot_candidates` calls `final_candidate_list` for stored division; positive integer selection must belong to returned list | Valid, malformed, unknown, other-division, excluded and draft-list tests |
| One identity status per election | Existing UNIQUE `(voter_id, election_id)` | Existing model duplicate tests |
| Single acceptance | Conditional SQL UPDATE from `has_voted=False` to True; exactly one affected row required | Stale-precheck test and synchronized two-connection contention test |
| Atomic acceptance | Same `db.session` and transaction for UPDATE and ballot INSERT; one final commit | Successful persistence and forced insertion/commit failure tests |
| Failure handling | Rollback on rejection or exception; SQLAlchemy failures become a safe domain error | Failure tests inspect fresh sessions and demonstrate a retry after insertion failure |

No nested transaction is opened: SQLAlchemy queries may already have begun an
implicit transaction. The existing maker-checker service uses the same
conditional-update/commit/rollback pattern. SQLAlchemy session synchronization
is disabled for the claim; successful commit expires ORM state normally.

## Concurrency evidence

`tests/test_ballot_concurrency.py` runs three independent races. Each uses a
temporary file-backed SQLite database, two worker threads, separate Flask app
contexts and separate SQL connections. A barrier after final candidate lookup
ensures both workers passed the eligibility pre-check before either claims.
The database executes both conditional updates; tests require row counts
`[0, 1]`, one successful return, one domain rejection, one stored ballot and
`has_voted=True`. An SQLAlchemy execution listener observes actual row counts
and distinct connections; it does not replace database operations.

This validates the local SQLite prototype, not every production database or
isolation configuration. Lock/transaction failures reject safely through the
same rollback path; the service does not automatically retry them.

## Rollback evidence

The insertion-failure test installs a temporary ORM `before_insert` listener.
It reads `has_voted=True` through the transaction's connection and then raises
`IntegrityError`. A fresh session subsequently sees False and zero ballots.
Removing the listener allows the voter to retry successfully.

The commit-failure test flushes the pending ballot and observes `(True, 1)`
inside the transaction before raising `OperationalError`. Fresh-session reads
must again show False and zero ballots. These are failures after the claim,
not validation failures presented as rollback evidence.

## Privacy and integration boundaries

Ballot IDs use `secrets.token_hex(32)` (256 random bits). No ID is returned or
copied into eligibility state, and no voter-to-ballot mapping is added.
`AnonymousBallot` is unchanged and contains no voter identity fields. This
preserves the existing schema's privacy direction without claiming complete
unlinkability. Anonymous credentials, receipts, encryption, tamper detection,
ballot audit events and tallying are outside this ticket.

Direct SQL or other code bypassing this service is outside its acceptance
boundary. Future HTTP integration must preserve authenticated identity and
route all ballot acceptance through the service. Reviewers should inspect the
conditional predicate, transaction ownership and opaque-payload contract.

## Reproducing validation

Use the repository virtual environment and module invocation:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_ballot_models.py tests/test_ballot_service.py tests/test_ballot_concurrency.py -q
.\.venv\Scripts\python.exe -m pytest -q
git --no-pager diff --check
```

The pre-existing Flask `test_app` collection warning and optional SR-04
integration skips are unrelated to this change. In a restricted execution
environment, pytest needs permission to access its temporary directories.
