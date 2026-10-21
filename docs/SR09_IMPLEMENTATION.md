# SR-09: Receipt-free confirmation

## Requirement and status

SR-09 service-level prototype complete; GUI/REST presentation enforcement
remains for final integration.

The platform shall not display, email, export or log a receipt that reveals
preferences or provides reusable proof of how a voter voted. Successful voting
shall return only a random non-preference confirmation reference that cannot
reconstruct the ballot. There is no revoting or ballot supersession requirement.

Selected solution: independent, opaque, non-persistent confirmation output.
SR-09 prevents the prototype from issuing an application-level preference-bearing
receipt or reusable reference-to-choice proof. This is not a formal proof of
receipt-freeness or coercion resistance.

## Generation and return contract

`ballot_confirmation.generate_confirmation_reference()` takes no voting inputs.
It calls `secrets.token_urlsafe(24)` and prepends `conf_`: 192 random bits,
32 URL-safe random characters, 37 characters overall. The prefix contributes
no entropy. The safe format contains no delimiters suitable for embedded
structured voting data. Generation validates the expected shape and handles
random-source `OSError` through `ConfirmationGenerationError`.

`is_confirmation_reference(value)` checks format only. It does not verify vote
acceptance, identify a voter or query stored state. Anyone can invent a string
of that shape; possession is not an authenticated proof of acceptance or choice.

The credential-facing service now returns only that string:

```python
reference = accept_ballot_with_credential(credential, candidate_id, opaque_payload)
```

No tuple, ballot object, preference, candidate, party, ballot ID, ciphertext,
credential, verifier or identity is returned. The existing trusted-identity
SR-03 `accept_ballot` remains unchanged and is not the future anonymous client
interface. SR-08 callers previously expecting None must now accept an opaque
string; the existing acceptance test was updated without dropping replay/state
assertions.

## Timing and failure handling

The existing acceptance transaction remains the authority:

1. Resolve the credential verifier and check expiry.
2. Revalidate enrolment, eligibility, assignment and the trusted final candidate.
3. Perform the SR-03 conditional SQL status claim; require exactly one row.
4. Delete the credential conditionally; require exactly one row.
5. Stage the anonymous ballot with its independent ballot-side ID.
6. Generate the ephemeral confirmation in memory, before attempting commit.
7. Commit status, deletion and ballot insertion together.
8. Return the confirmation only after commit succeeds.

Generation before commit prevents a random-source failure after a committed
ballot. On generation, insertion or pre-commit database failure, the same session
rolls back and the function raises the existing generic
`CredentialError("Credential authorisation failed")`; it returns no reference.
Generated-but-unreturned references are discarded and never persisted. Unexpected
programming errors retain the existing rollback-and-propagate behaviour for
internal diagnosis; future HTTP integration must suppress internal tracebacks.

Lost responses/process failure after commit cannot be recovered by a reference
lookup: no such lookup exists. A database commit whose outcome is unknown to the
client also requires operational handling; rollback cannot undo an already
completed commit. Tests inject failures before successful commit, not a fictitious
distributed rollback. Retrying an accepted vote remains a rejected credential
replay, even if the original response was lost.

## Independence and non-persistence

| Value | Relationship to confirmation |
|---|---|
| Ballot ID | Separate `secrets.token_hex(32)` draw inside the ballot writer; never returned, encoded or hashed into the confirmation |
| Credential/verifier | Neither is an input to generation. Confirmation format has length 37, so it cannot match the 43-character credential format; rejection occurs before hashing |
| Candidate/preference/payload | No input, derivation, hash, MAC or signature; all successful choices use the same confirmation semantics |
| Identity/session/IP/time | No input or embedded metadata |

No model/schema change, reference field, confirmation table, mapping, foreign key,
cache, audit entry or lookup method is added. The reference exists only in the
function's local memory and the returned output. Neither identity nor ballot
storage receives it. No reference-to-ballot, reference-to-credential or
reference-to-choice join can be performed on retained application rows.

The retained ballot schema remains exactly ballot ID, election, division and
opaque payload. Identity retains existing eligibility/status data; successful
credential voting deletes its verifier row. SR-08 cohort/inference and physical
storage limitations still apply. Database contents, live process memory or
client observation may reveal other information; a reference alone is not a
ballot lookup key.

## Logging, email, export and future presentation

Repository inspection found contact-email fields for enrolment data, but no
voting receipt mailer, confirmation lookup, ballot download/export or preference
receipt UI/API. Existing admin/audit endpoints serve their separate purposes;
SR-09 changes none of them. No email, receipt download, printable ballot, QR
code, signed preference proof, export endpoint or new audit event is introduced.

The confirmation service performs no logging/auditing. Tests observe both audit
entrypoints and application logs, and inspect SQL statements/parameters for
reference persistence. Workstream B's precise audit timestamps and existing
gateway logging are unchanged; they must not be extended with confirmation,
choice, identity or ballot-body data during final integration.

Future GUI presentation must contain only a generic success message and opaque
reference, for example `Vote accepted. Confirmation: <reference>`. It must not
repeat candidate/party/preference information, expose internal ballot IDs,
offer a receipt or provide a choice-verification link.

A future REST success body may contain only:

```json
{"status": "accepted", "confirmation_reference": "<opaque reference>"}
```

Disable/minimise request/response-body logging, analytics, session persistence,
crash dumps and browser tracing for voting data. Do not store the reference in
server sessions, send it by email or export it. No final GUI/REST implementation
is included here; transport presentation remains a separate integration task.

## Requirement-to-test traceability

| Acceptance/control | Automated evidence |
|---|---|
| Secure independent generation | `test_ballot_confirmation.py`: safe shape, distinct outputs, actual 24-byte randomness request, no voting parameters, malformed outputs and entropy failure |
| Only confirmation returned after commit | `test_confirmation_acceptance.py`: response inspection, real session after-commit ordering, separate random draws for internal ballot ID and reference |
| Different preferences cannot be reconstructed from reference | `test_confirmation_privacy.py`: two voters/two final candidates/distinct synthetic opaque payloads, distinct references, no internal values returned, no persisted reference or ballot-ID lookup match |
| No reference-to-choice mapping | Actual database schema reflection over all application tables, column/table/foreign-key inspection, retained-row scan and SQL parameter observation |
| No log/audit disclosure | Both audit entrypoints forbidden during successful voting; captured application logs remain empty |
| No success output on failure | `test_confirmation_failures.py`: invalid/expired credential and invalid candidate never generate output; insert/commit failure discards generated output and restores fresh-session state |
| Randomness failure is safe | Failure after claim/deletion and staged ballot rolls back before commit; caller receives only generic failure |
| Replay and role separation | Original credential cannot return a second reference; confirmation rejected as credential before verifier lookup; neither retrieves a ballot |
| Single confirmation under concurrency | Existing three two-connection SQLite same-credential races additionally require exactly one well-formed confirmation, one accepted ballot and actual SQL claim rowcounts `[0, 1]` |
| SR-03/SR-08 preserved | All existing eligibility, candidate, privacy, issuance, rollback, replay, expiry and genuine contention tests retained |

Numeric candidate IDs can coincidentally occur as substrings of random output.
Tests verify the opaque response contract and absence of derivation/structured
preference fields rather than making invalid claims about random substrings.
All payloads are synthetic opaque test data, not cryptographically encrypted
ballots or evidence that SR-10 has been implemented.

## Assumptions, limitations and review

The OS random source and trusted service caller are assumed sound. Calls own
their current session transaction and must contain no unrelated pending writes.
The reference is neither an authorisation credential nor verifiable proof of
acceptance, inclusion, counting or preference. There is no recovery/lookup,
revoting or replacement vote. Random collisions are negligibly probable rather
than prevented through persistence.

No claim covers screenshots/cameras, voluntary screen recording, malicious
browser extensions, compromised clients/servers or formal coercion resistance.
Existing SR-08 SQLite physical-store/service-credential limitations remain.
SR-10 encryption, authenticated payload binding, ballot chains, tamper detection
and tally integrity are deliberately deferred.

Review the minimal acceptance change, separate generator, non-persistence tests,
commit-failure timing and future response/logging contract before pushing.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_ballot_confirmation.py tests/test_confirmation_acceptance.py tests/test_confirmation_privacy.py tests/test_confirmation_failures.py -q
.\.venv\Scripts\python.exe -m pytest tests/test_ballot_models.py tests/test_ballot_service.py tests/test_ballot_concurrency.py tests/test_ballot_credentials.py tests/test_credential_acceptance.py tests/test_credential_privacy.py tests/test_credential_concurrency.py -q
.\.venv\Scripts\python.exe -m pytest -q
git --no-pager diff --check
```

Validation on this branch: 29 SR-09 tests passed, 105 SR-03/SR-08 regression
tests passed, and the full suite finished with 863 passed, 3 skipped and the
existing Flask `test_app` collection warning only. The complete change passes
`git diff --check`. No new dependencies or teammate-owned implementation changes
were required.
