# SR-10: Ballot integrity and tamper detection

## Requirement and scope

SR-10 requires authenticated encryption and append-only hash-linked records for
accepted ballots, verification before tally, detection of alteration, insertion,
deletion and reordering, and a security event on integrity failure.

Service-level prototype complete with local-checkpoint/external-anchor
limitations; GUI/REST/tally presentation integration remains. There was no tally
implementation in the checkout: this change adds a mandatory verified-input
boundary for trusted future tally code, not an election-results application.

SR-10 provides application-level authenticated ballot storage and detects
inconsistent/tampered retained chain state before tally. It does not provide
immutable blockchain storage or protection against compromised keys/servers.

## Architecture and authenticated content

Both acceptance paths continue their existing SR-03 eligibility/candidate checks
and conditional `has_voted=False -> True` SQL claim. The credential-facing path
also deletes the SR-08 credential conditionally. They pass only election, stored
division, supplied payload and the **same validated candidate ID** into the narrow
ballot writer. No identity or credential crosses that boundary.

`ballot_protection.py` constructs canonical UTF-8 JSON with sorted keys, compact
separators and `allow_nan=False`:

```json
{"candidate_id": 7, "payload": "<caller-supplied content>", "v": 1}
```

The candidate is not read from the supplied content. Even if that string embeds
a different candidate ID, the server constructs the authenticated selection from
the independently validated argument. Caller content remains an opaque string
for compatibility; callers must not embed identity in it.

`crypto_agility.crypto.encrypt("ballot", plaintext, aad=...)` performs actual
authenticated encryption. The default existing policy uses AES-256-GCM; policy
and versioned key handling remain entirely in SR-14. No crypto dependency, key
generation system, hardcoded key or teammate crypto change is introduced.

AAD is canonical JSON containing `domain="EVP_BALLOT_V1"`, ballot ID, election,
division, positive chain index and previous hash. It contains no voter,
credential, confirmation, IP or timestamp. Moving a ciphertext between records,
partitions or chain positions fails authentication.

`encrypted_ballot_json` now stores the full canonical AEAD envelope with
`alg`, `kid`, `v`, `nonce`, `ct`, rather than the caller's placeholder string.
Candidate and payload exist only inside encrypted content on ballot rows.
Authentication rejects malformed/noncanonical/duplicate-key JSON and validates
the decrypted exact field set, version, candidate type and payload bounds.
The private decryption helper is not a tally entrypoint.

## Chain and authenticated checkpoint

`AnonymousBallot` adds non-null `chain_index`, `previous_hash`, `record_hash`.
UNIQUE `(election_id, electoral_division, chain_index)` prevents duplicate
positions; a CHECK requires positive indexes. No identity or timestamp is added.
`BallotChainState`, keyed by election/division, stores nonnegative expected
`record_count`, `head_hash`, and `checkpoint_json` only.

Hashes are `sha256:<64 lowercase hex>` using standard-library SHA-256 over
canonical domain-separated JSON. A fixed SHA-256 record format avoids silently
changing historic links when the central configurable default hash changes.
AEAD and keyed checkpoint cryptography still use the central service.

| Value | Hashed/authenticated material |
|---|---|
| Genesis | `EVP_BALLOT_GENESIS_V1`, election and division |
| Record hash | `EVP_BALLOT_RECORD_V1`, full AAD metadata and parsed full encryption envelope |
| Checkpoint MAC | `EVP_BALLOT_CHECKPOINT_V1`, election, division, expected count and head |

Checkpoint authentication uses central `crypto.mac("ballot-chain", ...)` and
`verify_mac` with its self-describing versioned envelope (default HMAC-SHA256).
The separate purpose prevents ballot/checkpoint key confusion. Production key
manifests must provide both the ballot AEAD and ballot-chain MAC purposes, and
retain allowed historical key versions for verification/decryption.

The chain is logically append-only: normal service code never edits/deletes an
accepted ballot. Raw database writes are not blocked by new triggers; they are
the attacks detected by verification. Least-privilege deployment DB access
remains required.

## Atomic append and concurrency

Within the existing acceptance transaction, `append_ballot`:

1. Loads/authenticates the partition checkpoint. First use initialises an empty
   checkpoint only when there are no existing ballots; legacy rows cannot be
   silently adopted.
2. Allocates the next index from count, and uses the current head as previous
   hash. Generates an independent random 256-bit ballot ID.
3. Builds/encrypts the validated content, computes the record hash and MACs the
   next expected count/head.
4. Conditionally updates chain state WHERE the previous count, head **and**
   checkpoint still match; requires exactly one changed row.
5. Stages the ballot insertion. The caller generates the independent SR-09
   confirmation and commits status, credential deletion, encrypted ballot and
   checkpoint once together. There is no second commit or nested transaction.

Any expected crypto, chain or database failure rolls back the entire acceptance
and produces a safe domain error; no plaintext fallback or confirmation escapes.
Unexpected programming errors preserve rollback-and-propagate behaviour.
In-memory ORM checkpoint attributes can be stale before commit because the SQL
claim disables session synchronisation; security checks use SQL rowcounts and
persisted/explicitly refreshed data. Successful commit expires ORM state.

Database uniqueness and compare-and-swap prevent forks. Conflicts fail safely;
there is no automatic retry. SQLite serialises the identity write claims, so
two valid voters can both append sequentially within a concurrent race. Other
database engines/isolation modes may reject a contender and require a fresh
retry. They need deployment-specific validation.

## Verification before tally

`verify_ballot_chain(election_id, division)` returns True only after full
verification; it discloses no selections. Trusted server tally code must use
`verified_candidate_ids_for_tally(...)`, returning an immutable tuple of IDs
only after every record passes. No voter-facing route exposes either operation.

Both use an independent read session and one consistent snapshot. SQLite uses
an explicit `BEGIN` because its legacy driver does not start a snapshot for
SELECT automatically; other engines request SERIALIZABLE isolation. Verification:

- requires a checkpoint (missing is unavailable, not a silently valid empty
  election), and authenticates its MAC;
- compares actual count with expected count;
- checks contiguous positions, genesis, every previous link and full record
  hash, then reconstructed head against checkpoint;
- authenticates/decrypts every envelope using its own metadata and validates
  protected structure;
- materialises all results before returning any selections. A bad final ballot
  cannot produce partial tally input. There is no skip, repair or hash rewrite.

No election-wide tally aggregation or candidate-exclusion policy is introduced.
The returned tuple is trusted input for future tally logic, not a published
result or permanent snapshot handle. Later database changes require verification
again.

## Integrity security event

Each failed verifier attempt raises generic `BallotIntegrityError` and calls the
existing audit routine once with `BALLOT_INTEGRITY_FAILURE`, stream `ballot`,
actor type `anonymous`, actor ID None, outcome `failure`, source IP None and no
details. Tests exercise the real audit store and verify its generic fields.

The audit timestamp records **failed verification time**, not ballot acceptance.
It has no ballot/candidate/identity/credential/confirmation/IP correlation data.
If the audit service is unavailable, verification still fails closed and emits
only the generic fallback log `BALLOT_INTEGRITY_FAILURE audit_unavailable`.
Operators must treat that fallback as loss of durable audit delivery. No
acceptance events, ciphertext or plaintext are logged.

## Requirement-to-test traceability

| Control | Evidence |
|---|---|
| Real AEAD, trusted selection and canonical content | `test_ballot_protection.py`: round trip, embedded untrusted candidate ignored, randomised ciphertext, strict structure and key failure |
| Metadata/position binding | Five AAD-field mutations, ciphertext alteration, and a copied-envelope attack behind a test-resealed valid checkpoint |
| Chain construction/checkpoint | `test_ballot_chain.py`: linked records, independent partitions, unique positions, forged/missing state rejection and a real zero-row conditional claim |
| Alteration/insertion/deletion/reordering | `test_ballot_tampering.py`: committed raw SQL updates/insertion, middle deletion, tail deletion and stored-index swaps; no tally output and one generic audit event each |
| Stronger hash attack | Attacker recomputes every unkeyed link; retained keyed checkpoint still rejects it |
| Checkpoint tampering | Count, head, MAC and coordinated tail/count/head changes without a valid MAC fail |
| Mandatory verify-before-tally | `test_ballot_integrity.py`: full valid tuple; bad final record and unavailable decryption key release no input |
| Failure auditing | Real audit records have no actor/source/details; unavailable audit has a generic fallback signal |
| Atomicity | `test_ballot_integrity_failures.py`: encryption, record construction, checkpoint MAC, state update, insertion and commit failures preserve previous count/head/MAC, ballot count, eligibility and credential; retry works |
| First append rollback | Missing ballot crypto leaves zero ballots/checkpoints, unvoted eligibility and restored credential |
| Concurrency | Three same-credential races yield one ballot/confirmation/verified append; three different-voter races yield two unique positions and a valid chain |
| Consistent tally snapshot | `test_ballot_snapshot.py`: WAL-backed second connection commits a valid vote after checkpoint read; current verification sees the complete old snapshot and the next verification sees both votes |
| SR-08/SR-09 privacy | Retained-state/schema tests keep prohibited identity fields absent; raw payloads absent from storage, confirmed IDs recoverable only through verified tally; independent confirmations remain unpersisted and reveal no record hash |

Tests preserve the existing rollback/replay/expiry/candidate checks. Earlier
storage tests now use genuine protected appends and verified tally input rather
than persisting synthetic plaintext envelopes. Failure injection observes actual
SQL state after claims before rollback; concurrency uses file databases, threads,
separate connections and barriers, not sequential submissions labelled as races.

## Deployment assumptions and limitations

Keys and the live service are trusted. Compromised keys can forge checkpoints or
new authenticated ciphertext; a compromised application can bypass service
boundaries. The local checkpoint lives in the same SQLite database. It detects
tampering relative to retained authenticated expected state, including truncation
of the tail, but a coordinated restoration of an entire older valid database and
checkpoint can pass. Detecting historic rollback needs a separately administered
external monotonic anchor; none is claimed here. Deleting an entire partition
and its checkpoint makes verification fail missing-state, but first-use append
bootstrap cannot distinguish a destroyed partition from a never-initialised
one. Provisioning expected partitions/external anchors is required to close
that reset ambiguity in deployment.

No schema migration framework exists. Existing pre-SR-10 databases need an
explicit reviewed migration/new synthetic database; `create_all` does not alter
old tables. Placeholder ballots cannot be reinterpreted as authenticated votes.
Fresh tests create the new schema. Persistent crypto keys are required across
restarts; ephemeral test keys deliberately do not provide persistence.

SR-08's physical-store/service-credential limitation remains: one local database
preserves transaction atomicity. Chain order adds cohort/ordering inference
risk even without precise timestamps. No formal anonymity or coercion-resistance
guarantee is added. SQL/debug/HTTP body logging still needs deployment controls.

SR-03 status/credential atomicity, SR-08 identity separation and SR-09 opaque
confirmation contract remain enforced. Final RBAC-protected tally orchestration,
GUI/REST presentation, key provisioning, migration and production isolation
remain integration work. No integrity proofs, chain indexes/hashes, keys,
envelopes or selections are returned to voters. Nothing was pushed or merged.

## Validation

Use the repository virtual environment with module invocation:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_ballot_protection.py tests/test_ballot_chain.py tests/test_ballot_integrity.py tests/test_ballot_tampering.py tests/test_ballot_integrity_failures.py tests/test_ballot_snapshot.py -q
.\.venv\Scripts\python.exe -m pytest -q
git --no-pager diff --check
```

Final focused SR-10 result: 46 passed. The broader Workstream C run passed all
182 tests before the additional passing snapshot test. Final full project run:
912 passed, 3 skipped, with only the existing Flask `test_app` collection warning.
The full suite includes all preserved SR-03/SR-08/SR-09 regressions. The complete
change passes `git diff --check`. Five substantive local commits separate
protection, chain/checkpoint integration, verification/auditing, adversarial
testing and final snapshot/validation documentation.
