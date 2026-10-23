# Workstream C: Voting flow integration

## Scope and architecture

Prototype-level integration connects the existing Flask voter application,
browser ballot interface, JSON endpoints and database to reviewed SR-03, SR-08,
SR-09 and SR-10 services. No security service was redesigned. Routes are thin
controllers; authentication, eligibility, candidate validation, credential
verification, encryption, chain updates and confirmation generation remain in
their existing owners.

```text
Existing password + TOTP login API
  -> authenticated server-side voter session
  -> GET /vote (trusted eligibility and final candidates)
  -> POST /vote/credentials {} (identity from session only)
  -> POST /vote/ballots {credential, candidate_id}
  -> reviewed credential acceptance and one atomic database commit
  -> current browser session cleared
  -> generic acceptance + ephemeral confirmation only
```

The existing application has a login API, not a login GUI. Authenticate through
that API in the same browser first, then open `/vote`. No new authentication or
staff/tally user interface is added.

## Endpoint contracts

| Endpoint | Authentication and input | Output |
|---|---|---|
| `GET /vote` | Existing `require_active_session`; server-configured election and session voter ID | HTML containing only trusted final candidates for stored division, and a CSRF token; no credential issued on GET |
| `POST /vote/credentials` | Active voter session, CSRF token, exact JSON `{}` | `{"credential":"<one-time bearer credential>"}` |
| `POST /vote/ballots` | CSRF token; exact JSON `{"credential":"...","candidate_id":1}`; no authenticated identity required | `{"status":"accepted","confirmation_reference":"conf_..."}` |
| `GET /vote/assets/ballot.js` and `.css` | Static controller/style assets | Same-origin assets with privacy headers |

The election is `VOTING_ELECTION_ID`, configured from `EVP_ELECTION_ID` with the
prototype default `election-2026`. Browser identity/election/division overrides
are not accepted. Unexpected body fields and query strings are rejected, as are
duplicate JSON keys, malformed JSON, invalid types and oversized requests.
Existing 4 KiB application request limits are unchanged. Non-JSON POSTs receive
415; malformed/CSRF requests 400; oversized requests 413; unavailable eligibility
or rejected credential voting 409; unexpected service failures 503. User-facing
errors contain no SQL, crypto, checkpoint or identity diagnostics.

The HTTP contract deliberately offers **no arbitrary payload field**. It supplies
the fixed non-identifying `{"format":"single-choice-web-v1"}` payload to the
existing service, which authenticates/encrypts it alongside the validated choice.
This avoids a new browser-controlled channel for embedding identity into ballot
content. No integrity values or selections are returned in a success response.

## Identity, CSRF and session behaviour

Credential issuance derives `session["voter_id"]` only from the existing verified
session. Anonymous submission passes only bearer credential, candidate and fixed
payload into `accept_ballot_with_credential`; it never passes session identity,
source IP or gateway metadata. A separate anonymous browser session with its own
CSRF token can also submit a valid credential, demonstrated by HTTP tests.

Flask-WTF CSRF remains enabled for **all** voting POSTs. There are no exemptions.
The page's generated token is sent in `X-CSRFToken`; same-origin HTTPS Referer
behaviour is preserved. The referrer policy is `same-origin`, rather than
`no-referrer`, because Flask-WTF's HTTPS strict checks require that header.

Secure/HttpOnly/SameSite cookies, server-side storage and inactivity enforcement
are unchanged. Only after acceptance succeeds does the route call
`session.clear()`, matching the existing logout mechanism and completing the
post-vote integration point. Failed acceptance does not log the voter out or
discard a recoverable credential. Clearing applies to the submitting browser
session; it is not global revocation of every session on other devices. Service
eligibility checks still refuse subsequent voting for the accepted voter.

CSRF/session cookies provide transport security, not network anonymity. The
normal GUI uses same-origin cookies and TLS, and the application necessarily
resolves authorisation internally. No claim is made that a live server, proxy
or network observer cannot correlate requests.

## Browser behaviour and privacy

`templates/voting/ballot.html` displays election/division and the trusted ordered
final candidate tuple, with a single-choice radio group. Jinja escaping remains
enabled. JavaScript is required for the POST-based credential handoff.

The controller issues a credential only when submitting, keeps it in transient
memory, sends neither identity nor credential in a URL, and prevents accidental
double clicks. On success it resets/removes the entire ballot UI and renders
only `Vote accepted.` and `Confirmation: <reference>` using text nodes. Extra
response fields are never displayed. It clears transient credential/choice
variables and clears the page on navigation; it uses no localStorage,
sessionStorage, analytics, receipt download, email, export or console logging.

Responses use `Cache-Control: no-store`, `Pragma: no-cache`, same-origin referrers,
`nosniff` and a scoped CSP allowing only same-origin scripts/styles/connections,
with no inline script, framing or external form targets. These controls cover
voting HTML, JSON, assets and handled errors; they do not replace deployment-wide
browser or proxy security policy.

The confirmation is not stored server-side, put in a redirect/session or exposed
through a lookup API. Refreshing after acceptance finds the cleared session;
the reference is intentionally not recoverable. A lost response may follow an
already committed vote; the UI warns against assuming failure or automatic
revoting. Screenshots, malicious extensions, browser memory and compromised
clients remain outside the prototype's receipt-free guarantee.

## Database effects and traceability

| Requirement | Real flow enforcement | HTTP/security evidence |
|---|---|---|
| SR-03 | Page/issuance use trusted eligibility; acceptance validates final candidates and performs existing conditional status claim | Real login-to-vote flow; replay, already-voted, removed enrolment, unknown/other-division/excluded candidates; injected insertion/commit failure |
| SR-08 | Verifier-only credential issuance; submission has no caller voter ID; consumed verifier deleted; no identity/IP enters ballot domain | Exact-field tampering tests, separate anonymous client, retained-table and schema inspection |
| SR-09 | Only generic accepted status and independently random confirmation returned; no reference mapping | HTTP body inspection, no reference in retained state/session/logs, isolated controller success-DOM test |
| SR-10 | Real AEAD ballot and hash-chain/checkpoint appended inside the existing commit | Verify/decrypt through trusted tally boundary after HTTP vote; direct database tamper rejected before tally input with generic event |

Successful HTTP submission commits `has_voted=True`, deletes the credential,
stores one encrypted/hash-linked anonymous ballot and updates authenticated
chain count/head. Rollback leaves all those changes uncommitted and returns no
confirmation. Tests exercise actual encryption/MAC/SQL/confirmation generation;
failure injection is used only for explicit failure paths.

There is no existing authorised tally endpoint in this checkout. The server-side
`verified_candidate_ids_for_tally` boundary remains mandatory for future group
tally integration; no voter-facing tally or integrity-proof API was added.

## Running the local gateway demonstration

The existing gateway runtime expects the Nginx HTTPS/mTLS setup and external
read-only voter/certificate configuration documented in Workstream A. The image
now includes `admin/`, `audit/`, `crypto_agility/`, templates and static assets;
the old image copied only top-level Python files and could not import the new
route dependencies.

For the optional **fresh, synthetic, in-memory** voting bootstrap set:

```text
EVP_LOCAL_LAB=1
EVP_VOTING_DEMO=1
EVP_CRYPTO_DEV_KEYS=1
EVP_DEMO_CANDIDATES_FILE=/run/evp/demo-candidates.json
EVP_AUDIT_DB_URL=sqlite:////run/evp/audit.db
EVP_AUDIT_ARCHIVE=/run/evp/audit-checkpoints.jsonl
```

Use a writable, separate directory for the audit DB/archive if `/run/evp` is
mounted read-only. Keep voter configuration and certificates read-only; do not
make secret mounts writable to accommodate the audit files. The runtime user
must have permission to write the chosen audit paths. A configured key directory
can replace explicit ephemeral dev-key mode; no automatic crypto fallback is
introduced.

The external candidate file has exact shape:

```json
{"candidates":[{"name":"Priyanka Patel","party":"Harbour Reform","position_in_group":1}]}
```

These names are an example fixture, not a hardcoded ballot list. Startup derives
the division from stored election eligibility and uses `add_draft_candidate`,
then the existing maker/checker proposal/approval service with two distinct
synthetic named staff rows. It writes the existing admin audit events and never
sets FINAL directly. This is explicit offline lab setup, **not** live staff
authentication, certificate verification or elevation. Random staff credentials
are discarded; no staff endpoints are registered by the voter app. Bootstrap
refuses persistent databases and existing candidate lists and aborts on invalid
configuration. Normal/group deployment must provision real candidate approval
through the existing authorised administration flow instead.

After startup, use the existing `/login/csrf` and `/login` password/TOTP JSON API
in the same browser, then navigate to `/vote`. No secrets or tokens belong in
URLs or browser logs. The existing gateway retains its certificate/network
checks. The Docker/Nginx/browser deployment was not newly automated by this task.

## Validation and remaining limitations

`test_voting_routes.py` and `test_voting_page.py` inspect endpoint contracts,
session/CSRF controls, trusted rendering and headers. `test_voting_end_to_end.py`
uses the actual Flask test client and real password/TOTP login, database and
voting services. It covers replay, invalid candidates, expiry, state changes,
rollback, generic unexpected failures, retained privacy and post-vote tampering.
`test_voting_hardening.py` covers strict JSON, query rejection, cross-origin and
old-CSRF rejection. `test_voting_runtime.py` exercises real demo finalisation.

The Node-based test executes the real browser controller in an isolated DOM/fetch
harness; it verifies response rendering, memory-only handoff, busy guard and
navigation cleanup. It is **not** a real browser engine or live network test.
Node is optional for that one isolated test (skipped if unavailable). A manual
HTTPS browser smoke test with client certificate remains a reviewer task.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_voting_routes.py tests/test_voting_page.py tests/test_voting_browser.py tests/test_voting_end_to_end.py tests/test_voting_hardening.py tests/test_voting_runtime.py -q
.\.venv\Scripts\python.exe -m pytest -q
git --no-pager diff --check
```

Validation: 56 focused integration tests passed. The full project suite passed
968 tests, with 3 existing skips and the existing Flask `test_app` collection
warning only. The complete integration diff passes whitespace checks. The
isolated controller test also covers navigation during issuance and acceptance,
so delayed responses cannot repopulate a cleared page.

Existing physical-store/service-credential separation, local-checkpoint rollback,
ephemeral/session/rate-limit storage, real geolocation, certificate revocation
and production key management limitations remain as documented for the security
tickets. `create_all` does not migrate old schemas; use fresh test/demo data or a
separately reviewed migration. Nginx access logs, framework diagnostics and any
future request/response-body logging need deployment privacy review; this code
does not log voting bodies or selections. Cookie/gateway infrastructure can
still correlate timing even though no such data is persisted in ballots.

Group-level authorised tally presentation, login GUI, production hosting and
deployment validation remain separate work. No CI workflow existed or was
required for this integration; group CI remains optional. No push, merge or PR
is part of this task.
