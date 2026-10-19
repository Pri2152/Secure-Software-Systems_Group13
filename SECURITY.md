# Security policy

This is an academic prototype of an Electronic Voting Platform (Group 13, INTE2667). It holds synthetic data only. This policy covers SR-20: how we find, rank and fix vulnerabilities in our code and in third-party components.

## Reporting a vulnerability

Report it privately. Do not open a public issue or pull request, and do not post details in shared chats.

- Use GitHub's private reporting: the repository's **Security** tab, then **Report a vulnerability**. (A repository admin must turn this on under Settings → Code security.)
- Include the affected file or component, the steps to reproduce it, and what an attacker could gain.

We confirm receipt within 24 hours.

## How we rank it

1. **Severity:** the CVSS base score. Critical is 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low below 4.0.
2. **Exploitability:** we raise the priority if exploit code is public, the flaw is already being exploited, or it can be reached without logging in.
3. **Asset criticality:** we raise the priority if it touches ballots, voter personal data, the audit log, keys or secrets, or the gateway.

## Time limits for critical vulnerabilities

Measured from when the report or alert is received:

- **Election period: fixed within 24 hours.**
- **Otherwise: fixed within 72 hours.**

"Fixed" means a patch merged to `main`, or a documented mitigation (for example, turning off the affected feature) until the patch lands. We fix lower-severity issues in priority order after these.

## Who patches and who reviews

The owner of the affected workstream writes the fix:

| Area | Owner |
|---|---|
| Voter login, records, Nginx gateway | Workstream A |
| Staff accounts, dual approval, audit log, crypto service | Workstream B |
| Ballot store | Workstream C |
| Tally, results, bulletin board | Workstream D |
| Access control, deployment, CI, dependencies | Workstream E |

A different group member reviews and approves the pull request. Workstream E also reviews any dependency or deployment change.

## Dependabot and CI

- **Dependabot** checks `requirements.txt` and our Docker images weekly. It raises an alert and opens an update pull request. Each alert is ranked as above.
- **CI** (`.github/workflows/ci.yml`) runs on every push and pull request. It runs all tests, then `pip-audit`, which fails the build if any pinned package has a known vulnerability. A failed `pip-audit` step is handled like a new report. With branch protection on, a failing build cannot be merged.

## Evidence we keep

- Every CI run keeps its log and uploads an `sbom` artifact: a CycloneDX list of every third-party package in that build. GitHub keeps these for 90 days by default, so we download the runs we need for the report.
- Each vulnerability gets a private security advisory (or an issue with the `security` label once it is fixed). It records when it was reported, its rank, the fixing pull request, and when it was fixed, so we can show the time limits were met.
