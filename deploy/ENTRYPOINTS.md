# Compartment entrypoints (SR-20)

Every Python compartment runs from the same image, `deploy/Dockerfile.app`.
The image has no default command. Each Compose service sets its own
`command`, so a container runs only its own compartment's routes.

| Compartment | Entrypoint file | Gunicorn target | Owner | On `main` yet |
|---|---|---|---|---|
| voter-access | `gateway_runtime.py` | `gateway_runtime:application` | Workstream A | Yes |
| admin-audit | `admin/wsgi.py` | `admin.wsgi:app` | Workstream B | Yes |
| ballot | `ballot/wsgi.py` | `ballot.wsgi:app` | Workstream C | No |
| tally | `verification/wsgi.py` | `verification.wsgi:app` | Workstream D | No |
| results-consumer | `results_consumer/wsgi.py` | `results_consumer.wsgi:app` | Workstream D | No |

Checked against `origin/main` at `90f4968`. `tests/test_platform_dockerfile.py`
fails if the "On `main` yet" column no longer matches the files in the repository.

## Notes for owners

- Each `wsgi.py` should create a small app that registers only that
  compartment's blueprints and reads its own database URL from the environment.
- `app.py` adds `ballot` and `audit` database binds only when
  `EVP_BALLOT_DB_URL` / `EVP_AUDIT_DB_URL` are set, so other apps that use the
  shared `db` object from `records.py` need no binds.
- When a package folder reaches `main`, add a `COPY <folder>/ ./<folder>/` line
  to `deploy/Dockerfile.app` and change its row here to "Yes".
- `gateway_runtime:application` is Workstream A's local lab runtime. It needs
  `EVP_LOCAL_LAB=1`, its files under `/run/evp/` and a PII key (`EVP_KEY_DIR`).
  It trusts only the peers in `EVP_TRUSTED_GATEWAY_NETWORKS` (the gateway's
  fixed address in Compose; loopback when unset), as agreed with Binsa.
