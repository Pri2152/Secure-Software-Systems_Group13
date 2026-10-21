# Deployment (SR-19, SR-20)

This folder holds the Workstream E deployment:

- `docker-compose.yml`: isolated compartments, networks, databases and secrets
- `Dockerfile.app`: one non-root image for every Python compartment
- `ENTRYPOINTS.md`: which compartment runs which entrypoint
- `db/roles.sql`: least-privilege database accounts
- `scripts/make_secrets.sh`: generates local secrets
- `scripts/apply_db_security.sh`: applies database accounts and triggers

Secrets go in `deploy/secrets/`, which is git-ignored.
Never commit real secrets, passwords or keys.

## Before the first start

- Docker Desktop must be running.
- The gateway needs Workstream A's local test certificates in `nginx/certs/` (`server.crt`, `server.key`, `test-ca.crt`), as described in `docs/WORKSTREAM_A_IMPLEMENTATION.md`. Workstream E does not create or change certificates.
- Workstream A also supplies `deploy/secrets/demo-voter.json` and `deploy/secrets/registered_fingerprints.txt`.

## Commands

Run from the repository root.

Generate secrets (once; refuses to overwrite existing files):

```
bash deploy/scripts/make_secrets.sh
```

Start the stack:

```
docker compose -f deploy/docker-compose.yml up -d --build
```

Check it:

```
docker compose -f deploy/docker-compose.yml ps
```

Stop it (keeps database volumes):

```
docker compose -f deploy/docker-compose.yml down
```

Services for Workstreams B, C and D start only with `--profile full`, once their code is on `main`.

## Database accounts and triggers

Run in this order:

1. `bash deploy/scripts/make_secrets.sh`
2. `docker compose -f deploy/docker-compose.yml --profile full up -d --build`
3. Wait until the apps have created their tables (`docker compose -f deploy/docker-compose.yml ps` shows them running).
4. `bash deploy/scripts/apply_db_security.sh`

Step 4 creates the least-privilege accounts from `db/roles.sql` on each database container, then adds the audit log triggers to `db-audit` and the two-person rule triggers to `db-identity`. A GRANT whose table does not exist yet (for example the ballot tables, which come with Workstream C) is skipped with a warning; re-run step 4 once the table exists. Re-run it after `make_secrets.sh --force` as well, so the database passwords match the new files.

`bash deploy/scripts/make_secrets.sh --force` replaces every generated secret. A database that is already initialised keeps its old root password until its volume is removed (`docker compose -f deploy/docker-compose.yml down -v`, which deletes all database data).
