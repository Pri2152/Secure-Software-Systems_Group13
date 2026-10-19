# Deployment (SR-19, SR-20)

This folder holds the Workstream E deployment:

- `docker-compose.yml`: isolated compartments, networks, databases and secrets
- `Dockerfile.app`: one non-root image for every Python compartment
- `ENTRYPOINTS.md`: which compartment runs which entrypoint
- `db/roles.sql`: least-privilege database accounts
- `scripts/make_secrets.sh`: generates local secrets

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

`bash deploy/scripts/make_secrets.sh --force` replaces every generated secret. A database that is already initialised keeps its old root password until its volume is removed (`docker compose -f deploy/docker-compose.yml down -v`, which deletes all database data).
