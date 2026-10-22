# Deployment (SR-19, SR-20)

This folder holds the Workstream E deployment:

- `docker-compose.yml`: isolated compartments, networks, databases and secrets
- `Dockerfile.app`: one non-root image for every Python compartment
- `ENTRYPOINTS.md`: which compartment runs which entrypoint
- `db/roles.sql`: least-privilege database accounts
- `db/audit_triggers.sql`, `db/dual_authorisation_triggers.sql`: Workstream B's MySQL triggers
- `scripts/make_secrets.sh`: generates local secrets, and the crypto key folder through `scripts/make_keys.py`
- `scripts/apply_db_security.sh`: creates tables as root (`scripts/schema_sql.py`), then applies database accounts (`scripts/roles_plan.py`) and triggers
- `scripts/backup.sh`, `scripts/restore.sh`: scheduled backups and the timed restore drill
- `scripts/rotate_pii_key.py`: PII key rotation
- `../scripts/load_test.py`: load and flood drill (run from this PC and from `terminal-sim`)

Secrets go in `deploy/secrets/`, which is git-ignored.
Never commit real secrets, passwords or keys.

## Before the first start

- Docker Desktop must be running.
- The gateway needs Workstream A's local test certificates in `nginx/certs/` (`server.crt`, `server.key`, `test-ca.crt`), as described in `docs/WORKSTREAM_A_IMPLEMENTATION.md`. Workstream E does not create or change certificates.
- Workstream A also supplies `deploy/secrets/demo-voter.json` and `deploy/secrets/registered_fingerprints.txt`.

## Commands

Run from the repository root.

Generate secrets (creates only missing files; `--force` replaces them all):

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

Services for Workstreams C and D start only with `--profile full`, once their code is on `main`. The `terminal-sim` drill service starts only with `--profile drill`.

## Load and flood drill

The gateway uses Workstream A's self-signed test certificate, so `--insecure` (skip certificate checks) is needed; the script refuses it, and any target, other than `localhost`, `127.0.0.1` or `gateway`.

Load: 20 clients for 60 seconds against `/healthz` and the login flow:

```
python scripts/load_test.py load --clients 20 --duration 60 --insecure
```

Flood: start the registered terminal and the attacker together, in two terminals:

```
docker compose -f deploy/docker-compose.yml --profile drill up terminal-sim
python scripts/load_test.py flood --side attacker --duration 60 --insecure
```

## Database accounts and triggers

Run in this order:

1. `bash deploy/scripts/make_secrets.sh`
2. `docker compose -f deploy/docker-compose.yml up -d --build`
3. Wait until `db-identity` and `db-audit` show as healthy in `docker compose -f deploy/docker-compose.yml ps`.
4. `bash deploy/scripts/apply_db_security.sh`

Step 4 creates the identity and audit tables as root (from Workstream A's and B's own models), then the least-privilege accounts from `db/roles.sql` on each database container, then the audit log triggers on `db-audit` and the two-person rule triggers on `db-identity`. No app account can create or change tables.

`admin-audit` restarts until step 4 has run, because its database accounts do not exist before that; it then starts on its own.

A GRANT whose table does not exist yet (for example the ballot tables, which come with Workstream C) is skipped with a warning; re-run step 4 once the table exists. Re-run it after `make_secrets.sh --force` as well, so the database passwords match the new files.

## Backup and restore drill

The `backup` service dumps the identity, ballot and audit databases every 15 minutes (`mysqldump --single-transaction`) into the separate `backups` volume, one folder per UTC timestamp (for example `20261021T093000Z`), and keeps the newest 96 (24 hours). Target: lose at most 15 minutes of data (RPO) and be back within 2 hours (RTO).

Run the drill from the repository root, with the stack up:

1. Take a backup now (or wait for the next scheduled one):
   `docker compose -f deploy/docker-compose.yml exec backup bash /usr/local/bin/evp-backup.sh --once`
2. List the backups and pick a timestamp:
   `docker compose -f deploy/docker-compose.yml run --rm --no-deps --entrypoint ls backup -1 /backups`
3. Restore it:
   `bash deploy/scripts/restore.sh 20261021T093000Z`

`restore.sh` checks the backup files, stops the app services and the backup service, restores the three databases, starts the services again, and then checks the audit hash chain (Workstream B) and the ballot store (Workstream C's `verify_ballot_store`). A check that is not merged yet is reported with a warning. It prints the start time, end time and total duration; record them as the drill evidence. If anything fails, the app services stay stopped so nothing runs on a half-restored database.

Database accounts and passwords live in MySQL's own system tables, not in these dumps. If a database volume itself was lost, run `bash deploy/scripts/apply_db_security.sh` after the restore. Keys are not in the backups either: back them up separately (see Key rotation).

## Key rotation

Rotate the PII encryption key (SR-13) at least every 12 months, and at once if a key may have leaked.

1. Stop `voter-access-1`, `voter-access-2` and `admin-audit`.
2. Check first with `--dry-run`, then rotate. The identity database URL is read from `EVP_IDENTITY_DB_URL`, never from the command line:
   `python deploy/scripts/rotate_pii_key.py --generate-new-key --dry-run`
   `python deploy/scripts/rotate_pii_key.py --generate-new-key`
3. Mount the new key file (for example `pii_key_v2`) for the services in `docker-compose.yml`, next to `pii_key_v1`, then start them.

The script lists the new key before changing any row and makes it current only after every row decrypts with it, so a failure leaves every row readable; run it again to continue. It never removes the old key: keep it until a backup taken after the rotation has been checked.

Back up the keys in `deploy/secrets/keys/` separately from database backups, and never in the same place: a database backup together with its key is readable by anyone who gets both. Losing the keys means losing the encrypted data.

## Limitations

- Workstream A's login rate limiter and TOTP replay guard keep their state in memory in each process, so the two voter-access replicas do not share it. An attacker whose requests reach both replicas gets each replica's allowance, and a TOTP code used on one replica is not known to the other. Nginx's `ip_hash` keeps each client on one replica, and the 5-per-minute `/login` limit in Nginx applies across both; a shared store (for example Redis) would close this fully.
- Sessions are also held per replica, with a Flask secret key generated by each process. If a replica fails, its users are moved to the other replica and must log in again.
- The databases are on internal networks and not published to this PC, and no app account may change the encrypted columns, so `rotate_pii_key.py` needs a one-off container on `identity_net` with an account that can. That step is not scripted yet.
- `/healthz` is blocked at the gateway, so the load drill's health requests return 404 from Nginx; only the containers' own health checks reach it.
