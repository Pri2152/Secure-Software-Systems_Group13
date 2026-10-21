-- SR-04 / SR-20: Least-privilege MySQL accounts, one per service.
--
-- Security controls:
-- - One database user per service; no shared credentials
-- - Table-level GRANTs only: no GRANT ALL, no *.* or db.* grants,
--   no GRANT OPTION
-- - ballot_db.ballots is insert-only for the ballot service (SR-10)
-- - audit_db.audit_log is append-only for the audit writer (SR-17):
--   SELECT (to read the last entry and chain the next one) and INSERT,
--   never UPDATE or DELETE
-- - The tally service can only read ballots
-- - The staff admin service (admin_identity) reaches only Workstream B's
--   tables, never voter records, and has no DELETE
-- - No account can CREATE, ALTER or DROP: tables are created as root
--   by deploy/scripts/apply_db_security.sh
--
-- Passwords are ${...} placeholders. They are filled from environment
-- variables / Docker secrets at init time and are never committed.
--
-- Applied by deploy/scripts/apply_db_security.sh, which first creates
-- Workstream B's tables as root: MySQL requires each table named in a
-- table-level GRANT to exist. GRANTs on tables that do not exist yet
-- are skipped with a warning.

CREATE DATABASE IF NOT EXISTS identity_db;
CREATE DATABASE IF NOT EXISTS ballot_db;
CREATE DATABASE IF NOT EXISTS audit_db;

-- Voter access service (Workstream A): own enrolment and address records.
CREATE USER IF NOT EXISTS 'voter_access'@'%' IDENTIFIED BY '${VOTER_ACCESS_DB_PASSWORD}';
GRANT SELECT, INSERT, UPDATE ON identity_db.enrolment_records TO 'voter_access'@'%';
GRANT SELECT, UPDATE ON identity_db.address_records TO 'voter_access'@'%';

-- Staff administration (Workstream B, admin-audit): staff accounts,
-- elevation grants, candidates and dual-authorisation operations only.
-- No DELETE: revoked grants and finished operations are kept as history.
CREATE USER IF NOT EXISTS 'admin_identity'@'%' IDENTIFIED BY '${ADMIN_DB_PASSWORD}';
GRANT SELECT, INSERT, UPDATE ON identity_db.staff_accounts TO 'admin_identity'@'%';
GRANT SELECT, INSERT, UPDATE ON identity_db.staff_elevation_grants TO 'admin_identity'@'%';
GRANT SELECT, INSERT, UPDATE ON identity_db.candidates TO 'admin_identity'@'%';
GRANT SELECT, INSERT, UPDATE ON identity_db.pending_operations TO 'admin_identity'@'%';

-- Ballot service (Workstream C): cast ballots are never changed or removed.
CREATE USER IF NOT EXISTS 'ballot_writer'@'%' IDENTIFIED BY '${BALLOT_DB_PASSWORD}';
GRANT SELECT, INSERT ON ballot_db.ballots TO 'ballot_writer'@'%';
GRANT SELECT, INSERT, UPDATE ON ballot_db.ballot_keys TO 'ballot_writer'@'%';

-- Audit writer (Workstream B): append-only audit log. SELECT reads the
-- last entry to chain the next one; entries are never changed or removed.
CREATE USER IF NOT EXISTS 'audit_writer'@'%' IDENTIFIED BY '${AUDIT_DB_PASSWORD}';
GRANT SELECT, INSERT ON audit_db.audit_log TO 'audit_writer'@'%';

-- Tally service (Workstream D): read ballots only, nothing else.
CREATE USER IF NOT EXISTS 'tally_reader'@'%' IDENTIFIED BY '${TALLY_DB_PASSWORD}';
GRANT SELECT ON ballot_db.ballots TO 'tally_reader'@'%';

FLUSH PRIVILEGES;
