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
--
-- Passwords are ${...} placeholders. They are filled from environment
-- variables / Docker secrets at init time and are never committed.
--
-- Run after the application schema exists: MySQL requires each table
-- named in a table-level GRANT to exist.

CREATE DATABASE IF NOT EXISTS identity_db;
CREATE DATABASE IF NOT EXISTS ballot_db;
CREATE DATABASE IF NOT EXISTS audit_db;

-- Voter access service (Workstream A): own enrolment and address records.
CREATE USER IF NOT EXISTS 'voter_access'@'%' IDENTIFIED BY '${VOTER_ACCESS_DB_PASSWORD}';
GRANT SELECT, INSERT, UPDATE ON identity_db.enrolment_records TO 'voter_access'@'%';
GRANT SELECT, UPDATE ON identity_db.address_records TO 'voter_access'@'%';

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
