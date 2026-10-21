-- SR-06: Two-person rule backstop triggers for MySQL (Workstream B).
--
-- Security controls:
-- - An operation can only be stored as EXECUTED when two distinct
--   officers are recorded: approver_id is set and differs from
--   proposer_id (checked on INSERT and UPDATE)
-- - An EXECUTED operation can never be changed or deleted
-- - Works below the application, so a bug or a direct SQL session
--   cannot skip the maker-checker rule
-- - Same names and messages as the SQLite triggers in
--   admin/triggers.py
--
-- Run once as an administrator after the pending_operations table
-- exists in the identity database:
--   mysql -u root -p identity_db < deploy/db/dual_authorisation_triggers.sql

USE identity_db;

DROP TRIGGER IF EXISTS pending_operations_two_person_insert;
DROP TRIGGER IF EXISTS pending_operations_two_person_update;
DROP TRIGGER IF EXISTS pending_operations_executed_no_delete;

DELIMITER //

CREATE TRIGGER pending_operations_two_person_insert
BEFORE INSERT ON pending_operations
FOR EACH ROW
BEGIN
    IF NEW.status = 'EXECUTED'
       AND (NEW.approver_id IS NULL OR NEW.approver_id = NEW.proposer_id) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'two distinct officers required';
    END IF;
END//

CREATE TRIGGER pending_operations_two_person_update
BEFORE UPDATE ON pending_operations
FOR EACH ROW
BEGIN
    IF OLD.status = 'EXECUTED' THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'executed operations are final';
    END IF;

    IF NEW.status = 'EXECUTED'
       AND (NEW.approver_id IS NULL OR NEW.approver_id = NEW.proposer_id) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'two distinct officers required';
    END IF;
END//

CREATE TRIGGER pending_operations_executed_no_delete
BEFORE DELETE ON pending_operations
FOR EACH ROW
BEGIN
    IF OLD.status = 'EXECUTED' THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'executed operations are final';
    END IF;
END//

DELIMITER ;
