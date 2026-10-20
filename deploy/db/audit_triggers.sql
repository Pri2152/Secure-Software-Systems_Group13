-- SR-17: Append-only audit log triggers for MySQL (Workstream B).
--
-- Security controls:
-- - Every UPDATE or DELETE on audit_db.audit_log is aborted with
--   SQLSTATE 45000, even for accounts that hold those privileges
-- - Second layer under the least-privilege GRANTs in roles.sql
--   (the audit writer account gets no UPDATE or DELETE)
-- - Same trigger names and message as the SQLite triggers created
--   by audit/models.py, so tests and deployment behave the same
--
-- Run once as an administrator after the audit_log table exists:
--   mysql -u root -p audit_db < deploy/db/audit_triggers.sql

USE audit_db;

DROP TRIGGER IF EXISTS audit_log_no_update;
DROP TRIGGER IF EXISTS audit_log_no_delete;

DELIMITER //

CREATE TRIGGER audit_log_no_update
BEFORE UPDATE ON audit_log
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'audit_log is append-only';
END//

CREATE TRIGGER audit_log_no_delete
BEFORE DELETE ON audit_log
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'audit_log is append-only';
END//

DELIMITER ;
