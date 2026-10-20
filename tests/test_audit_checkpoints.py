"""
SR-17: Signed checkpoint archive tests.

The archive is a file in tmp_path standing in for the
separate audit-archive volume.
"""

import json
import logging

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.pool import StaticPool

import audit
import crypto_agility
from audit.checkpoints import (
    CHECKPOINT_INTERVAL,
    REASON_BAD_SIGNATURE,
    REASON_ENTRY_MISMATCH,
    REASON_ENTRY_MISSING,
    REASON_MALFORMED,
    REASON_OUT_OF_ORDER,
    ArchiveNotConfigured,
    CheckpointArchive,
    checkpoint_body,
    sign_checkpoint,
)
from audit.log import AuditLog
from crypto_agility import CryptoService, DEFAULT_POLICY, default_registry
from crypto_agility.algorithms import SIGN
from crypto_agility.keys import KeyStore


def new_crypto():
    return CryptoService(
        default_registry(), DEFAULT_POLICY, KeyStore.ephemeral()
    )


def memory_engine():
    return create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )


@pytest.fixture
def archive(tmp_path):
    return CheckpointArchive(tmp_path / "archive" / "checkpoints.jsonl")


@pytest.fixture
def audit_log(archive):
    archive.path.parent.mkdir()

    log = AuditLog(memory_engine(), crypto=new_crypto(), archive=archive)
    log.create_schema()

    return log


def add_events(audit_log, count, stream="identity"):
    for _ in range(count):
        audit_log.record_event(
            "AUTH_FAILURE" if stream != "admin" else "CONFIG_CHANGED",
            stream=stream,
            actor_type="anonymous" if stream != "admin" else "staff",
            actor_id=None if stream != "admin" else "admin-ada-lovelace",
            outcome="failure",
        )


def archived(archive):
    return [json.loads(line) for line in archive.lines()]


def rewrite_archive(archive, checkpoints):
    archive.path.write_text(
        "".join(json.dumps(c) + "\n" for c in checkpoints)
    )


def attacker_sql(audit_log, statement):
    with audit_log.engine.begin() as connection:
        connection.execute(text("DROP TRIGGER IF EXISTS audit_log_no_update"))
        connection.execute(text("DROP TRIGGER IF EXISTS audit_log_no_delete"))
        connection.execute(text(statement))


# Test 1: No checkpoint before the interval is reached
def test_no_checkpoint_before_interval(audit_log, archive):
    add_events(audit_log, CHECKPOINT_INTERVAL - 1)

    assert archive.lines() == []


# Test 2: A checkpoint is written every 50 entries per stream
def test_checkpoint_every_interval(audit_log, archive):
    add_events(audit_log, 2 * CHECKPOINT_INTERVAL)
    add_events(audit_log, 10, stream="admin")

    checkpoints = archived(archive)

    assert [(c["stream"], c["seq"]) for c in checkpoints] == [
        ("identity", 50), ("identity", 100)
    ]


# Test 3: Checkpoint records stream, seq, entry hash, time and signature
def test_checkpoint_contents(audit_log, archive):
    add_events(audit_log, 3)

    checkpoint = audit_log.checkpoint("identity")

    assert set(checkpoint) == {"stream", "seq", "entry_hash", "utc", "sig"}
    assert checkpoint["seq"] == 3
    assert checkpoint["sig"]["alg"] == "ed25519"
    assert checkpoint["sig"]["kid"] == "audit.ed25519.v1"
    assert archived(archive) == [checkpoint]


# Test 4: Checkpoint signature verifies
def test_checkpoint_signature_verifies(audit_log):
    add_events(audit_log, CHECKPOINT_INTERVAL)
    audit_log.checkpoint("identity")

    result = audit_log.verify_checkpoints()

    assert result.ok is True
    assert result.checked == 2


# Test 5: Tampered checkpoint fails signature verification
@pytest.mark.parametrize("field, value", [
    ("seq", 1), ("entry_hash", "forged"), ("utc", "2020-01-01T00:00:00Z"),
    ("stream", "admin"),
])
def test_tampered_checkpoint_fails(audit_log, archive, field, value):
    add_events(audit_log, 2)
    audit_log.checkpoint("identity")

    checkpoints = archived(archive)
    checkpoints[0][field] = value
    rewrite_archive(archive, checkpoints)

    result = audit_log.verify_checkpoints()

    assert result.ok is False
    assert result.broken_at_line == 1
    assert result.reason == REASON_BAD_SIGNATURE


# Test 6: Checkpoint forged with another key fails
def test_forged_checkpoint_fails(audit_log, archive):
    add_events(audit_log, 2)
    audit_log.checkpoint("identity")

    forged = sign_checkpoint(
        checkpoint_body("identity", 2, "forged", "2026-10-20T00:00:00Z"),
        new_crypto(),
    )
    archive.append(forged)

    result = audit_log.verify_checkpoints()

    assert (result.ok, result.broken_at_line, result.reason) == (
        False, 2, REASON_BAD_SIGNATURE
    )


# Test 7: Truncating the log tail is caught by checkpoints, not the chain
def test_truncated_log_detected_by_checkpoint(audit_log):
    add_events(audit_log, 5)
    audit_log.checkpoint("identity")

    attacker_sql(audit_log, "DELETE FROM audit_log WHERE seq > 3")

    assert audit_log.verify_chain("identity").ok is True

    result = audit_log.verify_checkpoints()

    assert (result.ok, result.reason) == (False, REASON_ENTRY_MISSING)


# Test 8: Rewritten checkpointed entry is detected
def test_rewritten_entry_detected_by_checkpoint(audit_log):
    add_events(audit_log, 2)
    audit_log.checkpoint("identity")

    attacker_sql(audit_log, "UPDATE audit_log SET entry_hash = 'x' "
                            "WHERE seq = 2")

    result = audit_log.verify_checkpoints()

    assert (result.ok, result.reason) == (False, REASON_ENTRY_MISMATCH)


# Test 9: Malformed archive lines are reported
@pytest.mark.parametrize("line", [
    "not json", "[]", '{"stream": "identity"}', "x" * 5000,
])
def test_malformed_archive_line(audit_log, archive, line):
    add_events(audit_log, 1)
    audit_log.checkpoint("identity")

    with archive.path.open("a") as handle:
        handle.write(line + "\n")

    result = audit_log.verify_checkpoints()

    assert (result.ok, result.broken_at_line, result.reason) == (
        False, 2, REASON_MALFORMED
    )


# Test 10: Replaying an older checkpoint after a newer one is reported
def test_replayed_old_checkpoint_is_out_of_order(audit_log, archive):
    add_events(audit_log, 1)
    first = audit_log.checkpoint("identity")
    add_events(audit_log, 1)
    audit_log.checkpoint("identity")

    archive.append(first)

    result = audit_log.verify_checkpoints()

    assert (result.ok, result.broken_at_line, result.reason) == (
        False, 3, REASON_OUT_OF_ORDER
    )


# Test 11: Checkpoints signed before an algorithm switch still verify (SR-14)
def test_checkpoints_survive_signing_algorithm_change(audit_log, archive):
    add_events(audit_log, 1)
    audit_log.checkpoint("identity")

    audit_log.crypto = audit_log.crypto.with_policy(
        DEFAULT_POLICY.with_default(SIGN, "ecdsa-p256-sha256")
    )
    add_events(audit_log, 1)
    audit_log.checkpoint("identity")

    algorithms = [c["sig"]["alg"] for c in archived(archive)]

    assert algorithms == ["ed25519", "ecdsa-p256-sha256"]
    assert audit_log.verify_checkpoints().ok is True


# Test 12: Archive is append-only across writers
def test_archive_appends_and_keeps_old_lines(audit_log, archive):
    add_events(audit_log, 1)
    audit_log.checkpoint("identity")

    reopened = CheckpointArchive(archive.path)
    reopened.append({"marker": 1})

    assert len(archive.lines()) == 2
    assert json.loads(archive.lines()[0])["seq"] == 1


# Test 13: Empty stream produces no checkpoint
def test_empty_stream_has_no_checkpoint(audit_log, archive):
    assert audit_log.checkpoint("ballot") is None
    assert archive.lines() == []


# Test 14: Without an archive, on-demand checkpoints are refused
def test_checkpoint_requires_archive():
    log = AuditLog(memory_engine(), crypto=new_crypto())
    log.create_schema()
    add_events(log, CHECKPOINT_INTERVAL)

    with pytest.raises(ArchiveNotConfigured):
        log.checkpoint("identity")

    with pytest.raises(ArchiveNotConfigured):
        log.verify_checkpoints()


# Test 15: A failing archive never loses the audit event
def test_archive_failure_keeps_event(tmp_path, caplog):
    log = AuditLog(
        memory_engine(),
        crypto=new_crypto(),
        archive=CheckpointArchive(tmp_path),  # a directory: writes fail
    )
    log.create_schema()

    with caplog.at_level(logging.ERROR, logger="evp.audit"):
        add_events(log, CHECKPOINT_INTERVAL)

    assert log.verify_chain("identity").checked == CHECKPOINT_INTERVAL
    assert "audit_checkpoint_failed" in caplog.text


# Test 16: EVP_AUDIT_ARCHIVE configures the archive from the environment
def test_env_archive_configuration(monkeypatch, tmp_path):
    archive_path = tmp_path / "checkpoints.jsonl"
    monkeypatch.setenv("EVP_AUDIT_DB_URL", "sqlite://")
    monkeypatch.setenv("EVP_AUDIT_ARCHIVE", str(archive_path))

    crypto_agility.configure(new_crypto())

    try:
        log = audit.build_audit_log_from_env()
        add_events(log, 1)
        log.checkpoint("identity")

        assert archive_path.exists()
        assert log.verify_checkpoints().ok is True

    finally:
        crypto_agility.configure(None)


# Test 17: Missing archive setting is logged, not silent
def test_env_without_archive_warns(monkeypatch, caplog):
    monkeypatch.setenv("EVP_AUDIT_DB_URL", "sqlite://")
    monkeypatch.delenv("EVP_AUDIT_ARCHIVE", raising=False)

    with caplog.at_level(logging.WARNING, logger="evp.audit"):
        log = audit.build_audit_log_from_env()

    assert log.archive is None
    assert "audit_checkpoint_archive_not_configured" in caplog.text
