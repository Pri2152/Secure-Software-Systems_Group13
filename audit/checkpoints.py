"""
SR-17: Signed audit checkpoints in a separate archive.

Security controls:
- Every CHECKPOINT_INTERVAL entries per stream (and on
  demand) the latest {stream, seq, entry_hash, utc} is
  signed with crypto.sign("audit") (SR-14) and
  appended to an archive outside the audit database
- The archive is opened append-only; in deployment it
  is a volume owned by a separate container
  (EVP_AUDIT_ARCHIVE), simulating write-once storage
  under separate administrative control
- Verification checks each checkpoint's signature,
  per-stream ordering, and that the audit database
  still holds the exact checkpointed entry, which
  exposes truncation or a rebuilt chain that the
  hash chain alone could not reveal

Local academic prototype.
"""

import json
import os

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .chain import AUDIT_KEY_PURPOSE, canonical_json
from .events import STREAMS


CHECKPOINT_INTERVAL = 50
ENV_AUDIT_ARCHIVE = "EVP_AUDIT_ARCHIVE"

ARCHIVE_FILE_MODE = 0o600
BINARY_FLAG = getattr(os, "O_BINARY", 0)  # no newline translation on Windows
MAX_ARCHIVE_LINE_LENGTH = 4096
CHECKPOINT_FIELDS = frozenset({"stream", "seq", "entry_hash", "utc"})

REASON_MALFORMED = "malformed"
REASON_BAD_SIGNATURE = "bad_signature"
REASON_OUT_OF_ORDER = "out_of_order"
REASON_ENTRY_MISSING = "entry_missing"
REASON_ENTRY_MISMATCH = "entry_mismatch"


class ArchiveNotConfigured(RuntimeError):
    """No checkpoint archive path is configured."""


class CheckpointArchive:
    """Append-only JSON-lines file of signed checkpoints."""

    def __init__(self, path):
        self.path = Path(path)

    def append(self, checkpoint: dict) -> None:
        line = (canonical_json(checkpoint) + "\n").encode("ascii")

        descriptor = os.open(
            self.path,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | BINARY_FLAG,
            ARCHIVE_FILE_MODE,
        )

        try:
            os.write(descriptor, line)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def lines(self) -> list[str]:
        if not self.path.exists():
            return []

        return self.path.read_text(encoding="ascii").splitlines()


def checkpoint_body(stream: str, seq: int, entry_hash: str, utc: str) -> dict:
    return {
        "stream": stream,
        "seq": seq,
        "entry_hash": entry_hash,
        "utc": utc,
    }


def sign_checkpoint(body: dict, crypto) -> dict:
    signature = crypto.sign(
        AUDIT_KEY_PURPOSE, canonical_json(body).encode("ascii")
    )

    return {**body, "sig": signature}


@dataclass(frozen=True)
class CheckpointResult:
    ok: bool
    checked: int
    broken_at_line: int | None = None
    reason: str | None = None

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "checked": self.checked,
            "broken_at_line": self.broken_at_line,
            "reason": self.reason,
        }


def _parse_line(line: str):
    if len(line) > MAX_ARCHIVE_LINE_LENGTH:
        return None

    try:
        checkpoint = json.loads(line)
    except ValueError:
        return None

    if (
        not isinstance(checkpoint, dict)
        or set(checkpoint) != CHECKPOINT_FIELDS | {"sig"}
        or checkpoint["stream"] not in STREAMS
        or type(checkpoint["seq"]) is not int
        or checkpoint["seq"] < 1
        or not isinstance(checkpoint["entry_hash"], str)
        or not isinstance(checkpoint["utc"], str)
    ):
        return None

    return checkpoint


def verify_checkpoint_lines(
    lines: list[str],
    crypto,
    entry_hash_at: Callable[[str, int], str | None],
) -> CheckpointResult:
    """
    Verify archive lines in order. entry_hash_at(stream,
    seq) returns the hash now stored in the audit DB.
    """

    last_seq = {}
    checked = 0

    for number, line in enumerate(lines, start=1):

        def broken(reason):
            return CheckpointResult(False, checked, number, reason)

        checkpoint = _parse_line(line)

        if checkpoint is None:
            return broken(REASON_MALFORMED)

        body = {name: checkpoint[name] for name in CHECKPOINT_FIELDS}

        if not crypto.verify(
            AUDIT_KEY_PURPOSE,
            canonical_json(body).encode("ascii"),
            checkpoint["sig"],
        ):
            return broken(REASON_BAD_SIGNATURE)

        stream, seq = body["stream"], body["seq"]

        if seq < last_seq.get(stream, 0):
            return broken(REASON_OUT_OF_ORDER)

        stored_hash = entry_hash_at(stream, seq)

        if stored_hash is None:
            return broken(REASON_ENTRY_MISSING)

        if stored_hash != body["entry_hash"]:
            return broken(REASON_ENTRY_MISMATCH)

        last_seq[stream] = seq
        checked += 1

    return CheckpointResult(True, checked)
