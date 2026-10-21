"""
SR-17: Per-stream HMAC hash chains.

Security controls:
- Each entry's hash is an HMAC (crypto.mac("audit"),
  SR-14) over the previous entry's hash plus the
  canonical JSON of the entry, so changing, removing,
  reordering or inserting any entry breaks the chain
- Three independent chains (identity, ballot, admin),
  each starting from its own genesis value
- The MAC envelope stored with each entry records the
  algorithm and key version, so entries made before
  an algorithm change still verify (crypto-agility)
- The verifier reports the exact sequence number and
  a reason code at the first break

Local academic prototype.
"""

import json

from dataclasses import dataclass

from .models import AuditEntry


AUDIT_KEY_PURPOSE = "audit"
GENESIS_PREFIX = "genesis:"

REASON_MISSING = "missing_entry"
REASON_DUPLICATE = "duplicate_entry"
REASON_BROKEN_LINK = "broken_link"
REASON_INVALID_MAC = "invalid_mac"


def canonical_json(value) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def genesis_hash(stream: str) -> str:
    return GENESIS_PREFIX + stream


def entry_payload(entry: AuditEntry) -> dict:
    """Every stored field the chain protects."""

    return {
        "stream": entry.stream,
        "seq": entry.seq,
        "timestamp_utc": entry.timestamp_utc,
        "event_type": entry.event_type,
        "actor_type": entry.actor_type,
        "actor_id": entry.actor_id,
        "source_ip": entry.source_ip,
        "outcome": entry.outcome,
        "details_json": entry.details_json,
    }


def chain_message(prev_hash: str, entry: AuditEntry) -> bytes:
    return (
        prev_hash + "\n" + canonical_json(entry_payload(entry))
    ).encode("utf-8")


def seal_entry(entry: AuditEntry, prev_hash: str, crypto) -> None:
    """Link the entry to its predecessor and set its HMAC."""

    entry.prev_hash = prev_hash
    entry.entry_hash = canonical_json(
        crypto.mac(AUDIT_KEY_PURPOSE, chain_message(prev_hash, entry))
    )


def entry_mac_is_valid(entry: AuditEntry, crypto) -> bool:
    try:
        envelope = json.loads(entry.entry_hash)
    except (TypeError, ValueError):
        return False

    return crypto.verify_mac(
        AUDIT_KEY_PURPOSE,
        chain_message(entry.prev_hash or "", entry),
        envelope,
    )


@dataclass(frozen=True)
class ChainResult:
    stream: str
    ok: bool
    checked: int
    broken_at_seq: int | None = None
    reason: str | None = None

    def to_dict(self) -> dict:
        return {
            "stream": self.stream,
            "ok": self.ok,
            "checked": self.checked,
            "broken_at_seq": self.broken_at_seq,
            "reason": self.reason,
        }


def verify_entries(stream: str, entries, crypto) -> ChainResult:
    """
    Verify one stream's entries, given in ascending
    seq order. Stops at the first break.
    """

    expected_seq = 1
    prev_hash = genesis_hash(stream)
    checked = 0

    def broken(seq, reason):
        return ChainResult(stream, False, checked, seq, reason)

    for entry in entries:
        if entry.seq > expected_seq:
            return broken(expected_seq, REASON_MISSING)

        if entry.seq < expected_seq:
            return broken(entry.seq, REASON_DUPLICATE)

        if entry.stream != stream or entry.prev_hash != prev_hash:
            return broken(entry.seq, REASON_BROKEN_LINK)

        if not entry_mac_is_valid(entry, crypto):
            return broken(entry.seq, REASON_INVALID_MAC)

        prev_hash = entry.entry_hash
        expected_seq += 1
        checked += 1

    return ChainResult(stream, True, checked)
