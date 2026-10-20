"""
SR-17: Audit event vocabulary and input validation.

Security controls:
- Allow-lists for stream, actor type and outcome;
  event types must be UPPER_SNAKE_CASE names
- Separate "identity", "ballot" and "admin" streams so
  voter identity events and ballot events never share
  one ordered log (protects ballot secrecy, SR-08)
- The "ballot" stream refuses an actor ID or source
  IP, so a ballot event cannot name a voter
- Lengths are capped and IP addresses are parsed, so
  callers cannot smuggle free text into these columns

Local academic prototype.
"""

import ipaddress
import re


STREAM_IDENTITY = "identity"
STREAM_BALLOT = "ballot"
STREAM_ADMIN = "admin"

STREAMS = (STREAM_IDENTITY, STREAM_BALLOT, STREAM_ADMIN)

ACTOR_TYPES = frozenset({"voter", "staff", "system", "anonymous"})
OUTCOMES = frozenset({"success", "failure", "denied"})

EVENT_TYPE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{1,63}")
MAX_ACTOR_ID_LENGTH = 128


def validate_event(
    event_type,
    stream,
    actor_type,
    actor_id,
    outcome,
    source_ip,
) -> None:
    """Raise ValueError if any field breaks the audit contract."""

    if not isinstance(event_type, str) or not EVENT_TYPE_PATTERN.fullmatch(
        event_type
    ):
        raise ValueError("Invalid audit event type")

    if stream not in STREAMS:
        raise ValueError("Invalid audit stream")

    if actor_type not in ACTOR_TYPES:
        raise ValueError("Invalid audit actor type")

    if outcome not in OUTCOMES:
        raise ValueError("Invalid audit outcome")

    if stream == STREAM_BALLOT and (
        actor_id is not None or source_ip is not None
    ):
        raise ValueError(
            "Ballot stream events must not identify the actor or source"
        )

    if actor_id is not None and (
        not isinstance(actor_id, str)
        or not actor_id
        or len(actor_id) > MAX_ACTOR_ID_LENGTH
    ):
        raise ValueError("Invalid audit actor ID")

    if source_ip is not None:
        if not isinstance(source_ip, str):
            raise ValueError("Invalid audit source IP")

        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            raise ValueError("Invalid audit source IP") from None
