"""
SR-17: Secure logger sensitive-data filter.

Security controls:
- Recursive, case-insensitive redaction of any key
  whose name contains a sensitive word (password,
  TOTP, token, CSRF, session, cookie, secret, key,
  ballot preferences, envelopes, ciphertext)
- Over-redaction is preferred to leaking: matching
  is by substring, so "session_id" and "api_key"
  are redacted too
- Only JSON-safe types are kept; long strings are
  cut, nesting depth and list length are capped,
  and the whole details object has a size cap

Local academic prototype.
"""

import json
import math


REDACTED = "[REDACTED]"
UNSUPPORTED = "[UNSUPPORTED]"
DEPTH_LIMIT = "[DEPTH-LIMIT]"

SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "totp",
    "otp",
    "token",
    "csrf",
    "session",
    "cookie",
    "secret",
    "key",
    "preference",
    "ballot",
    "envelope",
    "ciphertext",
    "authorization",
    "credential",
)

MAX_DEPTH = 4
MAX_STRING_LENGTH = 256
MAX_LIST_ITEMS = 50
MAX_DETAILS_BYTES = 2048

TRUNCATED_DETAILS = {"details_truncated": True}


def is_sensitive_key(key: str) -> bool:
    folded = key.casefold()

    return any(part in folded for part in SENSITIVE_KEY_PARTS)


def _clean(value, depth: int):
    if value is None or isinstance(value, (bool, int)):
        return value

    if isinstance(value, float):
        return value if math.isfinite(value) else UNSUPPORTED

    if isinstance(value, str):
        return value[:MAX_STRING_LENGTH]

    if depth >= MAX_DEPTH:
        return DEPTH_LIMIT

    if isinstance(value, dict):
        return {
            str(key)[:MAX_STRING_LENGTH]: (
                REDACTED
                if is_sensitive_key(str(key))
                else _clean(item, depth + 1)
            )
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [
            _clean(item, depth + 1)
            for item in value[:MAX_LIST_ITEMS]
        ]

    return UNSUPPORTED


def sanitize_details(details) -> dict:
    """
    Return a filtered copy of details that is safe to
    store. Oversized details become a marker object.
    """

    if details is None:
        return {}

    if not isinstance(details, dict):
        raise ValueError("Audit details must be a dictionary")

    cleaned = _clean(details, 0)

    encoded = json.dumps(
        cleaned, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")

    if len(encoded) > MAX_DETAILS_BYTES:
        return dict(TRUNCATED_DETAILS)

    return cleaned
