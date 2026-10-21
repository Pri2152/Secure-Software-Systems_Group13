"""SR-09 ephemeral, non-preference confirmation references."""

import re
import secrets


CONFIRMATION_RANDOM_BYTES = 24
CONFIRMATION_PATTERN = re.compile(r"conf_[A-Za-z0-9_-]{32}")


class ConfirmationGenerationError(Exception):
    """No safe confirmation could be generated."""


def is_confirmation_reference(value):
    """Check format only; this does not verify that any vote was accepted."""
    return (
        isinstance(value, str)
        and CONFIRMATION_PATTERN.fullmatch(value) is not None
    )


def generate_confirmation_reference():
    """Generate independent randomness without identity, ballot or choice input."""
    try:
        reference = "conf_" + secrets.token_urlsafe(CONFIRMATION_RANDOM_BYTES)
    except OSError:
        raise ConfirmationGenerationError("Confirmation unavailable") from None
    if not is_confirmation_reference(reference):
        raise ConfirmationGenerationError("Confirmation unavailable")
    return reference
