"""SR-09 confirmation randomness, format and domain separation."""

import inspect

import pytest

import ballot_confirmation
from ballot_confirmation import (
    ConfirmationGenerationError,
    generate_confirmation_reference,
    is_confirmation_reference,
)
from ballot_credentials import CREDENTIAL_PATTERN


def test_confirmation_has_safe_noncredential_format():
    reference = generate_confirmation_reference()
    assert is_confirmation_reference(reference)
    assert len(reference) == 37
    assert reference.startswith("conf_")
    assert CREDENTIAL_PATTERN.fullmatch(reference) is None


def test_independent_generations_are_distinct():
    references = {generate_confirmation_reference() for _ in range(100)}
    assert len(references) == 100


def test_generator_requests_192_random_bits_without_voting_inputs(monkeypatch):
    calls = []

    def random_value(nbytes):
        calls.append(nbytes)
        return "A" * 32

    monkeypatch.setattr(ballot_confirmation.secrets, "token_urlsafe", random_value)
    assert generate_confirmation_reference() == "conf_" + "A" * 32
    assert calls == [24]
    assert not inspect.signature(generate_confirmation_reference).parameters


@pytest.mark.parametrize("value", [None, {}, b"conf_", "", "conf_short", "conf_" + "!" * 32,
                                  "conf_" + "A" * 33, "conf_" + "A" * 32 + "\n"])
def test_format_check_rejects_malformed_values(value):
    assert is_confirmation_reference(value) is False


def test_format_check_is_not_an_acceptance_verifier():
    # Any correctly shaped string passes format checks without a database lookup.
    assert is_confirmation_reference("conf_" + "B" * 32)


def test_random_source_failure_has_safe_error(monkeypatch):
    def fail(nbytes):
        raise OSError("private random source details")

    monkeypatch.setattr(ballot_confirmation.secrets, "token_urlsafe", fail)
    with pytest.raises(ConfirmationGenerationError, match="^Confirmation unavailable$"):
        generate_confirmation_reference()


def test_invalid_random_output_fails_closed(monkeypatch):
    monkeypatch.setattr(ballot_confirmation.secrets, "token_urlsafe", lambda n: "short")
    with pytest.raises(ConfirmationGenerationError):
        generate_confirmation_reference()
