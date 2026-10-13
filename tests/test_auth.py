
"""
SR-01: Security tests for password authentication.
"""

import pytest

from auth import hash_password, verify_password


# Test 1: Password uses Argon2id
def test_password_uses_argon2id():
    password = "ExampleTestPassword2026!"

    stored_hash = hash_password(password)

    assert stored_hash.startswith("$argon2id$")
    assert stored_hash != password


# Test 2: Correct password is accepted
def test_correct_password():
    password = "SecureTestPassword123!"

    stored_hash = hash_password(password)

    assert verify_password(
        stored_hash,
        password
    ) is True


# Test 3: Incorrect password is rejected
def test_incorrect_password():
    stored_hash = hash_password(
        "CorrectTestPassword123!"
    )

    assert verify_password(
        stored_hash,
        "WrongTestPassword123!"
    ) is False


# Test 4: Each hash uses a different random salt
def test_random_password_salts():
    password = "SamePasswordForTesting123!"

    first_hash = hash_password(password)
    second_hash = hash_password(password)

    assert first_hash != second_hash

    assert verify_password(
        first_hash,
        password
    ) is True

    assert verify_password(
        second_hash,
        password
    ) is True


# Test 5: Malformed stored hash is rejected
def test_invalid_stored_hash():
    assert verify_password(
        "invalid-hash",
        "ExamplePassword123!"
    ) is False


# Test 6: Reject invalid password inputs
@pytest.mark.parametrize(
    "invalid_password",
    [None, "", 123]
)
def test_invalid_password_input(invalid_password):

    with pytest.raises(ValueError):
        hash_password(invalid_password)
