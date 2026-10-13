
"""
SR-01: Password and TOTP authentication tests.
"""

import pytest
import pyotp

from auth import (
    hash_password,
    verify_password,
    generate_totp_secret,
    verify_totp_code,
)


TEST_TOTP_SECRET = "JBSWY3DPEHPK3PXP"
FIXED_TIME = 1700000000


# Test 1: Password uses Argon2id
def test_password_uses_argon2id():
    password = "ExampleTestPassword2026!"

    stored_hash = hash_password(password)

    assert stored_hash.startswith("$argon2id$")
    assert stored_hash != password


# Test 2: Correct password accepted
def test_correct_password():
    password = "SecureTestPassword123!"

    stored_hash = hash_password(password)

    assert verify_password(
        stored_hash,
        password
    ) is True


# Test 3: Incorrect password rejected
def test_incorrect_password():
    stored_hash = hash_password(
        "CorrectTestPassword123!"
    )

    assert verify_password(
        stored_hash,
        "WrongTestPassword123!"
    ) is False


# Test 4: Different random password salts
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


# Test 5: Invalid stored hash rejected
def test_invalid_stored_hash():
    assert verify_password(
        "invalid-hash",
        "ExamplePassword123!"
    ) is False


# Test 6: Invalid password inputs
@pytest.mark.parametrize(
    "invalid_password",
    [None, "", 123]
)
def test_invalid_password_input(invalid_password):

    with pytest.raises(ValueError):
        hash_password(invalid_password)


# Test 7: Generate a usable TOTP secret
def test_generate_totp_secret():
    secret = generate_totp_secret()

    assert isinstance(secret, str)
    assert len(secret) >= 32

    code = pyotp.TOTP(secret).at(FIXED_TIME)

    assert verify_totp_code(
        secret,
        code,
        at_time=FIXED_TIME
    ) is True


# Test 8: Valid TOTP code accepted
def test_valid_totp_code():
    totp = pyotp.TOTP(TEST_TOTP_SECRET)

    valid_code = totp.at(FIXED_TIME)

    assert verify_totp_code(
        TEST_TOTP_SECRET,
        valid_code,
        at_time=FIXED_TIME
    ) is True


# Test 9: Incorrect TOTP rejected
def test_incorrect_totp_code():
    totp = pyotp.TOTP(TEST_TOTP_SECRET)

    valid_code = totp.at(FIXED_TIME)

    incorrect_code = str(
        (int(valid_code) + 1) % 1000000
    ).zfill(6)

    assert verify_totp_code(
        TEST_TOTP_SECRET,
        incorrect_code,
        at_time=FIXED_TIME
    ) is False


# Test 10: Expired TOTP rejected
def test_expired_totp_code():
    totp = pyotp.TOTP(TEST_TOTP_SECRET)

    old_code = totp.at(FIXED_TIME)

    # Verify 60 seconds after generation
    assert verify_totp_code(
        TEST_TOTP_SECRET,
        old_code,
        at_time=FIXED_TIME + 60
    ) is False


# Test 11: Invalid TOTP formats rejected
@pytest.mark.parametrize(
    "invalid_code",
    [
        None,
        123456,
        "12345",
        "12a456",
        "１２３４５６",
    ]
)
def test_invalid_totp_code_format(invalid_code):

    assert verify_totp_code(
        TEST_TOTP_SECRET,
        invalid_code,
        at_time=FIXED_TIME
    ) is False


# Test 12: Invalid secret rejected
def test_invalid_totp_secret():
    assert verify_totp_code(
        "%%%invalid%%%",
        "123456",
        at_time=FIXED_TIME
    ) is False
