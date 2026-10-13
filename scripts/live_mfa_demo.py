
"""
Workstream A: Live HTTPS and MFA demonstration.

Tests:
SR-01 - Password and TOTP authentication
SR-05 - Voter record authorisation
SR-07 - HTTPS and registered client certificate
SR-16 - Secure session and logout

Uses synthetic credentials stored outside Git.
Does not print passwords, MFA secrets or tokens.
"""

import json
import ssl

from pathlib import Path
from http.cookiejar import CookieJar
from urllib.error import HTTPError
from urllib.request import (
    HTTPCookieProcessor,
    HTTPSHandler,
    Request,
    build_opener,
)

import pyotp


BASE_URL = "https://localhost:8443"
CERT_DIR = Path("/certs")


def create_client():
    tls_context = ssl.create_default_context(
        cafile=str(CERT_DIR / "test-ca.crt")
    )

    tls_context.load_cert_chain(
        certfile=str(CERT_DIR / "mission-client.crt"),
        keyfile=str(CERT_DIR / "mission-client.key"),
    )

    return build_opener(
        HTTPCookieProcessor(CookieJar()),
        HTTPSHandler(context=tls_context),
    )


def send_request(
    client,
    path,
    method="GET",
    payload=None,
    csrf_token=None,
):
    headers = {
        "Accept": "application/json"
    }

    body = None

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    if csrf_token is not None:
        headers["X-CSRFToken"] = csrf_token
        headers["Referer"] = BASE_URL + "/login/csrf"

    request = Request(
        BASE_URL + path,
        data=body,
        headers=headers,
        method=method,
    )

    try:
        response = client.open(
            request,
            timeout=15,
        )
    except HTTPError as error:
        response = error

    with response:
        status = response.status
        content = response.read().decode("utf-8")

    try:
        result = json.loads(content)
    except json.JSONDecodeError:
        result = {"message": content}

    return status, result


def check(label, actual, expected):
    print(f"{label}: HTTP {actual}")

    if actual != expected:
        raise AssertionError(
            f"{label}: expected {expected}, got {actual}"
        )


def main():
    voter = json.loads(
        (CERT_DIR / "demo-voter.json").read_text(
            encoding="utf-8"
        )
    )

    client = create_client()

    # Step 1: Obtain CSRF token.
    status, result = send_request(
        client,
        "/login/csrf",
    )

    check("1. Obtain CSRF token", status, 200)

    csrf_token = result["csrf_token"]

    # Step 2: Authenticate with password and TOTP.
    totp_code = pyotp.TOTP(
        voter["totp_secret"]
    ).now()

    status, result = send_request(
        client,
        "/login",
        method="POST",
        payload={
            "account_id": voter["account_id"],
            "password": voter["password"],
            "totp_code": totp_code,
        },
        csrf_token=csrf_token,
    )

    check("2. Password and TOTP login", status, 200)

    # Step 3: Access the authenticated voter's record.
    status, result = send_request(
        client,
        "/records/enrolments/701",
    )

    check("3. Access own enrolment", status, 200)

    # Step 4: Verify authenticated session.
    status, result = send_request(
        client,
        "/session-status",
    )

    check("4. Authenticated session", status, 200)

    logout_token = result["csrf_token"]

    # Step 5: Log out securely.
    status, result = send_request(
        client,
        "/logout",
        method="POST",
        csrf_token=logout_token,
    )

    check("5. Logout", status, 200)

    # Step 6: Verify record access is revoked.
    status, result = send_request(
        client,
        "/records/enrolments/701",
    )

    check("6. Access after logout denied", status, 401)

    print("\nLIVE MFA DEMONSTRATION PASSED")


if __name__ == "__main__":
    main()
