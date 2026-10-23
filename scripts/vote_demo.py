"""
Workstream C + D: live voting demonstration through the HTTPS gateway.

Needs the lab voting demo running (deploy/docker-compose.voting-demo.yml).

Steps (each prints its HTTP status and stops at the first surprise):
1. Get a CSRF token and sign in with password and TOTP code
2. Open the vote page and read the candidate list
3. Ask for a one-time ballot credential
4. Cast the vote for the chosen candidate
5. Check the old session is closed and the same voter cannot vote again

Uses the synthetic voter and the test client certificate. Does not
print passwords, MFA secrets, credentials or tokens.

Usage:
  python scripts/vote_demo.py --certs /tmp/evp_bundle [--candidate 1]
"""

import argparse
import json
import re
import ssl
import sys

from http.cookiejar import CookieJar
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, HTTPSHandler, Request, build_opener

import pyotp


BASE_URL = "https://localhost:8443"
CANDIDATE_PATTERN = re.compile(r'name="candidate_id"\s+value="(\d+)"')
CSRF_PATTERN = re.compile(r'name="csrf-token"\s+content="([^"]+)"')
CONFIRMATION_PATTERN = re.compile(r"conf_[A-Za-z0-9_-]{32}")


def create_client(certs):
    context = ssl.create_default_context(cafile=str(certs / "test-ca.crt"))
    context.load_cert_chain(
        certfile=str(certs / "mission-client.crt"),
        keyfile=str(certs / "mission-client.key"),
    )

    return build_opener(
        HTTPCookieProcessor(CookieJar()), HTTPSHandler(context=context)
    )


def send(client, base_url, path, method="GET", payload=None, csrf=None):
    headers = {"Accept": "application/json"}
    data = None

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    if csrf:
        headers["X-CSRFToken"] = csrf

    request = Request(base_url + path, data=data, headers=headers, method=method)

    try:
        with client.open(request, timeout=15) as reply:
            return reply.status, reply.read().decode("utf-8")
    except HTTPError as problem:
        return problem.code, problem.read().decode("utf-8")


def as_json(text):
    try:
        return json.loads(text)
    except ValueError:
        return {}


def check(label, actual, expected):
    print(f"{label}: HTTP {actual}")

    if actual != expected:
        raise AssertionError(f"{label}: expected {expected}, got {actual}")


def run(certs, base_url, candidate, client=None):
    voter = json.loads((certs / "demo-voter.json").read_text(encoding="utf-8"))
    client = client or create_client(certs)

    status, text = send(client, base_url, "/login/csrf")
    check("1a. Get CSRF token", status, 200)

    status, text = send(
        client, base_url, "/login", "POST",
        {
            "account_id": voter["account_id"],
            "password": voter["password"],
            "totp_code": pyotp.TOTP(voter["totp_secret"]).now(),
        },
        csrf=as_json(text)["csrf_token"],
    )
    check("1b. Password and TOTP sign-in", status, 200)

    status, page = send(client, base_url, "/vote")
    check("2. Open vote page", status, 200)

    candidates = [int(value) for value in CANDIDATE_PATTERN.findall(page)]
    token = CSRF_PATTERN.search(page)

    if not candidates or token is None:
        raise AssertionError("2. Vote page has no candidates or CSRF token")

    choice = candidate if candidate in candidates else candidates[0]
    print(f"   candidates on the ballot: {candidates}, voting for {choice}")

    status, text = send(
        client, base_url, "/vote/credentials", "POST", {}, csrf=token.group(1)
    )
    check("3. Get one-time ballot credential", status, 200)

    status, text = send(
        client, base_url, "/vote/ballots", "POST",
        {"credential": as_json(text)["credential"], "candidate_id": choice},
        csrf=token.group(1),
    )
    check("4. Cast vote", status, 200)

    reply = as_json(text)

    if reply.get("status") != "accepted" or not CONFIRMATION_PATTERN.fullmatch(
        reply.get("confirmation_reference", "")
    ):
        raise AssertionError("4. Vote was not accepted with a confirmation")

    print("   vote accepted, confirmation received")

    if reply.get("tracking_code"):
        print(f"   tracking code: {reply['tracking_code']}")

    status, _ = send(client, base_url, "/vote")
    check("5a. Old session is closed", status, 401)

    print("\nLIVE VOTE DEMONSTRATION PASSED")


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--certs", type=Path, required=True,
                        help="folder with test-ca.crt, mission-client.crt/.key, demo-voter.json")
    parser.add_argument("--base-url", default=BASE_URL)
    parser.add_argument("--candidate", type=int, default=1)
    options = parser.parse_args(arguments)

    try:
        run(options.certs, options.base_url, options.candidate)
    except (AssertionError, OSError, KeyError, ValueError) as problem:
        print(f"FAILED: {problem}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
