"""
SR-19: Scaled load and flood test for the local gateway.

Modes:
  load    N concurrent clients for S seconds, each alternating
          GET /healthz and the login flow (GET /login/csrf, then
          POST /login with a synthetic account and a wrong password)
  flood   --side attacker: one client sending as fast as possible
          --side terminal: one client sending normal, paced requests;
          run it from the registered terminal address (the
          terminal-sim Compose service, profile "drill") while the
          attacker runs, to show terminals are not blocked

Each run prints requests sent, throughput, p95 latency, the share
of 429 (rate limited) responses and a count per status code.

Security controls:
- Python standard library only; no certificates are created or
  loaded (the default trust store is used unless --insecure)
- --insecure (skip certificate checks, for Workstream A's
  self-signed test certificate) is refused unless the target host
  is localhost, 127.0.0.1 or the Compose gateway service
- Only those local hosts can be targeted at all, so this cannot be
  pointed at someone else's server; clients and duration are capped
- Synthetic login data only; no real account or secret is used

Local academic prototype.
"""

import argparse
import http.client
import json
import math
import ssl
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from urllib.parse import urlsplit


DEFAULT_TARGET = "https://localhost:8443"
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "gateway"})

MAX_CLIENTS = 200
MAX_DURATION_SECONDS = 600
REQUEST_TIMEOUT_SECONDS = 10

LOGIN_ACCOUNT = "load-test-synthetic"
LOGIN_PASSWORD = "not-a-real-password"


class TargetError(ValueError):
    pass


# Target checks

def parse_target(url, insecure=False):
    """
    Return (scheme, host, port) for a local target. Refuses any
    other host, and --insecure unless the host is local.
    """

    parts = urlsplit(url)

    if parts.scheme not in ("http", "https"):
        raise TargetError("Target must start with http:// or https://")

    if parts.username or parts.password or parts.query or parts.fragment:
        raise TargetError("Target must be a plain scheme://host:port URL")

    if parts.path not in ("", "/"):
        raise TargetError("Target must not include a path")

    host = parts.hostname or ""

    if host not in LOCAL_HOSTS:
        if insecure:
            raise TargetError(
                "--insecure is only allowed for localhost, 127.0.0.1 "
                "or the Compose gateway service"
            )
        raise TargetError(
            "Only the local demo gateway (localhost, 127.0.0.1 or "
            "gateway) can be targeted"
        )

    try:
        port = parts.port
    except ValueError:
        raise TargetError("Invalid port") from None

    port = port or (443 if parts.scheme == "https" else 80)

    return parts.scheme, host, port


def tls_context(insecure):
    context = ssl.create_default_context()

    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    return context


# Statistics

def percentile(values, percent):
    """Nearest-rank percentile; None for no values."""

    if not values:
        return None

    if not 0 < percent <= 100:
        raise ValueError("percent must be in (0, 100]")

    ordered = sorted(values)
    rank = math.ceil(percent / 100 * len(ordered))

    return ordered[rank - 1]


def rate(count, seconds):
    return count / seconds if seconds > 0 else 0.0


def share(part, total):
    return part / total if total else 0.0


@dataclass
class Results:
    statuses: Counter = field(default_factory=Counter)
    latencies: list = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, status, latency):
        with self.lock:
            self.statuses[status] += 1
            self.latencies.append(latency)


def summarise(results, elapsed):
    total = sum(results.statuses.values())

    return {
        "requests": total,
        "seconds": round(elapsed, 2),
        "throughput_per_second": round(rate(total, elapsed), 1),
        "p95_latency_ms": (
            None if not results.latencies
            else round(percentile(results.latencies, 95) * 1000, 1)
        ),
        "share_429": round(share(results.statuses[429], total), 4),
        "statuses": {str(key): value for key, value
                     in sorted(results.statuses.items(), key=str)},
    }


def format_summary(title, summary):
    p95 = summary["p95_latency_ms"]

    return "\n".join([
        title,
        f"  requests sent    {summary['requests']}",
        f"  duration         {summary['seconds']} s",
        f"  throughput       {summary['throughput_per_second']} requests/s",
        f"  p95 latency      {'n/a' if p95 is None else f'{p95} ms'}",
        f"  429 share        {summary['share_429'] * 100:.1f} %",
        f"  status codes     {summary['statuses']}",
    ])


# HTTP

class Client:
    """One keep-alive connection with its own cookies."""

    def __init__(self, scheme, host, port, insecure):
        self.scheme, self.host, self.port = scheme, host, port
        self.insecure = insecure
        self.cookies = SimpleCookie()
        self.connection = None

    def _connect(self):
        if self.scheme == "https":
            return http.client.HTTPSConnection(
                self.host, self.port, timeout=REQUEST_TIMEOUT_SECONDS,
                context=tls_context(self.insecure),
            )
        return http.client.HTTPConnection(
            self.host, self.port, timeout=REQUEST_TIMEOUT_SECONDS
        )

    def request(self, results, method, path, body=None, headers=None):
        headers = dict(headers or {})
        cookie = "; ".join(f"{k}={m.value}" for k, m in self.cookies.items())
        if cookie:
            headers["Cookie"] = cookie

        started = time.perf_counter()

        try:
            if self.connection is None:
                self.connection = self._connect()

            self.connection.request(method, path, body=body, headers=headers)
            response = self.connection.getresponse()
            data = response.read()
            status = response.status

            for value in response.headers.get_all("Set-Cookie") or []:
                self.cookies.load(value)

        except (OSError, http.client.HTTPException):
            self.close()
            data, status = b"", "error"

        results.record(status, time.perf_counter() - started)

        return status, data

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None


def login_flow(client, results, base_url):
    status, data = client.request(results, "GET", "/login/csrf")

    if status != 200:
        return

    try:
        token = json.loads(data)["csrf_token"]
    except (ValueError, KeyError, TypeError):
        return

    client.request(
        results, "POST", "/login",
        body=json.dumps({
            "account_id": LOGIN_ACCOUNT,
            "password": LOGIN_PASSWORD,
            "totp_code": "000000",
        }),
        headers={
            "Content-Type": "application/json",
            "X-CSRFToken": token,
            "Referer": f"{base_url}/login/csrf",
        },
    )


def run_threads(count, worker):
    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(count)]

    started = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    return time.perf_counter() - started


def load(target, clients, duration, insecure, health_path):
    scheme, host, port = parse_target(target, insecure)
    base_url = target.rstrip("/")
    results = Results()
    deadline = time.monotonic() + duration

    def worker():
        client = Client(scheme, host, port, insecure)
        while time.monotonic() < deadline:
            client.request(results, "GET", health_path)
            login_flow(client, results, base_url)
        client.close()

    elapsed = run_threads(clients, worker)

    return summarise(results, elapsed)


def flood(target, side, duration, insecure, path, terminal_rate):
    scheme, host, port = parse_target(target, insecure)
    results = Results()
    deadline = time.monotonic() + duration
    pause = 0.0 if side == "attacker" else 1.0 / terminal_rate

    def worker():
        client = Client(scheme, host, port, insecure)
        while time.monotonic() < deadline:
            client.request(results, "GET", path)
            if pause:
                time.sleep(pause)
        client.close()

    elapsed = run_threads(1, worker)

    return summarise(results, elapsed)


# Command line

def positive_int(limit):
    def parse(value):
        number = int(value)
        if not 1 <= number <= limit:
            raise argparse.ArgumentTypeError(f"must be between 1 and {limit}")
        return number
    return parse


def build_parser():
    parser = argparse.ArgumentParser(description="SR-19 load and flood test")
    modes = parser.add_subparsers(dest="mode", required=True)

    def common(sub):
        sub.add_argument("--target", default=DEFAULT_TARGET)
        sub.add_argument("--insecure", action="store_true",
                         help="skip certificate checks (local hosts only)")
        sub.add_argument("--duration", type=positive_int(MAX_DURATION_SECONDS),
                         default=30, help="seconds")
        sub.add_argument("--json", action="store_true",
                         help="print the summary as JSON")

    load_mode = modes.add_parser("load", help="concurrent clients")
    common(load_mode)
    load_mode.add_argument("--clients", type=positive_int(MAX_CLIENTS),
                           default=20)
    load_mode.add_argument("--health-path", default="/healthz")

    flood_mode = modes.add_parser("flood", help="attacker or terminal side")
    common(flood_mode)
    flood_mode.add_argument("--side", choices=("attacker", "terminal"),
                            required=True)
    flood_mode.add_argument("--path", default="/")
    flood_mode.add_argument("--terminal-rate", type=positive_int(50),
                            default=2, help="terminal requests per second")

    return parser


def main(arguments=None):
    options = build_parser().parse_args(arguments)

    try:
        parse_target(options.target, options.insecure)

        if options.mode == "load":
            title = (f"SR-19 load: {options.clients} clients, "
                     f"{options.duration} s, {options.target}")
            summary = load(options.target, options.clients, options.duration,
                           options.insecure, options.health_path)
        else:
            title = (f"SR-19 flood ({options.side} side): "
                     f"{options.duration} s, {options.target}{options.path}")
            summary = flood(options.target, options.side, options.duration,
                            options.insecure, options.path,
                            options.terminal_rate)

    except TargetError as error:
        print(error, file=sys.stderr)
        return 2

    print(json.dumps(summary) if options.json
          else format_summary(title, summary))

    return 0


if __name__ == "__main__":
    sys.exit(main())
