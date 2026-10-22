
"""
SR-19 unit tests for scripts/load_test.py.

Statistics functions, the --insecure host check and the
command-line limits. No network connections are made.
"""

import ast
import importlib.util
import ssl
import sys
from collections import Counter
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "load_test.py"

spec = importlib.util.spec_from_file_location("load_test", SCRIPT)
load_test = importlib.util.module_from_spec(spec)
spec.loader.exec_module(load_test)


# p95 and rates

def test_p95_nearest_rank():
    values = list(range(1, 101))

    assert load_test.percentile(values, 95) == 95
    assert load_test.percentile(values, 50) == 50
    assert load_test.percentile(values, 100) == 100


def test_p95_does_not_depend_on_order():
    values = [0.5, 0.1, 0.9, 0.3, 0.7] * 4

    assert load_test.percentile(values, 95) == load_test.percentile(
        sorted(values), 95
    ) == 0.9


@pytest.mark.parametrize("values, expected", [
    ([0.2], 0.2),
    ([0.1, 0.2], 0.2),
    ([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
     19),
])
def test_p95_small_samples(values, expected):
    assert load_test.percentile(values, 95) == expected


def test_p95_of_nothing_is_none():
    assert load_test.percentile([], 95) is None


@pytest.mark.parametrize("percent", [0, -5, 101])
def test_percentile_range_is_checked(percent):
    with pytest.raises(ValueError):
        load_test.percentile([1, 2, 3], percent)


def test_rate_and_share():
    assert load_test.rate(300, 60) == 5.0
    assert load_test.rate(10, 0) == 0.0
    assert load_test.share(25, 100) == 0.25
    assert load_test.share(0, 0) == 0.0


def results_with(statuses, latencies):
    results = load_test.Results()
    results.statuses = Counter(statuses)
    results.latencies = latencies
    return results


def test_summary_fields():
    results = results_with(
        {200: 70, 429: 25, 403: 4, "error": 1},
        [0.010] * 95 + [0.500] * 5,
    )

    assert load_test.summarise(results, 10.0) == {
        "requests": 100,
        "seconds": 10.0,
        "throughput_per_second": 10.0,
        "p95_latency_ms": 10.0,
        "share_429": 0.25,
        "statuses": {"200": 70, "403": 4, "429": 25, "error": 1},
    }


def test_summary_with_no_requests():
    summary = load_test.summarise(load_test.Results(), 5.0)

    assert summary["requests"] == 0
    assert summary["p95_latency_ms"] is None
    assert summary["share_429"] == 0.0


def test_printed_summary_has_every_figure():
    summary = load_test.summarise(
        results_with({200: 3, 429: 1}, [0.01, 0.02, 0.03, 0.04]), 2.0
    )
    text = load_test.format_summary("SR-19 test", summary)

    for line in ("requests sent    4", "throughput       2.0 requests/s",
                 "p95 latency      40.0 ms", "429 share        25.0 %",
                 "status codes"):
        assert line in text


def test_results_are_thread_safe_counters():
    import threading

    results = load_test.Results()

    def worker():
        for _ in range(1000):
            results.record(200, 0.001)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results.statuses[200] == 8000
    assert len(results.latencies) == 8000


# --insecure host check

@pytest.mark.parametrize("target", [
    "https://localhost:8443",
    "https://127.0.0.1:8443",
    "https://gateway:8443",
    "https://LOCALHOST:8443",
    "https://localhost",
    "http://localhost:8080/",
])
def test_insecure_allowed_for_local_hosts(target):
    load_test.parse_target(target, insecure=True)


@pytest.mark.parametrize("target", [
    "https://example.com:8443",
    "https://10.0.0.5:8443",
    "https://172.30.0.10:8443",
    "https://localhost.example.com",
    "https://localhost.:8443",
    "https://gateway.evil.test",
    "https://[::1]:8443",
    "https://127.0.0.2:8443",
])
def test_insecure_refused_for_other_hosts(target):
    with pytest.raises(load_test.TargetError, match="--insecure"):
        load_test.parse_target(target, insecure=True)


@pytest.mark.parametrize("target", [
    "https://localhost@example.com:8443",     # userinfo trick
    "https://user:pass@localhost:8443",
    "https://localhost:8443/login",
    "https://localhost:8443?x=1",
    "ftp://localhost",
    "localhost:8443",
    "https://localhost:99999",
])
def test_malformed_or_tricky_targets_are_refused(target):
    with pytest.raises(load_test.TargetError):
        load_test.parse_target(target, insecure=True)


def test_non_local_target_refused_even_without_insecure():
    with pytest.raises(load_test.TargetError, match="local demo gateway"):
        load_test.parse_target("https://example.com", insecure=False)


def test_parse_target_ports():
    assert load_test.parse_target("https://localhost:8443") == (
        "https", "localhost", 8443)
    assert load_test.parse_target("https://localhost") == (
        "https", "localhost", 443)
    assert load_test.parse_target("http://gateway") == ("http", "gateway", 80)


def test_tls_checks_are_on_unless_insecure():
    secure = load_test.tls_context(False)
    insecure = load_test.tls_context(True)

    assert secure.verify_mode == ssl.CERT_REQUIRED and secure.check_hostname
    assert insecure.verify_mode == ssl.CERT_NONE
    assert not insecure.check_hostname


# Command line (refused before any connection is made)

def test_cli_refuses_insecure_remote_target(capsys):
    code = load_test.main(["load", "--target", "https://example.com",
                           "--insecure", "--duration", "1"])

    assert code == 2
    assert "--insecure is only allowed" in capsys.readouterr().err


@pytest.mark.parametrize("arguments", [
    ["load", "--clients", "0"],
    ["load", "--clients", "201"],
    ["load", "--duration", "601"],
    ["flood", "--duration", "10"],               # --side is required
    ["flood", "--side", "both"],
    ["flood", "--side", "terminal", "--terminal-rate", "0"],
])
def test_cli_limits(arguments):
    with pytest.raises(SystemExit) as error:
        load_test.main(arguments)

    assert error.value.code == 2


def test_defaults():
    parser = load_test.build_parser()
    load_options = parser.parse_args(["load"])
    flood_options = parser.parse_args(["flood", "--side", "attacker"])

    assert load_options.target == "https://localhost:8443"
    assert load_options.health_path == "/healthz"
    assert load_options.insecure is False
    assert flood_options.path == "/"


# The script itself

def test_uses_only_the_standard_library():
    tree = ast.parse(SCRIPT.read_text())
    imported = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module.split(".")[0])

    assert imported <= set(sys.stdlib_module_names), (
        imported - set(sys.stdlib_module_names)
    )


def test_never_creates_or_loads_certificates():
    text = SCRIPT.read_text()

    for call in ("load_cert_chain", "load_verify_locations", "cafile",
                 "certfile", "keyfile", "openssl", ".pem", ".crt"):
        assert call not in text, call


def test_script_has_sr19_docstring():
    docstring = ast.get_docstring(ast.parse(SCRIPT.read_text()))

    assert docstring.startswith("SR-19")
    assert "Security controls:" in docstring
