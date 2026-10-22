
"""
SR-19 / SR-08 static tests for nginx/conf.d/evp.conf.

A small parser turns the file into nested blocks of
directives, so each check looks at the right context
(http level, server, or location), not just at text.
No Nginx binary is needed.
"""

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = REPO_ROOT / "nginx" / "conf.d" / "evp.conf"

TERMINAL_SIM_ADDRESS = "172.30.0.20/32"

BINSA_PROXY_LINES = [
    "proxy_set_header X-EVP-Source-IP $remote_addr;",
    "proxy_set_header X-EVP-Client-Verify $ssl_client_verify;",
    "proxy_set_header X-EVP-Client-Cert $ssl_client_escaped_cert;",
    'proxy_set_header X-Forwarded-For "";',
]

TLS_LINES = [
    "listen 8443 ssl;",
    "ssl_certificate /etc/nginx/certs/server.crt;",
    "ssl_certificate_key /etc/nginx/certs/server.key;",
    "ssl_protocols TLSv1.3;",  # SR-12: TLS 1.3 only
    "ssl_session_tickets off;",
    "ssl_client_certificate /etc/nginx/certs/test-ca.crt;",
    "ssl_verify_client optional;",
    "ssl_verify_depth 1;",
]


# Parser

TOKEN = re.compile(r"""'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|[{};]|[^\s{};'"]+""")


def tokens(text):
    # The file has no "#" inside quoted values, so comments end lines.
    return TOKEN.findall(re.sub(r"#[^\n]*", "", text))


def parse(items):
    """[(name, args, children or None)] for one block."""

    block, current = [], []

    while items:
        token = items.pop(0)

        if token == ";":
            block.append((current[0], current[1:], None))
            current = []
        elif token == "{":
            children = parse(items)
            block.append((current[0], current[1:], children))
            current = []
        elif token == "}":
            assert not current, f"Unterminated directive {current}"
            return block
        else:
            current.append(token)

    assert not current, f"Unterminated directive {current}"
    return block


@pytest.fixture(scope="module")
def text():
    return CONFIG_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def http(text):
    return parse(tokens(text))


def directives(block, name):
    return [(args, children) for n, args, children in block if n == name]


def args_of(block, name):
    return [args for args, _ in directives(block, name)]


def server(http, port):
    for args, children in directives(http, "server"):
        if any(listen[0] == port for listen in args_of(children, "listen")):
            return children
    raise AssertionError(f"No server on {port}")


@pytest.fixture(scope="module")
def https(http):
    return server(http, "8443")


def location(block, *selector):
    for args, children in directives(block, "location"):
        if tuple(args) == selector:
            return children
    raise AssertionError(f"No location {selector}")


def zone_definitions(http):
    zones = {}

    for args in args_of(http, "limit_req_zone"):
        key = args[0]
        options = dict(arg.split("=", 1) for arg in args[1:])
        name, _, size = options["zone"].partition(":")
        zones[name] = {"key": key, "rate": options["rate"], "size": size}

    return zones


def limit_reqs(block):
    return {
        dict(arg.split("=", 1) for arg in args if "=" in arg)["zone"]: args
        for args in args_of(block, "limit_req")
    }


def per_second(rate):
    number, unit = re.fullmatch(r"(\d+)r/([sm])", rate).groups()
    return int(number) / (60 if unit == "m" else 1)


# Whole file

def test_file_parses(http):
    assert directives(http, "server")


def test_tls_lines_are_unchanged(text):
    lines = [line.strip() for line in text.splitlines()]

    for line in TLS_LINES:
        assert lines.count(line) == 1, line

    assert sum(line.startswith("ssl_") for line in lines) == len(TLS_LINES) - 1


# Geo block and maps

def test_geo_lists_registered_terminals(http):
    [(args, children)] = directives(http, "geo")

    assert args == ["$evp_registered_terminal"]
    assert children == [
        ("default", ["0"], None),
        (TERMINAL_SIM_ADDRESS, ["1"], None),
    ]


def test_terminals_are_identified_by_address_not_certificate(text, http):
    [(_, children)] = directives(http, "geo")

    assert all("ssl" not in name for name, _, _ in children)
    assert "$ssl_client" not in "".join(
        " ".join(args) for args in args_of(http, "map")
    )


def test_maps_split_public_and_terminal_keys(http):
    maps = {
        args[1]: {name: values[0] for name, values, _ in children}
        for args, children in directives(http, "map")
    }

    assert maps["$evp_public_key"] == {"0": "$binary_remote_addr", "1": '""'}
    assert maps["$evp_terminal_key"] == {"0": '""', "1": "$binary_remote_addr"}


# Zones

def test_limit_zones(http):
    zones = zone_definitions(http)

    assert set(zones) == {"evp_public", "evp_terminal", "evp_login",
                          "evp_ballot"}
    assert zones["evp_public"]["key"] == "$evp_public_key"
    assert zones["evp_terminal"]["key"] == "$evp_terminal_key"


def test_login_zone_is_five_per_minute(http):
    assert zone_definitions(http)["evp_login"]["rate"] == "5r/m"


def test_terminal_zone_is_higher_than_public(http):
    zones = zone_definitions(http)

    assert per_second(zones["evp_terminal"]["rate"]) > per_second(
        zones["evp_public"]["rate"]
    )


def test_registered_terminals_are_never_in_public_zones(http):
    # Public zones use the key that is empty for registered terminals.
    zones = zone_definitions(http)

    for name in ("evp_public", "evp_login", "evp_ballot"):
        assert zones[name]["key"] == "$evp_public_key", name

    conn = {args[1].split("=")[1].split(":")[0]: args[0]
            for args in args_of(http, "limit_conn_zone")}

    assert conn == {"evp_public_conn": "$evp_public_key",
                    "evp_terminal_conn": "$evp_terminal_key"}


# HTTPS server settings

def test_body_size_timeout_and_status(https):
    assert args_of(https, "client_max_body_size") == [["16k"]]
    assert args_of(https, "client_body_timeout") == [["10s"]]
    assert args_of(https, "limit_req_status") == [["429"]]
    assert args_of(https, "limit_conn_status") == [["429"]]


def test_connection_limit_per_address(https):
    limits = {args[0]: int(args[1]) for args in args_of(https, "limit_conn")}

    assert set(limits) == {"evp_public_conn", "evp_terminal_conn"}
    assert limits["evp_public_conn"] <= 20


# Locations

def proxied_locations(https):
    return [
        (args, children) for args, children in directives(https, "location")
        if args_of(children, "proxy_pass")
    ]


def test_login_location_uses_strict_zone(https):
    login = location(https, "=", "/login")
    zones = limit_reqs(login)

    assert set(zones) == {"evp_login", "evp_terminal"}
    assert "nodelay" in zones["evp_login"]


def test_ballot_location_is_stricter_than_public(http, https):
    ballot = location(https, "/vote")
    zones = zone_definitions(http)

    assert set(limit_reqs(ballot)) == {"evp_ballot", "evp_terminal"}
    assert [args[-1] for args in args_of(ballot, "access_log")] == [
        "evp_ballot_no_ip"
    ]
    assert per_second(zones["evp_ballot"]["rate"]) < per_second(
        zones["evp_public"]["rate"]
    )


def test_default_location_uses_public_and_terminal_zones(https):
    assert set(limit_reqs(location(https, "/"))) == {
        "evp_public", "evp_terminal"
    }


def test_every_proxied_location_is_rate_limited(https):
    for args, children in proxied_locations(https):
        assert limit_reqs(children), args


# Ballot log without client IP (SR-08)

def test_ballot_uses_log_format_without_client_ip(http, https):
    formats = {args[0]: " ".join(args[1:]) for args in args_of(http, "log_format")}

    assert "evp_ballot_no_ip" in formats

    log_format = formats["evp_ballot_no_ip"]

    for field in ("$remote_addr", "$binary_remote_addr", "$http_x_forwarded_for",
                  "$proxy_add_x_forwarded_for", "$realip_remote_addr",
                  "$http_user_agent", "$remote_user", "$ssl_client"):
        assert field not in log_format, field

    assert args_of(location(https, "/vote"), "access_log") == [
        ["/var/log/nginx/evp_ballot_access.log", "evp_ballot_no_ip"]
    ]


# Binsa's proxy headers

def test_proxy_headers_kept_exactly(text):
    for line in BINSA_PROXY_LINES:
        assert f"        {line}\n" in text


def test_every_proxied_location_overwrites_evp_headers(https):
    for args, children in proxied_locations(https):
        headers = [" ".join(header) for header in
                   args_of(children, "proxy_set_header")]

        assert headers == [
            "Host $host",
            "X-EVP-Source-IP $remote_addr",
            "X-EVP-Client-Verify $ssl_client_verify",
            "X-EVP-Client-Cert $ssl_client_escaped_cert",
            'X-Forwarded-For ""',
        ], args
        assert args_of(children, "proxy_pass") == [["http://evp_app"]]


# Terminal address matches Compose (when terminal-sim arrives)

def test_terminal_address_is_on_the_edge_subnet():
    import ipaddress

    import yaml

    compose = yaml.safe_load(
        (REPO_ROOT / "deploy" / "docker-compose.yml").read_text()
    )
    subnet = ipaddress.ip_network(
        compose["networks"]["edge"]["ipam"]["config"][0]["subnet"]
    )
    terminal = ipaddress.ip_network(TERMINAL_SIM_ADDRESS)

    assert terminal.subnet_of(subnet)

    gateway = compose["services"]["gateway"]["networks"]["edge"]["ipv4_address"]
    assert ipaddress.ip_address(gateway) not in terminal

    if "terminal-sim" in compose["services"]:
        address = compose["services"]["terminal-sim"]["networks"]["edge"][
            "ipv4_address"
        ]
        assert ipaddress.ip_network(f"{address}/32") == terminal


# Upstream (SR-19 failover)

def test_upstream_has_two_voter_access_servers(http):
    [(args, children)] = directives(http, "upstream")

    assert args == ["evp_app"]
    assert args_of(children, "server") == [
        ["voter-access-1:5000", "max_fails=3", "fail_timeout=10s"],
        ["voter-access-2:5000", "max_fails=3", "fail_timeout=10s"],
    ]


def test_upstream_keeps_clients_on_one_replica(http):
    [(_, children)] = directives(http, "upstream")

    # Sessions are per replica (deploy/README.md, Limitations).
    assert args_of(children, "ip_hash") == [[]]


def test_upstream_names_are_compose_services():
    import yaml

    services = yaml.safe_load(
        (REPO_ROOT / "deploy" / "docker-compose.yml").read_text()
    )["services"]

    for name in ("voter-access-1", "voter-access-2"):
        assert "edge" in services[name]["networks"]


def test_nothing_proxies_to_loopback(text):
    assert "127.0.0.1:5000" not in text


def test_healthz_is_not_routed_by_the_gateway(https):
    assert location(https, "=", "/healthz") == [("return", ["404"], None)]
