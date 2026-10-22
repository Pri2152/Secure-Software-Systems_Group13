
"""
SR-20 static tests for deploy/docker-compose.yml.

Checks compartment and database isolation, internal
networks, file-based secrets, pinned images, restart
and health-check policy, and that the gateway uses
Workstream A's TLS files unchanged and read-only.
"""

import re
from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
DEPLOY_DIR = REPO_ROOT / "deploy"
COMPOSE_PATH = DEPLOY_DIR / "docker-compose.yml"

APP_SERVICES = [
    "voter-access-1",
    "voter-access-2",
    "admin-audit",
    "ballot",
    "tally",
    "results-consumer",
]

PENDING_SERVICES = ["ballot", "tally", "results-consumer"]

DATABASES = {
    "db-identity": "identity_net",
    "db-ballot": "ballot_net",
    "db-audit": "audit_net",
}


@pytest.fixture(scope="module")
def compose():
    # safe_load resolves the "<<" merge keys used for shared settings.
    return yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def services(compose):
    return compose["services"]


def networks_of(service):
    networks = service.get("networks", [])

    return set(networks if isinstance(networks, list) else networks)


# Services and images

def test_expected_services(services):
    assert set(services) == {
        "gateway", *APP_SERVICES, *DATABASES, "backup", "terminal-sim",
    }


def test_gateway_image_is_pinned(services):
    assert re.fullmatch(
        r"nginx:\d+\.\d+\.\d+-alpine", services["gateway"]["image"]
    )


@pytest.mark.parametrize("name", [*DATABASES, "backup"])
def test_mysql_image_is_pinned_84(services, name):
    assert re.fullmatch(r"mysql:8\.4\.\d+", services[name]["image"])


@pytest.mark.parametrize("name", APP_SERVICES)
def test_app_services_use_shared_image(services, name):
    build = services[name]["build"]

    assert build["dockerfile"] == "deploy/Dockerfile.app"
    assert (DEPLOY_DIR / build["context"] / build["dockerfile"]).is_file()


def test_no_latest_tags(services):
    for service in services.values():
        image = service.get("image", "")
        assert not image.endswith(":latest") and ":" in image


# Voter access replicas

@pytest.mark.parametrize("name", ["voter-access-1", "voter-access-2"])
def test_voter_access_runs_gateway_runtime_on_5000(services, name):
    command = services[name]["command"]

    assert command[0] == "gunicorn"
    assert "gateway_runtime:application" in command
    assert command[command.index("--bind") + 1].endswith(":5000")


def test_voter_access_has_two_identical_replicas(services):
    assert services["voter-access-1"] == services["voter-access-2"]


# Profiles

@pytest.mark.parametrize("name", PENDING_SERVICES)
def test_pending_compartments_are_in_full_profile(services, name):
    assert services[name]["profiles"] == ["full"]


@pytest.mark.parametrize(
    "name",
    ["gateway", "voter-access-1", "voter-access-2", "admin-audit",
     *DATABASES, "backup"],
)
def test_available_services_start_by_default(services, name):
    assert "profiles" not in services[name]


def test_profile_removal_comment_for_each_pending_service():
    text = COMPOSE_PATH.read_text(encoding="utf-8")

    for entrypoint in ("ballot/wsgi.py",
                       "verification/wsgi.py", "results_consumer/wsgi.py"):
        assert f"Remove the profile when {entrypoint} is merged" in text


# Networks

def test_every_network_except_edge_is_internal(compose):
    networks = compose["networks"]

    assert set(networks) == {
        "edge", "identity_net", "ballot_net", "audit_net", "results_net",
    }

    for name, settings in networks.items():
        internal = (settings or {}).get("internal") is True
        assert internal is (name != "edge"), name


def test_ballot_never_on_identity_net(services):
    assert networks_of(services["ballot"]) == {"edge", "ballot_net"}


def test_tally_only_on_ballot_and_results(services):
    assert networks_of(services["tally"]) == {"ballot_net", "results_net"}


def test_results_consumer_only_on_results_net(services):
    assert networks_of(services["results-consumer"]) == {"results_net"}


def test_identity_net_members(services):
    members = {
        name for name, service in services.items()
        if "identity_net" in networks_of(service)
    }

    assert members == {
        "voter-access-1", "voter-access-2", "admin-audit",
        "db-identity", "backup",
    }


def test_gateway_only_on_edge(services):
    assert networks_of(services["gateway"]) == {"edge"}


@pytest.mark.parametrize("name", APP_SERVICES + list(DATABASES))
def test_no_host_networking(services, name):
    assert "network_mode" not in services[name]


# Databases

@pytest.mark.parametrize("name, network", DATABASES.items())
def test_database_only_on_its_own_network(services, name, network):
    assert networks_of(services[name]) == {network}


def test_each_database_has_its_own_volume(compose, services):
    volumes = [
        services[name]["volumes"][0].split(":")[0]
        for name in DATABASES
    ]

    assert len(set(volumes)) == 3
    for volume in volumes:
        assert volume in compose["volumes"]


@pytest.mark.parametrize("name", DATABASES)
def test_database_ports_not_published(services, name):
    assert "ports" not in services[name]


# Secrets

def test_secrets_are_files_in_deploy_secrets(compose):
    for name, settings in compose["secrets"].items():
        assert set(settings) == {"file"}, name
        assert settings["file"].startswith("./secrets/"), name


def test_referenced_secrets_are_defined(compose, services):
    defined = set(compose["secrets"])

    for name, service in services.items():
        for secret in service.get("secrets", []):
            source = secret if isinstance(secret, str) else secret["source"]
            assert source in defined, f"{name}: {source}"


@pytest.mark.parametrize("name", DATABASES)
def test_database_passwords_come_from_secret_files(services, name):
    environment = services[name]["environment"]
    secret_names = set(services[name]["secrets"])

    password_file = environment["MYSQL_ROOT_PASSWORD_FILE"]

    assert password_file.startswith("/run/secrets/")
    assert password_file.rsplit("/", 1)[1] in secret_names

    for key in ("MYSQL_ROOT_PASSWORD", "MYSQL_PASSWORD",
                "MYSQL_ALLOW_EMPTY_PASSWORD"):
        assert key not in environment


def test_no_inline_secret_values(services):
    for name, service in services.items():
        for key, value in (service.get("environment") or {}).items():
            if re.search(r"PASSWORD|SECRET|TOKEN|KEY", key):
                # A file, or a folder of secret files (EVP_KEY_DIR).
                assert key.endswith(("_FILE", "_DIR")), f"{name}: {key}"
                assert str(value).startswith("/run/secrets/"), f"{name}: {key}"


def test_no_secret_looking_text_in_file():
    text = COMPOSE_PATH.read_text(encoding="utf-8")

    assert "BEGIN" not in text  # no PEM blocks
    assert not re.search(r"(?i)password[ \t]*[:=][ \t]*['\"]?\w", text)


# Restart and health checks

@pytest.mark.parametrize("name", APP_SERVICES)
def test_app_service_restart_policy(services, name):
    assert services[name]["restart"] == "unless-stopped"


@pytest.mark.parametrize("name", APP_SERVICES)
def test_app_service_healthcheck_calls_healthz(services, name):
    test = services[name]["healthcheck"]["test"]

    assert test[0] == "CMD"
    assert "http://127.0.0.1:5000/healthz" in " ".join(test)


def test_healthcheck_path_is_served_by_the_health_module():
    from platform_security.health import HEALTH_PATH

    assert HEALTH_PATH == "/healthz"


@pytest.mark.parametrize("name", ["voter-access-1", "voter-access-2"])
def test_voter_replicas_restart_and_are_health_checked(services, name):
    service = services[name]

    assert service["restart"] == "unless-stopped"
    assert service["healthcheck"]["test"][-1].endswith(
        "urlopen('http://127.0.0.1:5000/healthz', timeout=3)"
    )


def test_gateway_depends_on_both_replicas(services):
    assert set(services["gateway"]["depends_on"]) == {
        "voter-access-1", "voter-access-2",
    }


# Container hardening

@pytest.mark.parametrize("name", APP_SERVICES)
def test_app_containers_are_hardened(services, name):
    service = services[name]

    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    assert service.get("privileged") is not True
    assert "ports" not in service
    assert "user" not in service  # keeps the image's non-root user


# Gateway and TLS

def test_gateway_mounts_workstream_a_files_read_only(services):
    assert services["gateway"]["volumes"] == [
        "../nginx/conf.d:/etc/nginx/conf.d:ro",
        "../nginx/certs:/etc/nginx/certs:ro",
    ]


def test_gateway_ports_are_local_only(services):
    for mapping in services["gateway"]["ports"]:
        assert mapping.startswith("127.0.0.1:")

    assert {
        mapping.rsplit(":", 1)[1] for mapping in services["gateway"]["ports"]
    } == {"8443", "8080"}


def test_compose_does_not_create_certificates():
    text = COMPOSE_PATH.read_text(encoding="utf-8")

    assert not re.search(r"\b(openssl|certbot|mkcert)\b", text)
    assert "ssl_" not in text


# Gateway trust (SR-07 / SR-20)

def edge_subnet(compose):
    import ipaddress

    config = compose["networks"]["edge"]["ipam"]["config"][0]

    return (
        ipaddress.ip_network(config["subnet"]),
        ipaddress.ip_address(config["gateway"]),
    )


def gateway_address(services):
    import ipaddress

    return ipaddress.ip_address(
        services["gateway"]["networks"]["edge"]["ipv4_address"]
    )


def test_gateway_has_fixed_address_on_edge(compose, services):
    subnet, network_gateway = edge_subnet(compose)
    address = gateway_address(services)

    assert address in subnet
    assert address != network_gateway


@pytest.mark.parametrize("name", ["voter-access-1", "voter-access-2"])
def test_voter_access_trusts_only_the_gateway_address(compose, services, name):
    import ipaddress

    value = services[name]["environment"]["EVP_TRUSTED_GATEWAY_NETWORKS"]
    networks = [
        ipaddress.ip_network(entry.strip()) for entry in value.split(",")
    ]

    assert len(networks) == 1
    assert networks[0].num_addresses == 1
    assert networks[0].network_address == gateway_address(services)
    assert networks[0] != edge_subnet(compose)[0]


@pytest.mark.parametrize("name", ["voter-access-1", "voter-access-2"])
def test_simulated_mission_network_is_single_address(services, name):
    import ipaddress

    value = services[name]["environment"]["EVP_SIMULATED_MISSION_NETWORKS"]

    assert ipaddress.ip_network(value).num_addresses == 1


# Policy check (guide section 3.4) and proof that it works

SECRET_NAME = re.compile(r"PASSWORD|SECRET|TOKEN|CREDENTIAL|(^|_)KEY($|_)")
URL_WITH_PASSWORD = re.compile(r"://[^/\s:@]+:[^@\s]+@")
TOKEN_LIKE = re.compile(r"[A-Za-z0-9+/=_-]{16,}")


def environment_items(service):
    environment = service.get("environment") or {}

    if isinstance(environment, list):
        return [
            tuple(entry.split("=", 1)) if "=" in entry else (entry, "")
            for entry in environment
        ]

    return [(key, "" if value is None else str(value))
            for key, value in environment.items()]


def looks_like_secret(key, value):
    import ipaddress

    if SECRET_NAME.search(key.upper()) and not (
        key.upper().endswith("_FILE")
        or (key.upper().endswith("_DIR") and value.startswith("/run/secrets/"))
    ):
        return True

    if value.startswith("/run/secrets/"):
        return False

    if "BEGIN" in value or URL_WITH_PASSWORD.search(value):
        return True

    for token in TOKEN_LIKE.findall(value):
        try:
            ipaddress.ip_network(token, strict=False)
            continue
        except ValueError:
            pass

        if any(c.isdigit() for c in token) and any(c.isalpha() for c in token):
            return True

    return False


def compose_violations(data):
    """Return every SR-20 compose rule the data breaks."""

    violations = []
    services = data.get("services", {})
    networks = data.get("networks", {})

    def on(name):
        return networks_of(services.get(name, {}))

    if "identity_net" in on("ballot"):
        violations.append("ballot is on identity_net")

    for forbidden in ("identity_net", "edge"):
        if forbidden in on("tally"):
            violations.append(f"tally is on {forbidden}")

    for name, settings in networks.items():
        if name != "edge" and (settings or {}).get("internal") is not True:
            violations.append(f"network {name} is not internal")

    for name, network in DATABASES.items():
        if on(name) != {network}:
            violations.append(f"{name} is not only on {network}")

    for name, service in services.items():
        if "build" in service:
            if service.get("restart") not in ("unless-stopped", "always"):
                violations.append(f"{name} has no restart policy")
            if not service.get("healthcheck", {}).get("test"):
                violations.append(f"{name} has no healthcheck")

        image = service.get("image", "")
        tag = image.rsplit("/", 1)[-1].partition(":")[2]
        if not tag or tag == "latest":
            violations.append(f"{name} image {image!r} is not pinned")

        for key, value in environment_items(service):
            if looks_like_secret(key, value):
                violations.append(f"{name} environment {key} looks like a secret")

    return violations


def test_real_compose_has_no_violations(compose):
    assert compose_violations(compose) == []


def mutate(compose, change):
    import copy

    data = copy.deepcopy(compose)
    change(data["services"], data["networks"])
    return data


def test_check_catches_ballot_on_identity_net(compose):
    broken = mutate(
        compose,
        lambda s, n: s["ballot"]["networks"].append("identity_net"),
    )

    assert "ballot is on identity_net" in compose_violations(broken)


MUTATIONS = {
    "tally on identity_net": (
        lambda s, n: s["tally"]["networks"].append("identity_net"),
        "tally is on identity_net",
    ),
    "tally on edge": (
        lambda s, n: s["tally"]["networks"].append("edge"),
        "tally is on edge",
    ),
    "ballot_net not internal": (
        lambda s, n: n.__setitem__("ballot_net", {}),
        "network ballot_net is not internal",
    ),
    "database on a second network": (
        lambda s, n: s["db-ballot"]["networks"].append("edge"),
        "db-ballot is not only on ballot_net",
    ),
    "app service without restart": (
        lambda s, n: s["voter-access-1"].pop("restart"),
        "voter-access-1 has no restart policy",
    ),
    "app service without healthcheck": (
        lambda s, n: s["ballot"].pop("healthcheck"),
        "ballot has no healthcheck",
    ),
    "latest image tag": (
        lambda s, n: s["gateway"].__setitem__("image", "nginx:latest"),
        "gateway image 'nginx:latest' is not pinned",
    ),
    "untagged image": (
        lambda s, n: s["db-audit"].__setitem__("image", "mysql"),
        "db-audit image 'mysql' is not pinned",
    ),
    "inline database password": (
        lambda s, n: s["db-audit"]["environment"].__setitem__(
            "MYSQL_ROOT_PASSWORD", "changeme"),
        "db-audit environment MYSQL_ROOT_PASSWORD looks like a secret",
    ),
    "random-looking value": (
        lambda s, n: s["tally"].__setitem__(
            "environment", {"EVP_SETTING": "q8XvT2pLm9RzK4wN7bY3cJ6d"}),
        "tally environment EVP_SETTING looks like a secret",
    ),
    "password inside a URL": (
        lambda s, n: s["ballot"].__setitem__(
            "environment",
            ["EVP_BALLOT_DB_URL=mysql+pymysql://ballot_writer:hunter2@db-ballot/ballot_db"]),
        "ballot environment EVP_BALLOT_DB_URL looks like a secret",
    ),
}


@pytest.mark.parametrize("label", MUTATIONS)
def test_check_catches_each_broken_rule(compose, label):
    change, expected = MUTATIONS[label]

    assert expected in compose_violations(mutate(compose, change))


@pytest.mark.parametrize("key, value", [
    ("EVP_LOCAL_LAB", "1"),
    ("EVP_TRUSTED_GATEWAY_NETWORKS", "172.30.0.10/32"),
    ("MYSQL_DATABASE", "identity_db"),
    ("MYSQL_ROOT_PASSWORD_FILE", "/run/secrets/db_identity_root_password"),
])
def test_ordinary_settings_are_not_flagged(key, value):
    assert looks_like_secret(key, value) is False


# admin-audit (Workstream B), settings from admin/wsgi.py

ADMIN_KEY_FILES = {"manifest.json", "pii_key_v1", "audit_hmac_v1",
                   "audit_sign_v1"}


@pytest.fixture(scope="module")
def admin(services):
    return services["admin-audit"]


def admin_script(admin):
    command = admin["command"]

    assert command[:2] == ["sh", "-c"]
    return command[2]


def test_admin_runs_its_own_entrypoint(admin):
    script = admin_script(admin)

    assert script.strip().splitlines()[0] == "set -eu"
    assert script.strip().splitlines()[-1] == (
        "exec gunicorn --workers 1 --bind 0.0.0.0:5000 admin.wsgi:app"
    )


def test_admin_settings_match_wsgi(admin):
    assert admin["environment"] == {
        "SECRET_KEY_FILE": "/run/secrets/flask_secret_key",
        "EVP_KEY_DIR": "/run/secrets/evp_keys",
        "EVP_AUDIT_ARCHIVE": "/var/lib/evp/audit/checkpoints.jsonl",
    }

    wsgi = (REPO_ROOT / "admin" / "wsgi.py").read_text(encoding="utf-8")

    for setting in ("SECRET_KEY_FILE", "EVP_IDENTITY_DB_URL",
                    "EVP_AUDIT_DB_URL", "EVP_AUDIT_ARCHIVE", "EVP_KEY_DIR"):
        assert setting in wsgi


def test_admin_database_urls_are_built_from_secret_files(admin):
    script = admin_script(admin)

    assert 'identity_pw="$$(cat /run/secrets/admin_db_password)"' in script
    assert 'audit_pw="$$(cat /run/secrets/audit_db_password)"' in script
    assert (
        'export EVP_IDENTITY_DB_URL="mysql+pymysql://admin_identity:'
        '$${identity_pw}@db-identity:3306/identity_db"' in script
    )
    assert (
        'export EVP_AUDIT_DB_URL="mysql+pymysql://audit_writer:'
        '$${audit_pw}@db-audit:3306/audit_db"' in script
    )
    assert "unset identity_pw audit_pw" in script

    for key in ("EVP_IDENTITY_DB_URL", "EVP_AUDIT_DB_URL"):
        assert key not in admin["environment"]


def test_admin_never_uses_a_root_database_account(admin):
    script = admin_script(admin)

    assert "root" not in script
    assert "db_identity_root_password" not in str(admin["secrets"])
    assert "db_audit_root_password" not in str(admin["secrets"])


def test_admin_mounts_only_its_own_keys(admin, compose):
    targets = {}

    for secret in admin["secrets"]:
        if isinstance(secret, dict):
            targets[secret["target"]] = secret["source"]

    key_dir = admin["environment"]["EVP_KEY_DIR"]

    assert {
        target.rsplit("/", 1)[1] for target in targets
    } == ADMIN_KEY_FILES
    assert all(target.startswith(key_dir + "/") for target in targets)
    assert (
        compose["secrets"][targets[f"{key_dir}/manifest.json"]]["file"]
        == "./secrets/keys/manifest-admin-audit.json"
    )

    text = str(admin["secrets"])
    for other in ("ballot_sign", "results_sign", "election_seal"):
        assert other not in text


def test_admin_plain_secrets(admin):
    plain = {secret for secret in admin["secrets"] if isinstance(secret, str)}

    assert plain == {"flask_secret_key", "admin_db_password",
                     "audit_db_password"}


def test_admin_archive_has_its_own_named_volume(admin, compose, services):
    assert admin["volumes"] == ["audit_archive:/var/lib/evp/audit"]
    assert "audit_archive" in compose["volumes"]
    assert admin["environment"]["EVP_AUDIT_ARCHIVE"].startswith(
        "/var/lib/evp/audit/"
    )

    for name, service in services.items():
        if name != "admin-audit":
            assert "audit_archive" not in str(service.get("volumes", [])), name


def test_admin_waits_for_healthy_databases(admin):
    assert admin["depends_on"] == {
        "db-identity": {"condition": "service_healthy"},
        "db-audit": {"condition": "service_healthy"},
    }


def test_admin_networks(admin):
    assert networks_of(admin) == {"edge", "identity_net", "audit_net"}


# terminal-sim (SR-19 flood drill)

def test_terminal_sim_only_in_drill_profile(services):
    assert services["terminal-sim"]["profiles"] == ["drill"]


def test_terminal_sim_has_the_registered_terminal_address(services):
    nginx = (REPO_ROOT / "nginx" / "conf.d" / "evp.conf").read_text()
    address = services["terminal-sim"]["networks"]["edge"]["ipv4_address"]

    assert f"    {address}/32 1;" in nginx
    assert set(services["terminal-sim"]["networks"]) == {"edge"}


def test_terminal_sim_runs_terminal_side_of_flood(services):
    command = services["terminal-sim"]["command"]

    assert command[:4] == ["python", "/opt/evp/load_test.py", "flood",
                           "--side"]
    assert command[4] == "terminal"
    assert "https://gateway:8443" in command
    assert services["terminal-sim"]["volumes"] == [
        "../scripts/load_test.py:/opt/evp/load_test.py:ro"
    ]


def test_terminal_sim_is_hardened_and_holds_no_secrets(services):
    service = services["terminal-sim"]

    assert service["image"] == "python:3.11.17-slim"
    assert service["user"] == "65534:65534"
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    assert "secrets" not in service and "ports" not in service
