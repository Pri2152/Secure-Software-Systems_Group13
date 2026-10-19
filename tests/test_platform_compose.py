
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

PENDING_SERVICES = ["admin-audit", "ballot", "tally", "results-consumer"]

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
        "gateway", *APP_SERVICES, *DATABASES, "backup",
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
    ["gateway", "voter-access-1", "voter-access-2", *DATABASES, "backup"],
)
def test_available_services_start_by_default(services, name):
    assert "profiles" not in services[name]


def test_profile_removal_comment_for_each_pending_service():
    text = COMPOSE_PATH.read_text(encoding="utf-8")

    for entrypoint in ("admin/wsgi.py", "ballot/wsgi.py",
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
                assert key.endswith("_FILE"), f"{name}: {key}"
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


def test_healthz_comment_present():
    text = COMPOSE_PATH.read_text(encoding="utf-8")

    assert "GET /healthz arrives with SR-19" in text


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
