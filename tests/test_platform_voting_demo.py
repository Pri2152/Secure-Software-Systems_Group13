"""Lab voting demo override: only voter-access changes, and every key it
mounts is one that make_keys.py really creates."""

import importlib.util
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
OVERRIDE = ROOT / "deploy" / "docker-compose.voting-demo.yml"
CANDIDATES = ROOT / "deploy" / "demo" / "demo-candidates.json"


class _Loader(yaml.SafeLoader):
    pass


# Compose-only tag; the test only needs the list that follows it.
_Loader.add_constructor(
    "!override", lambda loader, node: loader.construct_sequence(node, deep=True)
)


def override():
    return yaml.load(OVERRIDE.read_text(encoding="utf-8"), Loader=_Loader)


def key_file_names():
    spec = importlib.util.spec_from_file_location(
        "make_keys", ROOT / "deploy" / "scripts" / "make_keys.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return {entry[4] for entry in module.KEYS}


def test_only_the_two_voter_access_replicas_change():
    assert set(override()["services"]) == {"voter-access-1", "voter-access-2"}


def test_voting_demo_is_switched_on_in_memory_only():
    for service in override()["services"].values():
        environment = service["environment"]

        assert environment["EVP_VOTING_DEMO"] == "1"
        assert environment["EVP_AUDIT_DB_URL"].startswith("sqlite:////tmp/")
        assert "EVP_BALLOT_DB_URL" not in environment


def test_every_mounted_key_is_created_by_make_keys():
    data = override()
    names = key_file_names()

    for service in data["services"].values():
        targets = [
            secret["target"] for secret in service["secrets"]
            if secret["target"].startswith("/run/secrets/evp_keys/")
            and not secret["target"].endswith("manifest.json")
        ]

        assert targets
        assert {target.rsplit("/", 1)[1] for target in targets} == names


def test_manifest_and_key_secrets_point_into_the_secrets_folder():
    for name, secret in override()["secrets"].items():
        if name == "demo_candidates":
            continue

        assert secret["file"].startswith("./secrets/keys/")


def test_file_explains_it_is_lab_only():
    text = OVERRIDE.read_text(encoding="utf-8")

    assert "Lab-only" in text and "Do not copy" in text


def test_candidate_file_has_the_exact_shape_the_demo_expects():
    data = json.loads(CANDIDATES.read_text(encoding="utf-8"))

    assert set(data) == {"candidates"}
    assert 1 <= len(data["candidates"]) <= 50

    for candidate in data["candidates"]:
        assert set(candidate) == {"name", "party", "position_in_group"}
