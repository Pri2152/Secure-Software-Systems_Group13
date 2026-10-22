"""SR-18 / SR-20: results-consumer entrypoint starts only when configured."""

import importlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import crypto_agility
from crypto_agility.errors import CryptoNotConfigured
from results_consumer import wsgi
from verification.results import build_result, sign_result


ELECTION = "election-2026"


def public_only_key_dir(tmp_path):
    """A key folder with only the public results key."""

    private = ed25519.Ed25519PrivateKey.generate()
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    (tmp_path / "results_public_v1").write_bytes(public_pem)
    (tmp_path / "manifest.json").write_text(json.dumps({"keys": [{
        "kid": "results.ed25519.v1",
        "purpose": "results",
        "family": "sign",
        "alg": "ed25519",
        "file": "results_public_v1",
        "current": True,
    }]}))

    return private


def test_importing_the_module_needs_no_secrets():
    importlib.reload(wsgi)

    assert wsgi.ENV_ELECTION_ID == "EVP_ELECTION_ID"


def test_no_election_id_means_no_app(tmp_path):
    with pytest.raises(wsgi.ReceiverNotConfigured):
        wsgi.create_app({"EVP_KEY_DIR": str(tmp_path)})


def test_no_keys_means_no_app():
    with pytest.raises(CryptoNotConfigured):
        wsgi.create_app({"EVP_ELECTION_ID": ELECTION})


def test_app_with_only_public_key_has_one_route(tmp_path):
    public_only_key_dir(tmp_path)

    app = wsgi.create_app(
        {"EVP_ELECTION_ID": ELECTION, "EVP_KEY_DIR": str(tmp_path)}
    )
    routes = {rule.rule for rule in app.url_map.iter_rules()}

    assert routes == {"/results", "/static/<path:filename>"}


def test_public_only_receiver_rejects_unsigned_result(tmp_path):
    public_only_key_dir(tmp_path)

    app = wsgi.create_app(
        {"EVP_ELECTION_ID": ELECTION, "EVP_KEY_DIR": str(tmp_path)}
    )

    # signed by a different (dev) key, so the receiver must refuse it
    other = crypto_agility.build_service(dev_keys=True)
    package = sign_result(other, build_result(ELECTION, 1, {"A": {1: 1}}))

    assert app.test_client().post("/results", json=package).status_code == 400
