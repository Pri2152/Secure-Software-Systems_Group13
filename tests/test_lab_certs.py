"""
SR-07: Tests for deploy/scripts/make_lab_certs.py.

Generates the lab certificates and demo voter into a temporary folder
and checks the CA, the chain, that Python's ssl module loads them,
that MissionAccessPolicy accepts the fingerprint, and that existing
files are kept unless --force is given.
"""

import importlib.util
import json
import os
import ssl
import sys

from pathlib import Path

import pytest

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from mission_access import MissionAccessPolicy


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "deploy" / "scripts" / "make_lab_certs.py"


@pytest.fixture(scope="module")
def lab():
    spec = importlib.util.spec_from_file_location("make_lab_certs", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def generated(lab, tmp_path):
    lines = []
    lab.make_lab_certs(tmp_path, report=lines.append)
    return tmp_path, lines


def load_cert(path):
    return x509.load_pem_x509_certificate(path.read_bytes())


def test_writes_every_expected_file(generated):
    root, _ = generated

    for relative in (
        "nginx/certs/server.crt",
        "nginx/certs/server.key",
        "nginx/certs/test-ca.crt",
        "deploy/secrets/demo-voter.json",
        "deploy/secrets/registered_fingerprints.txt",
        "deploy/secrets/ca/test-ca.crt",
        "deploy/secrets/ca/test-ca.key",
        "deploy/secrets/client/test-ca.crt",
        "deploy/secrets/client/mission-client.crt",
        "deploy/secrets/client/mission-client.key",
        "deploy/secrets/client/demo-voter.json",
    ):
        assert (root / relative).is_file(), relative


def test_ca_private_key_is_not_in_nginx_certs(generated):
    root, _ = generated

    names = sorted(path.name for path in (root / "nginx" / "certs").iterdir())
    assert names == ["server.crt", "server.key", "test-ca.crt"]

    ca_key = (root / "deploy/secrets/ca/test-ca.key").read_bytes()

    for path in (root / "nginx" / "certs").iterdir():
        assert path.read_bytes() != ca_key
        if path.name != "server.key":
            assert b"PRIVATE KEY" not in path.read_bytes()


def test_ca_has_required_extensions(generated):
    root, _ = generated
    ca = load_cert(root / "nginx" / "certs" / "test-ca.crt")

    constraints = ca.extensions.get_extension_for_class(x509.BasicConstraints)
    assert constraints.critical
    assert constraints.value.ca is True
    assert constraints.value.path_length == 0

    usage = ca.extensions.get_extension_for_class(x509.KeyUsage)
    assert usage.critical
    assert usage.value.key_cert_sign and usage.value.crl_sign
    assert not usage.value.digital_signature

    ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)


def test_server_cert_names_and_usage(generated):
    root, _ = generated
    cert = load_cert(root / "nginx" / "certs" / "server.crt")

    names = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value
    assert names.get_values_for_type(x509.DNSName) == ["localhost"]
    assert [str(ip) for ip in names.get_values_for_type(x509.IPAddress)] == [
        "127.0.0.1"
    ]

    usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert list(usage.value) == [ExtendedKeyUsageOID.SERVER_AUTH]

    key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert key_usage.digital_signature and key_usage.key_encipherment

    cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)


def test_client_cert_names_and_usage(generated):
    root, _ = generated
    cert = load_cert(root / "deploy/secrets/client/mission-client.crt")

    assert cert.subject.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME
    )[0].value == "mission-device-01"

    usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert list(usage.value) == [ExtendedKeyUsageOID.CLIENT_AUTH]

    key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert key_usage.digital_signature and not key_usage.key_encipherment

    cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)


def test_validity_is_thirty_days(generated):
    root, _ = generated

    for relative in ("nginx/certs/test-ca.crt", "nginx/certs/server.crt",
                     "deploy/secrets/client/mission-client.crt"):
        cert = load_cert(root / relative)
        lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert 29 < lifetime.days <= 30, relative


@pytest.mark.parametrize("relative", [
    "nginx/certs/server.crt",
    "deploy/secrets/client/mission-client.crt",
])
def test_leaf_verifies_against_ca(generated, relative):
    root, _ = generated
    ca = load_cert(root / "nginx" / "certs" / "test-ca.crt")
    cert = load_cert(root / relative)

    assert cert.issuer == ca.subject
    cert.verify_directly_issued_by(ca)


def test_every_ca_copy_is_the_same(generated):
    root, _ = generated

    copies = {
        (root / relative).read_bytes()
        for relative in ("nginx/certs/test-ca.crt",
                         "deploy/secrets/ca/test-ca.crt",
                         "deploy/secrets/client/test-ca.crt")
    }
    assert len(copies) == 1


def test_ssl_loads_ca_and_client_pair(generated):
    root, _ = generated
    client = root / "deploy" / "secrets" / "client"

    context = ssl.create_default_context(cafile=str(client / "test-ca.crt"))
    context.load_cert_chain(
        certfile=str(client / "mission-client.crt"),
        keyfile=str(client / "mission-client.key"),
    )

    assert context.cert_store_stats()["x509_ca"] == 1


def test_ssl_loads_server_pair(generated):
    root, _ = generated
    certs = root / "nginx" / "certs"

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile=str(certs / "server.crt"), keyfile=str(certs / "server.key")
    )


def test_mutual_tls_handshake_with_strict_checks(generated):
    # Python 3.13+ sets VERIFY_X509_STRICT by default; set it here too,
    # so the check holds on older Pythons. In memory, no sockets.
    root, _ = generated
    certs = root / "nginx" / "certs"
    client = root / "deploy" / "secrets" / "client"
    strict = getattr(ssl, "VERIFY_X509_STRICT", 0)

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certs / "server.crt", certs / "server.key")
    server_context.load_verify_locations(certs / "test-ca.crt")
    server_context.verify_mode = ssl.CERT_REQUIRED
    server_context.verify_flags |= strict

    client_context = ssl.create_default_context(
        cafile=str(client / "test-ca.crt")
    )
    client_context.load_cert_chain(
        client / "mission-client.crt", client / "mission-client.key"
    )
    client_context.verify_flags |= strict

    pipes = [ssl.MemoryBIO() for _ in range(4)]
    client_side = client_context.wrap_bio(pipes[0], pipes[1],
                                          server_hostname="localhost")
    server_side = server_context.wrap_bio(pipes[2], pipes[3],
                                          server_side=True)
    done = {client_side: False, server_side: False}

    for _ in range(20):
        for side in done:
            if not done[side]:
                try:
                    side.do_handshake()
                    done[side] = True
                except ssl.SSLWantReadError:
                    pass

        pipes[2].write(pipes[1].read())
        pipes[0].write(pipes[3].read())

        if all(done.values()):
            break

    assert all(done.values())
    assert server_side.getpeercert()["subject"][-1] == (
        ("commonName", "mission-device-01"),
    )


def test_fingerprint_is_accepted_by_mission_policy(generated, lab):
    root, _ = generated
    text = (root / "deploy/secrets/registered_fingerprints.txt").read_text(
        encoding="ascii"
    )
    lines = [line for line in text.splitlines() if line.strip()]

    assert len(lines) == 1
    assert len(lines[0]) == 64 and ":" not in lines[0]
    assert lines[0] == lines[0].lower()

    client = load_cert(root / "deploy/secrets/client/mission-client.crt")
    assert lines[0] == lab.fingerprint(client)

    policy = MissionAccessPolicy(
        mission_networks=["203.0.113.0/24"],
        registered_fingerprints=lines,
        country_lookup=lambda address: "GB",
    )
    decision = policy.evaluate(
        "203.0.113.10", cert_verified=True, cert_fingerprint=lines[0]
    )

    assert decision.allowed
    assert decision.reason == "approved_mission_connection"


def test_demo_voter_has_three_fields(generated):
    root, _ = generated

    voter = json.loads(
        (root / "deploy/secrets/demo-voter.json").read_text(encoding="utf-8")
    )
    assert set(voter) == {"account_id", "password", "totp_secret"}
    assert voter["account_id"] == "demo-voter"
    assert len(voter["password"]) >= 16
    assert len(voter["totp_secret"]) >= 16

    bundle = root / "deploy/secrets/client/demo-voter.json"
    assert json.loads(bundle.read_text(encoding="utf-8")) == voter


def test_report_names_files_only(generated):
    root, lines = generated

    voter = json.loads(
        (root / "deploy/secrets/demo-voter.json").read_text(encoding="utf-8")
    )
    output = "\n".join(lines)

    assert voter["password"] not in output
    assert voter["totp_secret"] not in output
    assert "PRIVATE KEY" not in output
    assert all(line.startswith(("Wrote ", "Kept existing ")) for line in lines)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_private_files_are_owner_only(generated):
    root, _ = generated

    for relative in ("nginx/certs/server.key",
                     "deploy/secrets/ca/test-ca.key",
                     "deploy/secrets/client/mission-client.key",
                     "deploy/secrets/demo-voter.json",
                     "deploy/secrets/client/demo-voter.json"):
        assert os.stat(root / relative).st_mode & 0o777 == 0o600, relative


def test_existing_files_are_kept_without_force(generated, lab):
    root, _ = generated
    files = sorted(path for path in root.rglob("*") if path.is_file())
    before = {path: path.read_bytes() for path in files}

    lines = []
    lab.make_lab_certs(root, report=lines.append)

    assert {path: path.read_bytes() for path in files} == before
    assert not any(line.startswith("Wrote ") for line in lines)


def test_only_missing_files_are_created(generated, lab):
    root, _ = generated
    voter = root / "deploy/secrets/demo-voter.json"
    server = root / "nginx/certs/server.crt"
    kept = voter.read_bytes()
    old_server = server.read_bytes()

    (root / "nginx/certs/server.key").unlink()
    server.unlink()
    lab.make_lab_certs(root, report=lambda line: None)

    assert voter.read_bytes() == kept
    assert server.read_bytes() != old_server

    ca = load_cert(root / "nginx/certs/test-ca.crt")
    load_cert(server).verify_directly_issued_by(ca)


def test_missing_ca_with_signed_files_is_refused(generated, lab):
    root, _ = generated
    (root / "deploy/secrets/ca/test-ca.key").unlink()
    (root / "deploy/secrets/ca/test-ca.crt").unlink()

    with pytest.raises(lab.LabCertError):
        lab.make_lab_certs(root, report=lambda line: None)

    assert not (root / "deploy/secrets/ca/test-ca.crt").exists()


def test_force_regenerates_everything(generated, lab):
    root, _ = generated
    files = sorted(path for path in root.rglob("*") if path.is_file())
    before = {path: path.read_bytes() for path in files}

    lab.make_lab_certs(root, force=True, report=lambda line: None)

    for path, old in before.items():
        assert path.read_bytes() != old, path

    ca = load_cert(root / "nginx/certs/test-ca.crt")
    load_cert(root / "nginx/certs/server.crt").verify_directly_issued_by(ca)


def test_command_line_runs(tmp_path, capsys, lab):
    assert lab.main(["--root", str(tmp_path)]) == 0

    output = capsys.readouterr().out
    assert "Wrote nginx/certs/server.crt" in output
    assert "PRIVATE KEY" not in output
