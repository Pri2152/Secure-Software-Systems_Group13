"""SR-18: results are sent over mutual TLS to the receiver."""

import datetime
import ssl
import threading

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from werkzeug.serving import make_server

from results_consumer import ResultsState, create_app
from verification.export import ExportFailed, send_results
from verification.results import build_result, sign_result


ELECTION = "election-2026"


def make_ca(name):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf(ca_key, ca_cert, name, folder, *, server):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), False
        )
    # Python 3.13 checks certificates strictly, so the key ids are needed
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
        False,
    )
    cert = builder.sign(ca_key, hashes.SHA256())
    cert_file, key_file = folder / f"{name}.crt", folder / f"{name}.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return str(cert_file), str(key_file)


@pytest.fixture
def pki(tmp_path):
    """A test CA, a server and client from it, and a stranger CA + client."""
    ca_key, ca_cert = make_ca("test-ca")
    other_key, other_cert = make_ca("other-ca")

    ca_file = tmp_path / "ca.crt"
    ca_file.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    other_file = tmp_path / "other.crt"
    other_file.write_bytes(other_cert.public_bytes(serialization.Encoding.PEM))

    return {
        "ca": str(ca_file),
        "other_ca": str(other_file),
        "server": make_leaf(ca_key, ca_cert, "server", tmp_path, server=True),
        "client": make_leaf(ca_key, ca_cert, "client", tmp_path, server=False),
        "stranger": make_leaf(other_key, other_cert, "stranger", tmp_path, server=False),
    }


@pytest.fixture
def receiver(pki, ballot_crypto):
    state = ResultsState()
    app = create_app(crypto=ballot_crypto, election_id=ELECTION, state=state)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED      # client must show a certificate
    context.load_verify_locations(cafile=pki["ca"])
    context.load_cert_chain(*pki["server"])

    server = make_server("localhost", 0, app, ssl_context=context, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"https://localhost:{server.server_port}/results", state

    server.shutdown()
    thread.join(2)


def package(crypto, version=1):
    return sign_result(crypto, build_result(ELECTION, version, {"Melbourne": {7: 2}}))


def test_signed_result_is_delivered(receiver, pki, ballot_crypto):
    url, state = receiver
    certfile, keyfile = pki["client"]

    status, body = send_results(
        package(ballot_crypto), url, cafile=pki["ca"], certfile=certfile, keyfile=keyfile
    )

    assert (status, body["status"]) == (200, "accepted")
    assert state.last_version == 1


def test_receiver_still_rejects_a_forged_result(receiver, pki, ballot_crypto):
    url, state = receiver
    certfile, keyfile = pki["client"]
    forged = package(ballot_crypto)
    forged["result"]["divisions"]["Melbourne"]["7"] = 999

    status, _ = send_results(
        forged, url, cafile=pki["ca"], certfile=certfile, keyfile=keyfile
    )

    assert status == 400
    assert state.accepted == []


def test_client_from_unknown_ca_is_refused(receiver, pki, ballot_crypto):
    url, state = receiver
    certfile, keyfile = pki["stranger"]

    with pytest.raises(ExportFailed):
        send_results(
            package(ballot_crypto), url,
            cafile=pki["ca"], certfile=certfile, keyfile=keyfile,
        )

    assert state.accepted == []


def test_receiver_with_untrusted_certificate_is_refused(receiver, pki, ballot_crypto):
    url, state = receiver
    certfile, keyfile = pki["client"]

    with pytest.raises(ExportFailed):
        send_results(
            package(ballot_crypto), url,
            cafile=pki["other_ca"], certfile=certfile, keyfile=keyfile,
        )

    assert state.accepted == []


def test_no_client_certificate_means_no_connection(receiver, pki):
    url, state = receiver
    context = ssl.create_default_context(cafile=pki["ca"])

    import urllib.request

    with pytest.raises((OSError, ssl.SSLError)):
        urllib.request.urlopen(url, data=b"{}", context=context, timeout=5).read()

    assert state.accepted == []


def test_plain_http_is_not_allowed(pki, ballot_crypto):
    certfile, keyfile = pki["client"]

    with pytest.raises(ExportFailed):
        send_results(
            package(ballot_crypto), "http://localhost:9/results",
            cafile=pki["ca"], certfile=certfile, keyfile=keyfile,
        )
