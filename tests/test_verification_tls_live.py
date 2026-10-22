"""
SR-12: test with a real server that only allows TLS 1.3.

We start a small local server (same rule as the gateway) and check that
TLS 1.2 is refused and TLS 1.3 is accepted.
"""

import datetime
import socket
import ssl
import threading

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from verification.tls_check import accepts, check_server, passes


@pytest.fixture
def tls13_server(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), False
        )
        .sign(key, hashes.SHA256())
    )
    cert_file = tmp_path / "server.crt"
    key_file = tmp_path / "server.key"
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert_file, key_file)

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(0.2)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except (socket.timeout, OSError):
                continue
            try:
                with context.wrap_socket(connection, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                connection.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield "localhost", listener.getsockname()[1], str(cert_file)
    stop.set()
    thread.join(2)
    listener.close()


def test_tls13_is_accepted(tls13_server):
    host, port, cafile = tls13_server

    assert accepts(host, port, cafile, ssl.TLSVersion.TLSv1_3)


def test_tls12_is_refused(tls13_server):
    host, port, cafile = tls13_server

    assert not accepts(host, port, cafile, ssl.TLSVersion.TLSv1_2)


def test_server_passes_the_sr12_check(tls13_server):
    results = check_server(*tls13_server)

    assert results == {"TLSv1.2": False, "TLSv1.3": True}
    assert passes(results)


def test_a_server_that_accepts_tls12_fails_the_check():
    assert not passes({"TLSv1.2": True, "TLSv1.3": True})
    assert not passes({"TLSv1.2": False, "TLSv1.3": False})
