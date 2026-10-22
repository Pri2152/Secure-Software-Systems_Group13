"""
SR-12: check which TLS versions a server accepts.

We want TLS 1.3 to work and TLS 1.2 to be refused, so there is no
fallback to an older version.
"""

import socket
import ssl


def handshake_version(host, port, cafile, *, minimum, maximum, timeout=5):
    """Connect and return the TLS version used. Raises if it fails."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=cafile)
    context.minimum_version = minimum
    context.maximum_version = maximum

    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            return tls.version()


def accepts(host, port, cafile, version):
    """True if a client that only speaks this version can connect."""

    try:
        handshake_version(
            host, port, cafile, minimum=version, maximum=version
        )
    except (ssl.SSLError, ConnectionError, OSError):
        return False

    return True


def check_server(host, port, cafile):
    """Return {version: accepted or not} for TLS 1.2 and 1.3."""

    return {
        "TLSv1.2": accepts(host, port, cafile, ssl.TLSVersion.TLSv1_2),
        "TLSv1.3": accepts(host, port, cafile, ssl.TLSVersion.TLSv1_3),
    }


def passes(results):
    """Pass only if TLS 1.3 works and TLS 1.2 is refused."""

    return results["TLSv1.3"] and not results["TLSv1.2"]
