
"""
SR-07: Trusted Nginx-to-Flask security adapter.

Local academic prototype.

The Flask backend must listen only on loopback inside
the Nginx container's private network namespace, or
trust only the gateway addresses configured in
EVP_TRUSTED_GATEWAY_NETWORKS (SR-20 compartments).

Nginx must overwrite the X-EVP-* headers using trusted
TLS and connection variables.
"""

import ipaddress
import logging
import os

from urllib.parse import unquote_to_bytes

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from mission_access import AccessDecision


logger = logging.getLogger("evp.gateway_security")


def parse_network_list(value, setting):
    """
    Parse comma-separated addresses or CIDR ranges.

    Raises ValueError for any invalid or empty entry,
    or a range that would match every address.
    """

    networks = []

    for entry in value.split(","):
        entry = entry.strip()

        try:
            network = ipaddress.ip_network(
                entry,
                strict=True
            )
        except ValueError as exc:
            raise ValueError(
                f"{setting}: invalid network entry"
            ) from exc

        if network.prefixlen == 0:
            raise ValueError(
                f"{setting}: range must not match every address"
            )

        networks.append(network)

    return tuple(networks)


def load_trusted_gateway_networks():
    """
    Return configured gateway networks, or None for
    the default loopback-only behaviour.
    """

    value = os.environ.get("EVP_TRUSTED_GATEWAY_NETWORKS")

    if value is None:
        return None

    return parse_network_list(
        value,
        "EVP_TRUSTED_GATEWAY_NETWORKS"
    )


# Read once at start-up; invalid values stop the app.
TRUSTED_GATEWAY_NETWORKS = load_trusted_gateway_networks()


def is_trusted_gateway_peer(peer):
    if TRUSTED_GATEWAY_NETWORKS is None:
        return peer.is_loopback

    return any(
        peer in network
        for network in TRUSTED_GATEWAY_NETWORKS
        if peer.version == network.version
    )


def deny(reason):
    logger.warning(
        "gateway_access_denied reason=%s",
        reason
    )

    return AccessDecision(
        allowed=False,
        reason=reason
    )


def evaluate_gateway_request(request_obj, policy):
    """
    Evaluate a request forwarded by trusted Nginx.

    The backend must not be directly reachable by clients.
    Nginx must overwrite all X-EVP-* metadata headers.
    """

    try:
        peer = ipaddress.ip_address(
            request_obj.remote_addr
        )
    except (ValueError, TypeError):
        return deny("invalid_gateway_peer")

    if not is_trusted_gateway_peer(peer):
        return deny("untrusted_gateway_peer")

    source_ip = request_obj.headers.get(
        "X-EVP-Source-IP"
    )

    verification_status = request_obj.headers.get(
        "X-EVP-Client-Verify"
    )

    encoded_certificate = request_obj.headers.get(
        "X-EVP-Client-Cert",
        ""
    )

    if verification_status not in (
        "SUCCESS",
        "NONE"
    ):
        return deny("invalid_certificate_status")

    fingerprint = None

    if verification_status == "SUCCESS":

        if (
            not isinstance(encoded_certificate, str)
            or not encoded_certificate
            or len(encoded_certificate) > 16384
        ):
            return deny("missing_verified_certificate")

        try:
            certificate_bytes = unquote_to_bytes(
                encoded_certificate
            )

            certificate = (
                x509.load_pem_x509_certificate(
                    certificate_bytes
                )
            )

            fingerprint = certificate.fingerprint(
                hashes.SHA256()
            ).hex()

        except (ValueError, TypeError):
            return deny("invalid_certificate_data")

    elif encoded_certificate:
        return deny("unexpected_certificate_data")

    return policy.evaluate(
        source_ip,
        cert_verified=(
            verification_status == "SUCCESS"
        ),
        cert_fingerprint=fingerprint
    )
