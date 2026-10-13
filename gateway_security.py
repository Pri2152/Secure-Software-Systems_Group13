
"""
SR-07: Trusted Nginx-to-Flask security adapter.

Local academic prototype.

The Flask backend must listen only on loopback inside
the Nginx container's private network namespace.

Nginx must overwrite the X-EVP-* headers using trusted
TLS and connection variables.
"""

import ipaddress
import logging

from urllib.parse import unquote_to_bytes

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from mission_access import AccessDecision


logger = logging.getLogger("evp.gateway_security")


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

    if not peer.is_loopback:
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
