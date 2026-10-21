"""
SR-02: Client-certificate factor from the trusted gateway.

Security controls:
- Reuses Workstream A's SR-07 gateway adapter
  (gateway_security.evaluate_gateway_request) unchanged:
  the request must come from the trusted Nginx peer,
  X-EVP-Client-Verify must be a known status, and the
  certificate is parsed and SHA-256 fingerprinted there
- Headers sent directly by a client are never trusted:
  a request from any other peer yields no identity
- The original client source IP is validated, for the
  SR-01 rate limiter and the audit log
- No mission-country policy applies to staff; the
  capturing policy only records what the gateway
  verified

Local academic prototype.
"""

import ipaddress

from dataclasses import dataclass

from gateway_security import evaluate_gateway_request
from mission_access import AccessDecision


STAFF_GATEWAY_REASON = "staff_gateway_verified"


@dataclass(frozen=True)
class GatewayIdentity:
    source_ip: str
    cert_verified: bool
    cert_fingerprint: str | None


class _CapturingPolicy:
    """
    Stands in for A's mission policy: records the
    gateway-verified values instead of deciding access.
    """

    def __init__(self):
        self.identity = None

    def evaluate(self, source_ip, *, cert_verified=False,
                 cert_fingerprint=None):
        try:
            source = str(ipaddress.ip_address(str(source_ip).strip()))
        except ValueError:
            return AccessDecision(allowed=False, reason="invalid_source")

        self.identity = GatewayIdentity(
            source_ip=source,
            cert_verified=cert_verified is True,
            cert_fingerprint=cert_fingerprint if cert_verified else None,
        )

        return AccessDecision(allowed=True, reason=STAFF_GATEWAY_REASON)


def read_gateway_identity(request_obj) -> GatewayIdentity | None:
    """
    What the trusted gateway verified for this request,
    or None if the request did not come through it.
    """

    policy = _CapturingPolicy()

    decision = evaluate_gateway_request(request_obj, policy)

    if not decision.allowed:
        return None

    return policy.identity
