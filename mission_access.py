
"""
SR-07: Diplomatic-mission access policy.

For overseas connections, access requires:
1. A configured diplomatic-mission network.
2. A registered, verified client certificate.

The calling server must obtain the source IP,
country classification and certificate verification
from trusted infrastructure, never client headers.

Prototype policy. Not yet connected to Nginx.
"""

import ipaddress
import logging
import re

from dataclasses import dataclass


logger = logging.getLogger("evp.mission_access")


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    reason: str


class MissionAccessPolicy:

    def __init__(
        self,
        mission_networks,
        registered_fingerprints,
        country_lookup
    ):
        if not callable(country_lookup):
            raise TypeError(
                "A trusted country lookup is required"
            )

        self.country_lookup = country_lookup

        self.mission_networks = tuple(
            ipaddress.ip_network(
                network,
                strict=True
            )
            for network in mission_networks
        )

        if not self.mission_networks:
            raise ValueError(
                "At least one mission network is required"
            )

        fingerprints = set()

        for fingerprint in registered_fingerprints:
            normalised = self._fingerprint(fingerprint)

            if normalised is None:
                raise ValueError(
                    "Invalid registered certificate fingerprint"
                )

            fingerprints.add(normalised)

        self.registered_fingerprints = frozenset(
            fingerprints
        )

    @staticmethod
    def _fingerprint(value):
        if not isinstance(value, str):
            return None

        normalised = value.strip().lower()

        if not re.fullmatch(r"[0-9a-f]{64}", normalised):
            return None

        return normalised

    @staticmethod
    def _deny(reason):
        # Avoid logging certificate secrets or
        # user-controlled location headers.
        logger.warning(
            "mission_access_denied reason=%s",
            reason
        )

        return AccessDecision(
            allowed=False,
            reason=reason
        )

    def evaluate(
        self,
        source_ip,
        *,
        cert_verified=False,
        cert_fingerprint=None
    ):
        """
        Evaluate an access request.

        Parameters must come from trusted server-side
        connection and certificate verification data.
        """

        if not isinstance(source_ip, str):
            return self._deny("invalid_source")

        try:
            address = ipaddress.ip_address(
                source_ip.strip()
            )
        except ValueError:
            return self._deny("invalid_source")

        try:
            country = self.country_lookup(
                str(address)
            )
        except Exception:
            return self._deny(
                "location_unavailable"
            )

        if (
            not isinstance(country, str)
            or not re.fullmatch(
                r"[A-Z]{2}",
                country.strip().upper()
            )
        ):
            return self._deny(
                "location_unavailable"
            )

        country = country.strip().upper()

        # SR-07 imposes additional controls on
        # connections originating outside Australia.
        if country == "AU":
            return AccessDecision(
                True,
                "domestic_connection"
            )

        network_allowed = any(
            address in network
            for network in self.mission_networks
            if address.version == network.version
        )

        if not network_allowed:
            return self._deny(
                "non_mission_network"
            )

        if cert_verified is not True:
            return self._deny(
                "certificate_not_verified"
            )

        fingerprint = self._fingerprint(
            cert_fingerprint
        )

        if (
            fingerprint is None
            or fingerprint
            not in self.registered_fingerprints
        ):
            return self._deny(
                "unregistered_credential"
            )

        return AccessDecision(
            True,
            "approved_mission_connection"
        )
