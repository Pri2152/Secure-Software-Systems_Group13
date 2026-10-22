"""
Test-only SR-13 crypto provider.

Stands in for Workstream B's SR-14 crypto_agility
service in tests: AES-256-GCM with a random key made
per instance, the purpose bound as associated data,
and the envelope {alg, kid, v, nonce, ct}.

Never use this outside tests: the key lives only in
memory and is lost when the provider is discarded.
"""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AesGcmTestProvider:
    ALG = "AES-256-GCM"
    VERSION = 1

    def __init__(self, kid="test-pii-v1"):
        self.kid = kid
        self._aesgcm = AESGCM(AESGCM.generate_key(bit_length=256))

    def encrypt(self, purpose, plaintext_bytes):
        nonce = os.urandom(12)
        ct = self._aesgcm.encrypt(
            nonce, plaintext_bytes, purpose.encode("utf-8")
        )

        return {
            "alg": self.ALG,
            "kid": self.kid,
            "v": self.VERSION,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ct": base64.b64encode(ct).decode("ascii"),
        }

    def decrypt(self, purpose, envelope):
        if (
            envelope.get("alg") != self.ALG
            or envelope.get("kid") != self.kid
            or envelope.get("v") != self.VERSION
        ):
            raise ValueError("Unsupported envelope")

        return self._aesgcm.decrypt(
            base64.b64decode(envelope["nonce"]),
            base64.b64decode(envelope["ct"]),
            purpose.encode("utf-8"),
        )
