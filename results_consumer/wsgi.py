"""
SR-18 / SR-20: results-consumer compartment entrypoint (Workstream D).

Gunicorn target: results_consumer.wsgi:app (deploy/ENTRYPOINTS.md)

Security controls:
- Registers only the POST /results route, nothing else
- Needs only the PUBLIC "results" key to check signatures, so
  this compartment cannot sign or change a result
- Fails closed at start-up: no election id or no keys means no app
- The app is built on first use, so importing this file needs
  no secrets

Environment:
- EVP_ELECTION_ID    the election this receiver accepts results for
- EVP_KEY_DIR        folder with manifest.json and the results key
- EVP_CRYPTO_POLICY  optional crypto policy file

Local academic prototype.
"""

import os

import crypto_agility

from .app import create_app as build_receiver


ENV_ELECTION_ID = "EVP_ELECTION_ID"


class ReceiverNotConfigured(RuntimeError):
    """A setting is missing, so the receiver will not start."""


def create_app(environ=None):
    environ = os.environ if environ is None else environ

    election_id = environ.get(ENV_ELECTION_ID)

    if not election_id:
        raise ReceiverNotConfigured(f"{ENV_ELECTION_ID} is required")

    # Raises CryptoNotConfigured when there is no key folder.
    crypto = crypto_agility.build_service_from_env(environ)

    return build_receiver(crypto=crypto, election_id=election_id)


_app = None


def __getattr__(name):
    # Built on first access (gunicorn's "results_consumer.wsgi:app").
    global _app

    if name == "app":
        if _app is None:
            _app = create_app()

        return _app

    raise AttributeError(name)
