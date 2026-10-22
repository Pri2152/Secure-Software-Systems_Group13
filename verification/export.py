"""
SR-18: send the signed result over mutual TLS.

Both sides show a certificate. We check the receiver's certificate
against our CA, and the receiver checks ours. TLS 1.3 only.
"""

import json
import ssl
import urllib.error
import urllib.request


class ExportFailed(RuntimeError):
    """Could not deliver the result (connection or certificate problem)."""


def mtls_context(cafile, certfile, keyfile):
    context = ssl.create_default_context(cafile=cafile)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile, keyfile)
    return context


def send_results(package, url, *, cafile, certfile, keyfile, timeout=10):
    """
    POST the signed package. Returns (http status, json body).
    A 4xx answer is returned, not raised. Connection and certificate
    problems raise ExportFailed.
    """

    if not url.startswith("https://"):
        raise ExportFailed("Only https URLs are allowed")

    request = urllib.request.Request(
        url,
        data=json.dumps(package).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        context = mtls_context(cafile, certfile, keyfile)
        with urllib.request.urlopen(request, context=context, timeout=timeout) as reply:
            return reply.status, json.loads(reply.read())
    except urllib.error.HTTPError as answer:
        return answer.code, json.loads(answer.read() or b"{}")
    except (urllib.error.URLError, ssl.SSLError, OSError, ValueError):
        raise ExportFailed("Result could not be delivered") from None
