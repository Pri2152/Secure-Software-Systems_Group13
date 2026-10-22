"""
SR-15: Security response headers.

Security controls:
- Every response carries headers that stop browsers running
  injected script, sniffing content types, framing the page or
  caching sensitive data
- Headers are only added when a route has not set its own, so a
  stricter route policy (such as the voting page) is never weakened

Local academic prototype.
"""

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def register_security_headers(app):
    """Add the standard headers to every response from this app."""

    @app.after_request
    def add_security_headers(response):
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)

        return response

    return app
