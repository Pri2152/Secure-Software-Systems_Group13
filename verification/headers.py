"""
SR-15: security headers for every response.

- They stop the browser from running injected script, guessing
  content type, putting our page in a frame, or caching private data.
- A header is only added if the route did not set it already, so the
  stricter voting page policy stays as it is.
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
    """Add the headers to every response of this app."""

    @app.after_request
    def add_security_headers(response):
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)

        return response

    return app
