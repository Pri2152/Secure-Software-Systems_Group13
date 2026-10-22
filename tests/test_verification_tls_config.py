"""SR-12: gateway config allows only TLS 1.3 and sends HSTS."""

import re

from pathlib import Path


CONFIG = Path(__file__).resolve().parent.parent / "nginx" / "conf.d" / "evp.conf"


def server_blocks():
    """Cut the config into its server { ... } blocks."""

    text = CONFIG.read_text(encoding="utf-8")
    blocks = []
    for match in re.finditer(r"^server\s*\{", text, re.MULTILINE):
        depth, position = 1, match.end()
        while depth:
            character = text[position]
            depth += character == "{"
            depth -= character == "}"
            position += 1
        blocks.append(text[match.start():position])
    return blocks


def https_block():
    [block] = [b for b in server_blocks() if "listen 8443 ssl" in b]
    return block


def code_lines(block):
    return [
        line.strip()
        for line in block.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def test_https_server_allows_only_tls13():
    lines = [l for l in code_lines(https_block()) if l.startswith("ssl_protocols")]

    assert lines == ["ssl_protocols TLSv1.3;"]


def test_no_older_protocol_is_named_anywhere():
    text = "\n".join(code_lines(CONFIG.read_text(encoding="utf-8")))

    assert not re.search(r"TLSv1(\.[012])?\b(?!\.3)", text.replace("TLSv1.3", ""))


def test_hsts_is_sent_on_every_response():
    lines = [
        l for l in code_lines(https_block())
        if l.startswith("add_header Strict-Transport-Security")
    ]

    assert len(lines) == 1
    assert lines[0].endswith(" always;")
    max_age = int(re.search(r"max-age=(\d+)", lines[0]).group(1))
    assert max_age >= 31536000
    assert "includeSubDomains" in lines[0]


def test_locations_do_not_replace_the_hsts_header():
    # In nginx, add_header inside a location hides the server-level ones.
    block = https_block()
    locations = re.findall(r"location[^{]*\{[^}]*\}", block)

    assert locations
    assert all("add_header" not in location for location in locations)


def test_plain_http_serves_no_application():
    [http_block] = [b for b in server_blocks() if "listen 8443 ssl" not in b]
    text = "\n".join(code_lines(http_block))

    assert "proxy_pass" not in text
    assert "return 403;" in text
