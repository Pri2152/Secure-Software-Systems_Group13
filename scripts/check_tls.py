"""
SR-12: check that the running gateway refuses TLS 1.2 and accepts TLS 1.3.

How to run (project folder, gateway running):
    python scripts/check_tls.py localhost 8443 certs/test-ca.crt
"""

import sys

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verification.tls_check import check_server, passes  # noqa: E402


def main(argv):
    host, port, cafile = argv[1], int(argv[2]), argv[3]
    results = check_server(host, port, cafile)

    for version, accepted in results.items():
        print(f"{version}: {'accepted' if accepted else 'refused'}")

    print("PASS" if passes(results) else "FAIL")
    return 0 if passes(results) else 1


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    sys.exit(main(sys.argv))
