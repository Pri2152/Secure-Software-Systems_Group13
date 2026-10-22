"""
SR-11: anyone can run this to check a published bulletin board.

How to run:
    EVP_KEY_DIR=<folder with the public keys> python scripts/verify_tally.py bulletin.json

It prints PASS or FAIL for each check and exits with 1 if any check fails.
"""

import json
import sys

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verification.bulletin import all_passed, verify_bulletin  # noqa: E402


def run(path, crypto):
    package = json.loads(Path(path).read_text(encoding="utf-8"))
    checks = verify_bulletin(crypto, package)

    for name, passed in checks:
        print(f"{'PASS' if passed else 'FAIL'}  {name}")

    return 0 if all_passed(checks) else 1


def main(argv):
    from crypto_agility import build_service_from_env

    return run(argv[1], build_service_from_env())


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv))
