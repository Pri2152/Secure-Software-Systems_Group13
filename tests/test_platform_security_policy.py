
"""
SR-20 tests for SECURITY.md.

The vulnerability policy must exist and state the
remediation time limits for critical vulnerabilities.
"""

from pathlib import Path

import pytest


SECURITY_PATH = Path(__file__).resolve().parent.parent / "SECURITY.md"


@pytest.fixture(scope="module")
def policy():
    return SECURITY_PATH.read_text(encoding="utf-8")


def test_security_policy_exists():
    assert SECURITY_PATH.is_file()


def test_states_both_time_limits(policy):
    assert "**Election period: fixed within 24 hours.**" in policy
    assert "**Otherwise: fixed within 72 hours.**" in policy


@pytest.mark.parametrize("topic", [
    "Report a vulnerability",
    "CVSS",
    "Exploitability",
    "Asset criticality",
    "Dependabot",
    "pip-audit",
    "sbom",
])
def test_covers_required_topics(policy, topic):
    assert topic in policy


def test_stays_under_one_page(policy):
    assert len(policy.split()) <= 650
