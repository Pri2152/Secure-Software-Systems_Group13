
"""
Layout tests for Workstream E (SR-13, SR-20).

Checks that secrets and generated artefacts are
git-ignored and the shared platform package imports.
"""

import importlib
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent


def ignore_rules():
    text = (REPO_ROOT / ".gitignore").read_text(
        encoding="utf-8"
    )

    return {
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    }


@pytest.mark.parametrize("pattern", [
    "deploy/secrets/",
    "certs/",
    "*.key",
    "*.pem",
    "*.crt",
    "*.p12",
    "sbom.json",
    "backups/",
])
def test_gitignore_excludes_secrets_and_artefacts(pattern):
    assert pattern in ignore_rules()


def test_gitignore_keeps_existing_rules():
    rules = ignore_rules()

    for pattern in (".env", ".env.*", "!.env.example",
                    "*.db", "/nginx/certs/"):
        assert pattern in rules


def test_shell_scripts_use_lf_line_endings():
    text = (REPO_ROOT / ".gitattributes").read_text(
        encoding="utf-8"
    )

    assert "*.sh text eol=lf" in text.splitlines()


def test_platform_security_package_imports():
    package = importlib.import_module("platform_security")

    for requirement in ("SR-04", "SR-13", "SR-19", "SR-20"):
        assert requirement in package.__doc__
