
"""
SR-20 tests for the CI pipeline and Dependabot settings.

Checks that every change is tested, scanned for known
vulnerabilities and recorded in an SBOM, with a
read-only workflow token.
"""

from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
DEPENDABOT_PATH = REPO_ROOT / ".github" / "dependabot.yml"


def load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def workflow():
    return load(WORKFLOW_PATH)


@pytest.fixture(scope="module")
def steps(workflow):
    return workflow["jobs"]["test-and-scan"]["steps"]


def commands(steps):
    return [step.get("run", "") for step in steps]


def step_index(steps, text):
    matches = [
        index for index, command in enumerate(commands(steps))
        if text in command
    ]
    assert matches, f"No CI step runs {text!r}"
    return matches[0]


def test_workflow_triggers(workflow):
    # PyYAML reads the bare key "on" as boolean True.
    triggers = workflow.get("on", workflow.get(True))

    assert triggers["push"]["branches"] == ["main", "feature/**"]
    assert "pull_request" in triggers


def test_workflow_token_is_read_only(workflow):
    assert workflow["permissions"] == {"contents": "read"}

    for job in workflow["jobs"].values():
        assert job.get("permissions", {"contents": "read"}) == {
            "contents": "read"
        }


def test_job_uses_python_311_on_ubuntu(workflow, steps):
    job = workflow["jobs"]["test-and-scan"]

    assert job["runs-on"] == "ubuntu-latest"

    setup = [
        step for step in steps
        if step.get("uses", "").startswith("actions/setup-python@")
    ]
    assert setup[0]["with"]["python-version"] == "3.11"


def test_requirements_are_installed(steps):
    step_index(steps, "pip install -r requirements.txt")


def test_pytest_step_runs_full_suite(steps):
    assert "python -m pytest -q" in commands(steps)


def test_pip_audit_scans_requirements(steps):
    step_index(steps, "pip-audit -r requirements.txt")


def test_sbom_is_generated_and_uploaded(steps):
    step_index(
        steps,
        "cyclonedx-py requirements requirements.txt -o sbom.json",
    )

    uploads = [
        step for step in steps
        if step.get("uses", "").startswith("actions/upload-artifact@")
    ]

    assert uploads[0]["with"] == {"name": "sbom", "path": "sbom.json"}


def test_scans_run_after_tests(steps):
    tests = step_index(steps, "python -m pytest")

    assert step_index(steps, "pip-audit -r") > tests
    assert step_index(steps, "cyclonedx-py requirements") > tests


def test_scanner_tools_are_pinned(steps):
    install = commands(steps)[step_index(steps, "pip-audit==")]

    assert "pip-audit==" in install
    assert "cyclonedx-bom==" in install


def test_only_official_actions_with_major_versions(steps):
    for step in steps:
        action = step.get("uses")

        if action is None:
            continue

        name, _, version = action.partition("@")

        assert name.startswith("actions/")
        assert version.startswith("v") and version[1:].isdigit()


def test_checkout_does_not_keep_token(steps):
    checkout = [
        step for step in steps
        if step.get("uses", "").startswith("actions/checkout@")
    ]

    assert checkout[0]["with"]["persist-credentials"] is False


def test_gitkeep_removed():
    assert not (WORKFLOW_PATH.parent / ".gitkeep").exists()


def test_dependabot_covers_pip_and_docker_weekly():
    config = load(DEPENDABOT_PATH)

    assert config["version"] == 2

    updates = {
        update["package-ecosystem"]: update
        for update in config["updates"]
    }

    assert {"pip", "docker"} <= set(updates)

    for ecosystem in ("pip", "docker"):
        assert updates[ecosystem]["directory"] == "/"
        assert updates[ecosystem]["schedule"]["interval"] == "weekly"


def test_pyyaml_is_pinned():
    lines = (REPO_ROOT / "requirements.txt").read_text(
        encoding="utf-8"
    ).splitlines()

    assert "PyYAML==6.0.3" in lines
