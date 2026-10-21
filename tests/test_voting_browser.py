"""Execute the real GUI controller to inspect its handoff and success DOM."""

from pathlib import Path
import shutil
import subprocess

import pytest


def test_browser_controller_clears_preferences_and_shows_only_confirmation():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is needed for the optional isolated browser-controller test")
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [node, str(root / "tests/voting_browser_harness.cjs"),
         str(root / "static/voting/ballot.js")],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
