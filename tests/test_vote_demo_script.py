"""scripts/vote_demo.py reads the real vote page and fails safely."""

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def vote_demo():
    spec = importlib.util.spec_from_file_location(
        "vote_demo", ROOT / "scripts" / "vote_demo.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def test_patterns_match_the_real_ballot_template(vote_demo):
    template = (ROOT / "templates" / "voting" / "ballot.html").read_text()
    page = template.replace("{{ csrf_token() }}", "token-123").replace(
        "{{ candidate.candidate_id }}", "7"
    )

    assert vote_demo.CANDIDATE_PATTERN.findall(page) == ["7"]
    assert vote_demo.CSRF_PATTERN.search(page).group(1) == "token-123"


def test_confirmation_pattern_matches_what_the_ballot_page_accepts(vote_demo):
    assert vote_demo.CONFIRMATION_PATTERN.fullmatch("conf_" + "A" * 32)
    assert not vote_demo.CONFIRMATION_PATTERN.fullmatch("conf_short")


def test_missing_certificates_fail_with_exit_code_1(vote_demo, tmp_path, capsys):
    assert vote_demo.main(["--certs", str(tmp_path)]) == 1
    assert "FAILED" in capsys.readouterr().err


def test_script_never_prints_secrets(vote_demo):
    text = (ROOT / "scripts" / "vote_demo.py").read_text()

    assert "print(voter" not in text
    assert "print(credential" not in text
