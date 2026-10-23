"""Lab demo: the demo voter script writes a valid, private voter file."""

import importlib.util
import json
import stat

from pathlib import Path

import pyotp
import pytest


PATH = Path(__file__).resolve().parent.parent / "scripts" / "set_demo_voter.py"
spec = importlib.util.spec_from_file_location("set_demo_voter", PATH)
script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(script)

PASSWORD = "A-long-demo-password-1"


def test_voter_has_the_three_fields_the_gateway_reads():
    voter = script.make_voter("Priyanka", PASSWORD)

    assert set(voter) == {"account_id", "password", "totp_secret"}
    assert voter["account_id"] == "priyanka"          # gateway folds case
    assert pyotp.TOTP(voter["totp_secret"]).verify(
        pyotp.TOTP(voter["totp_secret"]).now()
    )


@pytest.mark.parametrize("account", [
    "", " ", "a b", "<script>", "' OR 1=1", "x" * 129, ".leading-dot",
])
def test_bad_account_names_are_refused(account):
    with pytest.raises(script.DemoVoterError):
        script.make_voter(account, PASSWORD)


@pytest.mark.parametrize("password", ["", "short", "x" * 11, "x" * 129])
def test_weak_or_huge_passwords_are_refused(password):
    with pytest.raises(script.DemoVoterError):
        script.make_voter("priyanka", password)


def test_file_is_private_and_rewritten_in_place(tmp_path):
    target = tmp_path / "secrets" / "demo-voter.json"
    script.write_voter(script.make_voter("priyanka", PASSWORD), target)
    first_inode = target.stat().st_ino

    script.write_voter(script.make_voter("priyanka", PASSWORD), target)

    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.stat().st_ino == first_inode
    assert json.loads(target.read_text())["account_id"] == "priyanka"


def test_provisioning_uri_has_account_and_issuer():
    uri = script.provisioning_uri(script.make_voter("priyanka", PASSWORD))

    assert uri.startswith("otpauth://totp/")
    assert "priyanka" in uri and "Electronic%20Voting%20Platform" in uri


def test_main_never_prints_the_password(tmp_path, monkeypatch, capsys):
    answers = iter([PASSWORD, PASSWORD])
    monkeypatch.setattr(script.getpass, "getpass", lambda prompt="": next(answers))
    target = tmp_path / "voter.json"

    code = script.main(["--account", "priyanka", "--out", str(target)])

    assert code == 0
    assert PASSWORD not in capsys.readouterr().out
    assert json.loads(target.read_text())["password"] == PASSWORD


def test_main_refuses_when_the_two_passwords_differ(tmp_path, monkeypatch, capsys):
    answers = iter([PASSWORD, "something-else-entirely"])
    monkeypatch.setattr(script.getpass, "getpass", lambda prompt="": next(answers))
    target = tmp_path / "voter.json"

    assert script.main(["--account", "priyanka", "--out", str(target)]) == 1
    assert not target.exists()
