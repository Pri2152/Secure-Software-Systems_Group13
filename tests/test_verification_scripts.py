"""SR-11: the verify script and the demo script work."""

import copy
import json
import random
import runpy

import pytest

from sqlalchemy import create_engine

import audit

from audit import AuditLog
from ballot_chain import append_ballot
from records import db
from test_ballot_models import db_app  # noqa: F401  (fixture)
from verification.bulletin import build_bulletin


ROOT = __import__("pathlib").Path(__file__).resolve().parent.parent


@pytest.fixture
def package(db_app, ballot_crypto, monkeypatch):
    audit_log = AuditLog(create_engine("sqlite:///:memory:"), crypto=ballot_crypto)
    audit_log.create_schema()
    monkeypatch.setattr(audit, "record_event", audit_log.record_event)

    for candidate in (1, 2, 1):
        append_ballot("election-2026", "Melbourne", "opaque", candidate)
        db.session.commit()

    yield build_bulletin(
        ballot_crypto, "election-2026", ["Melbourne"], 1, rng=random.Random(1)
    )
    audit_log.engine.dispose()


def load_verify_script():
    return runpy.run_path(str(ROOT / "scripts" / "verify_tally.py"))["run"]


def test_script_passes_an_honest_file(tmp_path, ballot_crypto, package, capsys):
    path = tmp_path / "bulletin.json"
    path.write_text(json.dumps(package))

    assert load_verify_script()(path, ballot_crypto) == 0
    assert "FAIL" not in capsys.readouterr().out


def test_script_fails_a_changed_file(tmp_path, ballot_crypto, package, capsys):
    bad = copy.deepcopy(package)
    bad["bulletin"]["divisions"][0]["choices"][0] = 42
    path = tmp_path / "bulletin.json"
    path.write_text(json.dumps(bad))

    assert load_verify_script()(path, ballot_crypto) == 1
    assert "FAIL" in capsys.readouterr().out


def test_demo_script_shows_pass_then_fail(capsys):
    runpy.run_path(str(ROOT / "scripts" / "demo_bulletin.py"), run_name="__main__")

    output = capsys.readouterr().out
    honest, changed = output.split("Check after one choice was changed:")

    assert "FAIL" not in honest.split("Check of the honest bulletin:")[1]
    assert "FAIL" in changed
