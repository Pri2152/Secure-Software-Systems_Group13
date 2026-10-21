"""Authenticated trusted ballot rendering and browser privacy headers."""

from html.parser import HTMLParser

import pytest

import app as application
from admin.models import Candidate
from ballot_models import BallotCredential, VotingEligibility
from records import db
from test_voting_routes import HTTPS_URL, voting_client


class BallotPage(HTMLParser):
    def __init__(self):
        super().__init__()
        self.csrf = None
        self.candidates = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta" and attrs.get("name") == "csrf-token":
            self.csrf = attrs["content"]
        if tag == "input" and attrs.get("name") == "candidate_id":
            self.candidates.append(int(attrs["value"]))


def test_page_renders_only_final_candidates_and_no_credential(voting_client):
    client, candidate_id = voting_client
    response = client.get("/vote", base_url=HTTPS_URL)
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    parsed = BallotPage()
    parsed.feed(html)
    assert parsed.csrf
    assert parsed.candidates == [candidate_id]
    assert "Candidate Alpha" in html
    assert "Example Party" in html
    assert "Melbourne" in html
    assert "voter-001" not in html
    assert 'name="credential"' not in html
    with application.app.app_context():
        assert BallotCredential.query.count() == 0


def test_page_requires_active_authentication(voting_client):
    client, _ = voting_client
    with client.session_transaction(base_url=HTTPS_URL) as active:
        active.clear()
    assert client.get("/vote", base_url=HTTPS_URL).status_code == 401


@pytest.mark.parametrize("state", ["draft", "excluded", "already-voted"])
def test_unavailable_ballot_renders_generic_page(voting_client, state):
    client, candidate_id = voting_client
    with application.app.app_context():
        if state == "already-voted":
            VotingEligibility.query.filter_by(voter_id="voter-001").one().has_voted = True
        elif state == "excluded":
            db.session.get(Candidate, candidate_id).status = "EXCLUDED"
        else:
            # Direct setup mutation simulates a list which was never finalised.
            db.session.execute(db.update(Candidate).values(status="DRAFT"))
        db.session.commit()
    response = client.get("/vote", base_url=HTTPS_URL)
    assert response.status_code == 409
    html = response.get_data(as_text=True)
    assert "Voting unavailable" in html
    assert "Candidate Alpha" not in html
    assert "already" not in html


@pytest.mark.parametrize("path", ["/vote", "/vote/assets/ballot.js", "/vote/assets/ballot.css"])
def test_voting_responses_are_private_and_csp_compatible(voting_client, path):
    client, _ = voting_client
    response = client.get(path, base_url=HTTPS_URL)
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Referrer-Policy"] == "same-origin"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert "'unsafe-inline'" not in response.headers["Content-Security-Policy"]
