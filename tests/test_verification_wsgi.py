"""SR-11 / SR-18 / SR-20: tally entrypoint starts only when configured."""

import pytest

from sqlalchemy import update

import audit
import crypto_agility
from ballot_chain import append_ballot
from ballot_models import AnonymousBallot
from records import db
from verification import wsgi
from verification.bulletin import all_passed, verify_bulletin


ELECTION = "election-2026"
TOKEN = "t" * 40
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def settings(tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text(TOKEN)

    return {
        "EVP_ELECTION_ID": ELECTION,
        "EVP_DIVISIONS": "Melbourne, Kooyong",
        "EVP_TALLY_TOKEN_FILE": str(token_file),
        "EVP_BALLOT_DB_URL": f"sqlite:///{tmp_path / 'ballot.db'}",
        "EVP_AUDIT_DB_URL": f"sqlite:///{tmp_path / 'audit.db'}",
    }


@pytest.fixture
def tally(settings, monkeypatch):
    crypto = crypto_agility.build_service(dev_keys=True)
    app = wsgi.create_app(settings, crypto=crypto)

    with app.app_context():
        db.create_all()

        for division, candidate in (
            ("Melbourne", 7), ("Melbourne", 8), ("Kooyong", 3),
        ):
            append_ballot(ELECTION, division, "opaque", candidate)
            db.session.commit()

        yield app, crypto

        db.session.remove()

    crypto_agility.configure(None)


@pytest.mark.parametrize("missing", [
    "EVP_ELECTION_ID", "EVP_DIVISIONS", "EVP_TALLY_TOKEN_FILE",
    "EVP_BALLOT_DB_URL",
])
def test_missing_setting_means_no_app(settings, missing):
    del settings[missing]

    with pytest.raises(wsgi.TallyNotConfigured):
        wsgi.create_app(settings, crypto=object())


def test_short_token_means_no_app(settings, tmp_path):
    (tmp_path / "token").write_text("short")

    with pytest.raises(wsgi.TallyNotConfigured):
        wsgi.create_app(settings, crypto=object())


def test_receiver_url_without_certificates_means_no_app(settings):
    settings["EVP_RESULTS_URL"] = "https://results:5000/results"

    with pytest.raises(wsgi.TallyNotConfigured):
        wsgi.create_app(settings, crypto=object())


def test_importing_the_module_needs_no_secrets():
    assert wsgi.ENV_ELECTION_ID == "EVP_ELECTION_ID"


def test_routes_need_the_token(tally):
    app, _ = tally
    client = app.test_client()

    assert client.post("/publish").status_code == 401
    assert client.get("/bulletin").status_code == 401
    assert client.post(
        "/publish", headers={"Authorization": "Bearer wrong"}
    ).status_code == 401


def test_health_needs_no_token(tally):
    app, _ = tally

    assert app.test_client().get("/healthz").get_json() == {"status": "ok"}


def test_bulletin_is_404_before_publish(tally):
    app, _ = tally

    assert app.test_client().get("/bulletin", headers=HEADERS).status_code == 404


def test_publish_gives_a_bulletin_that_passes_every_check(tally):
    app, crypto = tally
    client = app.test_client()

    reply = client.post("/publish", headers=HEADERS)
    bulletin = client.get("/bulletin", headers=HEADERS).get_json()

    assert reply.get_json()["version"] == 1
    assert reply.get_json()["delivered"] is None
    assert all_passed(verify_bulletin(crypto, bulletin))


def test_each_publish_has_a_higher_version(tally):
    app, _ = tally
    client = app.test_client()

    client.post("/publish", headers=HEADERS)

    assert client.post("/publish", headers=HEADERS).get_json()["version"] == 2


def test_tampered_ballot_is_refused_without_details(tally):
    app, _ = tally

    db.session.execute(update(AnonymousBallot).values(record_hash="sha256:bad"))
    db.session.commit()

    reply = app.test_client().post("/publish", headers=HEADERS)

    assert reply.status_code == 409
    assert reply.get_json() == {"error": "Tally refused"}


def test_security_headers_are_set(tally):
    app, _ = tally

    reply = app.test_client().get("/healthz")

    assert reply.headers["X-Content-Type-Options"] == "nosniff"


def test_checks_route_needs_the_token(tally):
    app, _ = tally

    assert app.test_client().get("/bulletin/checks").status_code == 401


def test_checks_route_says_nothing_published_yet(tally):
    app, _ = tally

    response = app.test_client().get("/bulletin/checks", headers=HEADERS)

    assert response.status_code == 404


def test_checks_route_reports_totals_and_passing_checks(tally):
    app, _ = tally
    client = app.test_client()
    client.post("/publish", headers=HEADERS)

    data = client.get("/bulletin/checks", headers=HEADERS).get_json()

    assert data["all_passed"] is True
    assert data["ballots_counted"] == 3
    assert data["divisions"]["Melbourne"] == {"7": 1, "8": 1}
    assert data["version"] == 1
    assert all(item["passed"] for item in data["checks"])
    assert "record_hashes" not in data and "bulletin" not in data


def test_lookup_needs_the_token(tally):
    app, _ = tally

    response = app.test_client().post(
        "/bulletin/lookup", json={"tracking_code": "sha256:" + "0" * 64}
    )

    assert response.status_code == 401


def test_lookup_finds_a_published_record_and_misses_an_unknown_one(tally):
    app, _ = tally
    client = app.test_client()
    client.post("/publish", headers=HEADERS)

    with app.app_context():
        from ballot_models import AnonymousBallot
        mine = AnonymousBallot.query.filter_by(
            electoral_division="Kooyong"
        ).one().record_hash

    found = client.post(
        "/bulletin/lookup", json={"tracking_code": mine}, headers=HEADERS
    ).get_json()
    missing = client.post(
        "/bulletin/lookup", json={"tracking_code": "sha256:" + "0" * 64},
        headers=HEADERS,
    ).get_json()

    assert found == {
        "included": True, "division": "Kooyong", "position": 1,
        "ballots_in_division": 1, "version": 1,
    }
    assert missing == {"included": False, "version": 1}


def test_lookup_says_nothing_published_yet(tally):
    app, _ = tally

    response = app.test_client().post(
        "/bulletin/lookup", json={"tracking_code": "sha256:" + "0" * 64},
        headers=HEADERS,
    )

    assert response.status_code == 404


@pytest.mark.parametrize("body", [
    [], "x", {}, {"tracking_code": 5},
    {"tracking_code": "' OR '1'='1"},
    {"tracking_code": "<script>alert(1)</script>"},
    {"tracking_code": "sha256:" + "G" * 64},
    {"tracking_code": "sha256:" + "0" * 63},
    {"tracking_code": "sha256:" + "0" * 64, "extra": 1},
])
def test_lookup_refuses_bad_bodies_without_echoing_them(tally, body):
    app, _ = tally

    response = app.test_client().post(
        "/bulletin/lookup", json=body, headers=HEADERS
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid request"}
    assert b"script" not in response.data


def test_lookup_needs_a_json_body(tally):
    app, _ = tally

    response = app.test_client().post("/bulletin/lookup", headers=HEADERS)

    assert response.status_code == 415
