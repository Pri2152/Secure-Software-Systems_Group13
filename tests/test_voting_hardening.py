"""Final HTTP boundary checks without modifying the reviewed voting controls."""

import pytest

from test_voting_routes import HTTPS_URL, csrf_headers, issue, vote, voting_client


@pytest.mark.parametrize("path", ["/vote", "/vote/credentials", "/vote/ballots"])
def test_no_query_string_handoff(voting_client, path):
    client, _ = voting_client
    request = client.get if path == "/vote" else client.post
    result = request(path + "?voter_id=untrusted", base_url=HTTPS_URL,
                     headers=csrf_headers(client))
    assert result.status_code == 400
    assert result.get_json() == {"error": "Invalid request"}
    assert result.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("body", [b'{"credential":"a","credential":"b","candidate_id":1}',
                                  b'{"candidate_id":', b'\xff'])
def test_ambiguous_or_invalid_json_is_rejected(voting_client, body):
    client, _ = voting_client
    response = client.post("/vote/ballots", data=body, content_type="application/json",
                           base_url=HTTPS_URL, headers=csrf_headers(client))
    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid request"}


def test_post_vote_csrf_cannot_be_replayed(voting_client):
    client, candidate_id = voting_client
    old = csrf_headers(client)
    credential = issue(client).get_json()["credential"]
    assert vote(client, credential, candidate_id).status_code == 200
    response = client.post("/vote/ballots", json=dict(credential=credential, candidate_id=candidate_id),
                           headers=old, base_url=HTTPS_URL)
    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid request"}


def test_cross_origin_csrf_request_fails(voting_client):
    client, _ = voting_client
    headers = csrf_headers(client)
    headers["Referer"] = "https://untrusted.example/"
    result = client.post("/vote/credentials", json={}, base_url=HTTPS_URL, headers=headers)
    assert result.status_code == 400


def test_success_and_failure_both_disable_caching(voting_client):
    client, candidate_id = voting_client
    credential = issue(client).get_json()["credential"]
    for response in (vote(client, credential, candidate_id), vote(client, credential, candidate_id)):
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["Pragma"] == "no-cache"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
