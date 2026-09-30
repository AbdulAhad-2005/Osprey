"""Engagement ids are now human-readable slugs derived from the target
("geo1", "geo2", ...) instead of an opaque uuid blob — an operator staring
at CLI output or the dashboard should recognize which engagement is which
without cross-referencing a lookup table."""

from __future__ import annotations

from fastapi.testclient import TestClient

from osprey.main import app


def _create(client: TestClient, target: str) -> str:
    resp = client.post("/api/v1/engagements/", json={"target": target})
    return resp.json()["id"]


def test_first_engagement_for_a_target_gets_slug_plus_one():
    with TestClient(app) as client:
        eid = _create(client, "id-scheme-geo.test")
    assert eid == "idschemegeo1"


def test_repeat_target_increments_the_counter():
    with TestClient(app) as client:
        first = _create(client, "id-scheme-counter.test")
        second = _create(client, "id-scheme-counter.test")
    assert first == "idschemecounter1"
    assert second == "idschemecounter2"


def test_www_prefix_is_stripped():
    with TestClient(app) as client:
        eid = _create(client, "www.id-scheme-www.test")
    assert eid == "idschemewww1"


def test_ip_target_still_gets_a_readable_id():
    with TestClient(app) as client:
        eid = _create(client, "203.0.113.77")
    assert eid.startswith("203")
