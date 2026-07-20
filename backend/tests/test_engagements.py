from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.services.engagement_store import get_engagement_store


def test_create_and_get_engagement() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/engagements/",
            json={"target": "example.com", "name": "test-engagement"},
        )
        assert response.status_code == 201
        body = response.json()
        assert body["target"] == "example.com"
        assert body["name"] == "test-engagement"
        assert len(body["id"]) == 12
        assert body["status"] == "created"

        fetched = client.get(f"/api/v1/engagements/{body['id']}")
        assert fetched.status_code == 200
        assert fetched.json()["id"] == body["id"]


def test_list_engagements_includes_created() -> None:
    with TestClient(app) as client:
        create = client.post("/api/v1/engagements/", json={"target": "list-test.local"})
        assert create.status_code == 201
        engagement_id = create.json()["id"]

        listed = client.get("/api/v1/engagements/")
        assert listed.status_code == 200
        ids = {item["id"] for item in listed.json()}
        assert engagement_id in ids


def test_engagement_store_persists_across_instances() -> None:
    with TestClient(app) as client:
        created = client.post("/api/v1/engagements/", json={"target": "persist.test"})
        assert created.status_code == 201
        engagement_id = created.json()["id"]

    store = get_engagement_store()
    engagement = store.get(engagement_id)
    assert engagement is not None
    assert engagement.target == "persist.test"


def test_delete_engagement() -> None:
    with TestClient(app) as client:
        created = client.post("/api/v1/engagements/", json={"target": "delete-me.test"})
        engagement_id = created.json()["id"]

        deleted = client.delete(f"/api/v1/engagements/{engagement_id}")
        assert deleted.status_code == 204

        missing = client.get(f"/api/v1/engagements/{engagement_id}")
        assert missing.status_code == 404
