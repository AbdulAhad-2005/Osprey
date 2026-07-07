from fastapi.testclient import TestClient

from pentest_platform.main import app

client = TestClient(app)


def test_root_health() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "pentest-platform-backend"}


def test_api_v1_health() -> None:
    response = client.get("/api/v1/health/")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "pentest-platform-api"}
