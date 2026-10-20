"""The foreground chat SSE endpoint + interactive-question endpoints.

Covers the deterministic, LLM-free paths: a graceful no-model stream, answering
an unknown question, and the open-questions listing. The LLM-driving path is
covered where the loop lives (cli/tests)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from osprey.main import app


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def test_chat_without_model_streams_error_then_done(client, monkeypatch):
    # Force "no model" deterministically regardless of any local .env.
    import osprey.services.foreground_chat as fc

    monkeypatch.setattr(fc, "resolve_model_config", lambda: None)

    r = client.post("/api/v1/agent/chat", json={"engagement_id": "eng-x", "prompt": "hi"})
    assert r.status_code == 200
    assert "text/event-stream" in r.headers["content-type"]
    body = r.text
    assert "event: error" in body
    assert "event: done" in body
    # The error points the operator at a fix (Settings / LLM_MODEL) rather than
    # hanging silently on a chat with no usable model.
    assert "No usable model is configured" in body
    assert "Settings" in body


def test_chat_requires_engagement_and_prompt(client, monkeypatch):
    import osprey.services.foreground_chat as fc

    monkeypatch.setattr(fc, "resolve_model_config", lambda: None)
    r = client.post("/api/v1/agent/chat", json={"engagement_id": "", "prompt": ""})
    assert r.status_code == 200
    assert "required" in r.text


def test_answer_unknown_question_returns_ok_false(client):
    r = client.post("/api/v1/agent/question/nope/answer", json={"engagement_id": "e", "answer": "x"})
    assert r.status_code == 200
    assert r.json()["ok"] is False


def test_open_questions_empty_for_fresh_engagement(client):
    r = client.get("/api/v1/agent/questions/eng-empty-123")
    assert r.status_code == 200
    assert r.json() == {"engagement_id": "eng-empty-123", "questions": []}
