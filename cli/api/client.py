from __future__ import annotations

import os
from typing import Any

import httpx


class APIClient:
    """HTTP client for communicating with the FastAPI backend."""

    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = (base_url or os.getenv("API_BASE_URL", "http://localhost:9000")).rstrip("/")
        self._client = httpx.Client(timeout=300.0, follow_redirects=True)

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def health(self) -> dict[str, Any]:
        resp = self._client.get(self._url("/health"))
        resp.raise_for_status()
        return resp.json()

    def api_health(self) -> dict[str, Any]:
        resp = self._client.get(self._url("/api/v1/health/"))
        resp.raise_for_status()
        return resp.json()

    def list_tools(self) -> list[dict[str, Any]]:
        try:
            resp = self._client.get(self._url("/api/v1/tools"))
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError:
            return []

    def list_models(self) -> list[dict[str, Any]]:
        try:
            resp = self._client.get(self._url("/api/v1/models"))
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError:
            return []

    def list_engagements(self) -> list[dict[str, Any]]:
        try:
            resp = self._client.get(self._url("/api/v1/engagements"))
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError:
            return []

    def list_findings(self, engagement_id: str | None = None) -> list[dict[str, Any]]:
        try:
            params = {"engagement_id": engagement_id} if engagement_id else {}
            resp = self._client.get(self._url("/api/v1/findings"), params=params)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError:
            return []

    def create_engagement(self, data: dict[str, Any]) -> dict[str, Any]:
        resp = self._client.post(self._url("/api/v1/engagements"), json=data)
        resp.raise_for_status()
        return resp.json()

    def send_prompt(self, prompt: str, engagement_id: str | None = None) -> dict[str, Any]:
        """Send a prompt to the agent and return the full response.

        The response includes: response, model, tool_calls, duration_seconds, etc.
        """
        payload: dict[str, Any] = {"prompt": prompt}
        if engagement_id:
            payload["engagement_id"] = engagement_id
        try:
            resp = self._client.post(self._url("/api/v1/agent/chat"), json=payload)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            return {"error": f"Request failed: {exc.response.status_code}"}

    def get_agent_status(self) -> dict[str, Any]:
        try:
            resp = self._client.get(self._url("/api/v1/agent/status"))
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError:
            return {}

    def reconnect(self, base_url: str | None = None) -> None:
        """Close the current client and reconnect to a (possibly different) backend URL."""
        self._client.close()
        if base_url:
            self.base_url = base_url.rstrip("/")
        else:
            self.base_url = os.getenv("API_BASE_URL", "http://localhost:9000").rstrip("/")
        self._client = httpx.Client(timeout=300.0, follow_redirects=True)

    def close(self) -> None:
        self._client.close()
