from __future__ import annotations

import json
import os
from collections.abc import Iterator
from typing import Any

import httpx


class APIClient:
    """HTTP client for communicating with the FastAPI backend."""

    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = (base_url or os.getenv("API_BASE_URL", "http://localhost:9000")).rstrip("/")
        self._timeout = httpx.Timeout(3600.0, connect=30.0)
        self._client = httpx.Client(timeout=self._timeout, follow_redirects=True)
        self._conversation_history: list[dict[str, Any]] = []
        self._run_id: str | None = None

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
        """Send a prompt to the agent and return the full response."""
        payload: dict[str, Any] = {"prompt": prompt, "phase": "full"}
        if engagement_id:
            payload["engagement_id"] = engagement_id
        if self._conversation_history:
            payload["conversation_history"] = list(self._conversation_history)
        if self._run_id:
            payload["run_id"] = self._run_id
        try:
            resp = self._client.post(self._url("/api/v1/agent/chat"), json=payload)
            resp.raise_for_status()
            data = resp.json()
            if data.get("run_id"):
                self._run_id = data["run_id"]
            response_text = data.get("response", "")
            if response_text and data.get("success", True):
                self._conversation_history.append({"role": "user", "content": prompt})
                self._conversation_history.append({"role": "assistant", "content": response_text})
            return data
        except httpx.TimeoutException as exc:
            return {
                "error": (
                    f"Request timed out ({exc}). The backend may still be working — "
                    "check: docker logs -f ai-pentest-backend. "
                    "Use /exit, restart the CLI, then /reset before the next target."
                ),
            }
        except httpx.HTTPStatusError as exc:
            return {"error": f"Request failed: {exc.response.status_code}"}

    def send_prompt_stream(
        self,
        prompt: str,
        engagement_id: str | None = None,
    ) -> Iterator[tuple[str, dict[str, Any]]]:
        """Stream agent events from SSE. Yields (event_type, data) until done."""
        payload: dict[str, Any] = {"prompt": prompt, "phase": "full"}
        if engagement_id:
            payload["engagement_id"] = engagement_id
        if self._conversation_history:
            payload["conversation_history"] = list(self._conversation_history)
        if self._run_id:
            payload["run_id"] = self._run_id

        final_data: dict[str, Any] | None = None

        try:
            with self._client.stream(
                "POST",
                self._url("/api/v1/agent/chat/stream"),
                json=payload,
            ) as resp:
                resp.raise_for_status()
                event_type = "message"
                data_lines: list[str] = []

                for raw_line in resp.iter_lines():
                    if raw_line is None:
                        continue
                    line = raw_line.strip()
                    if not line:
                        if data_lines:
                            data = json.loads("".join(data_lines))
                            data_lines.clear()
                            if event_type == "done":
                                final_data = data
                            yield event_type, data
                        continue
                    if line.startswith("event:"):
                        event_type = line[6:].strip()
                    elif line.startswith("data:"):
                        data_lines.append(line[5:].strip())

                if data_lines:
                    data = json.loads("".join(data_lines))
                    if event_type == "done":
                        final_data = data
                    yield event_type, data

        except httpx.TimeoutException as exc:
            yield "error", {
                "message": (
                    f"Request timed out ({exc}). The backend may still be working — "
                    "check: docker logs -f ai-pentest-backend"
                ),
            }
            return
        except httpx.HTTPStatusError as exc:
            yield "error", {"message": f"Request failed: {exc.response.status_code}"}
            return

        if final_data and final_data.get("success", True):
            response_text = final_data.get("response", "")
            if response_text:
                self._conversation_history.append({"role": "user", "content": prompt})
                self._conversation_history.append({"role": "assistant", "content": response_text})
            if final_data.get("run_id"):
                self._run_id = final_data["run_id"]

    def get_agent_status(self) -> dict[str, Any]:
        try:
            resp = self._client.get(self._url("/api/v1/agent/status"))
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError:
            return {}

    def reset_conversation(self) -> None:
        self._conversation_history.clear()
        self._run_id = None

    def reconnect(self, base_url: str | None = None) -> None:
        """Close the current client and reconnect to a (possibly different) backend URL."""
        self._client.close()
        if base_url:
            self.base_url = base_url.rstrip("/")
        else:
            self.base_url = os.getenv("API_BASE_URL", "http://localhost:9000").rstrip("/")
        self._client = httpx.Client(timeout=self._timeout, follow_redirects=True)

    def close(self) -> None:
        self._client.close()
