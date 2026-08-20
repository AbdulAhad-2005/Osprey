from __future__ import annotations

import json
import os
from collections.abc import Iterator
from typing import Any

import httpx


def _error_detail(exc: httpx.HTTPStatusError) -> str:
    """Best-effort extract of the backend's `detail` from an HTTP error response."""
    import json

    try:
        exc.response.read()
        data = exc.response.json()
    except (json.JSONDecodeError, ValueError, httpx.ResponseNotRead, httpx.StreamError):
        return ""
    if isinstance(data, dict) and data.get("detail"):
        detail = data["detail"]
        return str(detail) if isinstance(detail, (str, int)) else json.dumps(detail)
    return ""


class APIClient:
    """HTTP client for communicating with the FastAPI backend."""

    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = (base_url or os.getenv("API_BASE_URL", "http://localhost:9000")).rstrip("/")
        self._timeout = httpx.Timeout(3600.0, connect=30.0)
        self._client = httpx.Client(timeout=self._timeout, follow_redirects=True)
        self._conversation_history: list[dict[str, Any]] = []
        self._run_id: str | None = None
        self._engagement_id: str | None = None

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

    def list_findings(
        self, engagement_id: str | None = None, *, q: str = "", limit: int = 100,
        exclude_noise: bool = True,
    ) -> list[dict[str, Any]]:
        """List findings for an engagement.

        The backend returns a ``{"findings": [...], "total": n}`` envelope —
        normalize both shapes so callers always get a bare list. `q` is a
        substring filter (title/target/evidence/source tool/tags, backend-side)
        — without it, a large engagement's default 100-row window can be
        dominated by whichever tool happened to produce the most granular
        findings (e.g. nmap's per-port/per-script output), silently hiding
        everything else. `exclude_noise` (default True) hides unparsed/raw-
        output findings kept only for evidence, not real findings.
        """
        try:
            params: dict[str, Any] = {"engagement_id": engagement_id} if engagement_id else {}
            if q:
                params["q"] = q
            params["limit"] = limit
            params["exclude_noise"] = exclude_noise
            resp = self._client.get(self._url("/api/v1/findings"), params=params)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict) and "findings" in data:
                return data["findings"] or []
            return data or []
        except httpx.HTTPStatusError:
            return []

    def get_report_markdown(self, engagement_id: str) -> str | None:
        """Human-readable recon report (seed -> sister domains -> subdomains
        -> IPs -> ports/services/tech, WHOIS/OSINT, vulnerabilities) as raw
        Markdown text. None on any HTTP error (e.g. unknown engagement)."""
        try:
            resp = self._client.get(self._url(f"/api/v1/engagements/{engagement_id}/report.md"))
            resp.raise_for_status()
            return resp.text
        except httpx.HTTPStatusError:
            return None

    def list_findings_grouped(
        self, engagement_id: str | None = None, *, q: str = "", exclude_noise: bool = True,
    ) -> dict[str, Any]:
        """One row per distinct issue pattern (the same NSE script across many
        ports, the same URL-crawl pattern across many paths) instead of one
        row per instance — returns {"groups": [...], "total_groups": n,
        "total_findings": n}, or an empty groups list on any HTTP error."""
        try:
            params: dict[str, Any] = {"engagement_id": engagement_id} if engagement_id else {}
            if q:
                params["q"] = q
            params["exclude_noise"] = exclude_noise
            resp = self._client.get(self._url("/api/v1/findings/grouped"), params=params)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError:
            return {"groups": [], "total_groups": 0, "total_findings": 0}

    def create_engagement(self, data: dict[str, Any]) -> dict[str, Any]:
        resp = self._client.post(self._url("/api/v1/engagements"), json=data)
        resp.raise_for_status()
        return resp.json()

    def resolve_engagement(self, target: str, force_new: bool = False) -> dict[str, Any]:
        """Get-or-create an engagement for a target (backend validates the name).

        Raises httpx.HTTPStatusError with the backend detail on bad/ambiguous targets.
        """
        resp = self._client.post(
            self._url("/api/v1/engagements/resolve"),
            json={"target": target, "force_new": force_new},
        )
        resp.raise_for_status()
        return resp.json()

    def compile_engagement_for_target(self, target: str, force_new: bool = False) -> dict[str, Any]:
        """Bind a target to an engagement for this session — reuse existing unless force_new.

        Prefers the get-or-create ``/engagements/resolve`` endpoint; falls back to a
        plain create if the backend does not expose it yet.
        """
        try:
            return self.resolve_engagement(target, force_new=force_new)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return self.create_engagement({"target": target})
            raise

    def _set_active_engagement(self, engagement_id: str | None) -> None:
        self._engagement_id = engagement_id or None

    @property
    def active_engagement_id(self) -> str | None:
        return self._engagement_id

    def execution_status(self) -> dict[str, Any]:
        """Ask the backend whether tools can actually run (docker/native) and if
        it's ready. Used by /scan --engine to fail fast with one clear error
        instead of every tool reporting '(failed)'. On any HTTP error, assume
        ready so we never block a scan on a transient probe failure."""
        try:
            resp = self._client.get(self._url("/api/v1/health/execution"))
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError:
            return {"ready": True, "mode": "unknown", "message": ""}

    def start_expansion_job(
        self, engagement_id: str, *, run_id: str = "", max_passes: int = 5,
        include_low_confidence: bool = False,
    ) -> dict[str, Any]:
        """Engine mode: run the BFS surface-expansion engine as a background
        job — no LLM involved. Same job kind/endpoint the MCP `platform_expand`
        tool and the auto-fire-on-bind path use; the CLI is just another caller."""
        resp = self._client.post(
            self._url("/api/v1/jobs/start"),
            json={
                "kind": "expansion", "engagement_id": engagement_id,
                "run_id": run_id, "max_passes": max_passes,
                "include_low_confidence": include_low_confidence,
                "label": f"expand(max_passes={max_passes})",
            },
        )
        resp.raise_for_status()
        return resp.json()

    def start_fast_scan_job(self, engagement_id: str, target: str, *, run_id: str = "") -> dict[str, Any]:
        """Deterministic, no-LLM, no-sister-domain pipeline: whois -> direct
        subdomain enumeration -> resolve to IPs -> nmap deep scan (service +
        OS detection, tuned min-rate, top ports) per unique IP. Narrower and
        faster than the full BFS expansion engine (start_expansion_job) —
        just the four things asked for, nothing else."""
        resp = self._client.post(
            self._url("/api/v1/jobs/start"),
            json={
                "kind": "fast_scan", "engagement_id": engagement_id,
                "run_id": run_id, "target": target,
                "label": f"fast-scan({target})",
            },
        )
        resp.raise_for_status()
        return resp.json()

    def poll_job(self, job_id: str, *, wait_seconds: float = 0) -> dict[str, Any]:
        params = {"wait_seconds": wait_seconds} if wait_seconds else {}
        resp = self._client.get(self._url(f"/api/v1/jobs/{job_id}"), params=params)
        resp.raise_for_status()
        return resp.json()

    def job_result(self, job_id: str) -> dict[str, Any]:
        resp = self._client.get(self._url(f"/api/v1/jobs/{job_id}/result"))
        resp.raise_for_status()
        return resp.json()

    def cancel_job(self, job_id: str) -> dict[str, Any]:
        """Stop a running job early. Findings gathered before the stop are already
        persisted server-side; this just halts further work."""
        resp = self._client.post(self._url(f"/api/v1/jobs/{job_id}/cancel"))
        resp.raise_for_status()
        return resp.json()

    def _build_chat_payload(
        self, prompt: str, engagement_id: str | None, phase: str
    ) -> dict[str, Any]:
        """Shared request body for the /agent/chat[/stream] endpoints."""
        payload: dict[str, Any] = {"prompt": prompt, "phase": phase}
        if engagement_id:
            payload["engagement_id"] = engagement_id
        if self._conversation_history:
            payload["conversation_history"] = list(self._conversation_history)
        if self._run_id:
            payload["run_id"] = self._run_id
        return payload

    def send_prompt(
        self, prompt: str, engagement_id: str | None = None, phase: str = "full"
    ) -> dict[str, Any]:
        """Send a prompt to the agent and return the full response."""
        payload = self._build_chat_payload(prompt, engagement_id, phase)
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
        except httpx.HTTPStatusError as exc:
            detail = _error_detail(exc)
            return {"error": f"Request failed: {exc.response.status_code}" + (f" — {detail}" if detail else "")}
        except httpx.TimeoutException as exc:
            return {
                "error": (
                    f"Request timed out ({exc}). The backend may still be working — "
                    "check: docker logs -f ai-pentest-backend. "
                    "Use /exit, restart the CLI, then /reset before the next target."
                ),
            }

    def send_prompt_stream(
        self,
        prompt: str,
        engagement_id: str | None = None,
        phase: str = "full",
    ) -> Iterator[tuple[str, dict[str, Any]]]:
        """Stream agent events from SSE. Yields (event_type, data) until done."""
        payload = self._build_chat_payload(prompt, engagement_id, phase)

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
            detail = _error_detail(exc)
            yield "error", {"message": f"Request failed: {exc.response.status_code}" + (f" — {detail}" if detail else "")}
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
