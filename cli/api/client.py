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
        self._run_id: str | None = None
        self._engagement_id: str | None = None
        # The CLI's own local agent loop (cli/agent/loop.py) — lazily created
        # and attached by cli/commands/prompt.py, lives here so it persists
        # across prompts within one CLI session (follow-up questions keep
        # full context) without APIClient needing to know its shape.
        self.agent_runner: Any = None

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
        except httpx.HTTPError:
            return []

    def list_models(self) -> list[dict[str, Any]]:
        try:
            resp = self._client.get(self._url("/api/v1/models"))
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError:
            return []

    def list_engagements(self) -> list[dict[str, Any]]:
        try:
            resp = self._client.get(self._url("/api/v1/engagements"))
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError:
            return []

    def get_conversation(self, engagement_id: str, *, limit: int = 30) -> list[dict[str, Any]]:
        try:
            resp = self._client.get(
                self._url(f"/api/v1/agent/conversation/{engagement_id}"),
                params={"limit": limit},
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("messages") or []
        except httpx.HTTPStatusError:
            return []

    def get_pipeline_activity(self, engagement_id: str) -> dict[str, Any]:
        try:
            resp = self._client.get(
                self._url(f"/api/v1/agent/pipeline-activity/{engagement_id}")
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError:
            return {}

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
        except httpx.HTTPError:
            return None

    def read_artifact(
        self,
        engagement_id: str,
        path: str,
        *,
        offset: int = 0,
        limit: int = 200_000,
    ) -> dict[str, Any] | None:
        """Read a saved tool artifact slice from the backend/Kali workspace."""
        try:
            resp = self._client.get(
                self._url("/api/v1/hybrid/artifacts/read"),
                params={
                    "engagement_id": engagement_id,
                    "path": path,
                    "offset": offset,
                    "limit": limit,
                },
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError:
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

    def list_learned_skills(self) -> dict[str, Any]:
        resp = self._client.get(self._url("/api/v1/capabilities/learned-skills"))
        resp.raise_for_status()
        return resp.json()

    def add_learned_skill(self, payload: dict[str, Any]) -> dict[str, Any]:
        resp = self._client.post(
            self._url("/api/v1/capabilities/learned-skills/add"), json=payload
        )
        resp.raise_for_status()
        return resp.json()

    def approve_learned_skill(self, proposal_id: str) -> dict[str, Any]:
        resp = self._client.post(
            self._url(f"/api/v1/capabilities/learned-skills/{proposal_id}/approve")
        )
        resp.raise_for_status()
        return resp.json()

    def reject_learned_skill(self, proposal_id: str) -> dict[str, Any]:
        resp = self._client.delete(
            self._url(f"/api/v1/capabilities/learned-skills/{proposal_id}")
        )
        resp.raise_for_status()
        return resp.json()

    # --- FP-cache (plans/harness/04-learning-fp-cache.md) ---
    def mark_finding_fp(self, finding_id: str, *, reason: str = "", target_glob: str = "") -> dict[str, Any]:
        resp = self._client.post(
            self._url(f"/api/v1/findings/{finding_id}/fp"),
            params={"reason": reason, "target_glob": target_glob},
        )
        resp.raise_for_status()
        return resp.json()

    def list_fp_patterns(self) -> dict[str, Any]:
        resp = self._client.get(self._url("/api/v1/findings/fp/patterns"))
        resp.raise_for_status()
        return resp.json()

    def remove_fp_pattern(self, pattern_id: str) -> dict[str, Any]:
        resp = self._client.delete(self._url(f"/api/v1/findings/fp/patterns/{pattern_id}"))
        resp.raise_for_status()
        return resp.json()

    def list_suppressed_promotions(self, engagement_id: str) -> dict[str, Any]:
        resp = self._client.get(
            self._url("/api/v1/findings/fp/suppressed"), params={"engagement_id": engagement_id}
        )
        resp.raise_for_status()
        return resp.json()

    # --- Earned-finding pipeline (plans/harness/03-earned-finding-pipeline.md) ---
    # The only two ways a Finding comes into existence — same REST endpoints
    # platform_file_finding / platform_promote_observations call, so the CLI
    # and any MCP harness produce identical results against the same engagement.
    def file_finding(
        self, *, engagement_id: str, title: str, finding_type: str, observation_ids: list[str],
        claim_severity: str = "none", description: str = "", evidence_records: list[dict[str, Any]] | None = None,
        run_id: str = "", target: str = "", tags: list[str] | None = None,
    ) -> dict[str, Any]:
        resp = self._client.post(
            self._url("/api/v1/findings/file"),
            json={
                "engagement_id": engagement_id, "title": title, "finding_type": finding_type,
                "observation_ids": observation_ids, "claim_severity": claim_severity,
                "description": description, "evidence_records": evidence_records or [],
                "run_id": run_id, "target": target, "tags": tags or [],
            },
        )
        resp.raise_for_status()
        return resp.json()

    def promote_observations(self, engagement_id: str, *, run_id: str = "") -> dict[str, Any]:
        resp = self._client.post(
            self._url("/api/v1/findings/promote"), params={"engagement_id": engagement_id, "run_id": run_id},
        )
        resp.raise_for_status()
        return resp.json()

    # --- Observations (plans/harness/02-evidence-and-observation-layer.md) ---
    def list_observations(
        self, engagement_id: str, *, observation_type: str = "", target: str = "", limit: int = 200,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"engagement_id": engagement_id, "limit": limit}
        if observation_type:
            params["type"] = observation_type
        if target:
            params["target"] = target
        resp = self._client.get(self._url("/api/v1/observations/"), params=params)
        resp.raise_for_status()
        return resp.json()

    def get_observation(self, observation_id: str) -> dict[str, Any]:
        resp = self._client.get(self._url(f"/api/v1/observations/{observation_id}"))
        resp.raise_for_status()
        return resp.json()

    # --- World model (plans/harness/05-world-model-and-attack-paths.md Step 2) ---
    def world_model_assets(self, engagement_id: str, *, asset_type: str = "") -> dict[str, Any]:
        params: dict[str, Any] = {"engagement_id": engagement_id}
        if asset_type:
            params["asset_type"] = asset_type
        resp = self._client.get(self._url("/api/v1/reasoning/assets"), params=params)
        resp.raise_for_status()
        return resp.json()

    def world_model_related(self, engagement_id: str, asset_id: str, *, max_hops: int = 2) -> dict[str, Any]:
        resp = self._client.get(
            self._url("/api/v1/reasoning/related"),
            params={"engagement_id": engagement_id, "asset_id": asset_id, "max_hops": max_hops},
        )
        resp.raise_for_status()
        return resp.json()

    def world_model_incomplete(self, engagement_id: str) -> dict[str, Any]:
        resp = self._client.get(self._url("/api/v1/reasoning/incomplete"), params={"engagement_id": engagement_id})
        resp.raise_for_status()
        return resp.json()

    def world_model_unexplained(self, engagement_id: str) -> dict[str, Any]:
        resp = self._client.get(self._url("/api/v1/reasoning/unexplained"), params={"engagement_id": engagement_id})
        resp.raise_for_status()
        return resp.json()

    def world_model_conflicts(self, engagement_id: str) -> dict[str, Any]:
        resp = self._client.get(self._url("/api/v1/reasoning/conflicts"), params={"engagement_id": engagement_id})
        resp.raise_for_status()
        return resp.json()

    # --- Attack paths (plans/harness/05-world-model-and-attack-paths.md Step 3) ---
    def propose_attack_path(self, engagement_id: str, *, title: str, steps: list[dict[str, Any]]) -> dict[str, Any]:
        resp = self._client.post(
            self._url("/api/v1/reasoning/attack-paths"),
            json={"engagement_id": engagement_id, "title": title, "steps": steps},
        )
        resp.raise_for_status()
        return resp.json()

    def list_attack_paths(self, engagement_id: str, *, active_only: bool = True) -> dict[str, Any]:
        resp = self._client.get(
            self._url("/api/v1/reasoning/attack-paths"),
            params={"engagement_id": engagement_id, "active_only": active_only},
        )
        resp.raise_for_status()
        return resp.json()

    def get_attack_path(self, path_id: str) -> dict[str, Any]:
        resp = self._client.get(self._url(f"/api/v1/reasoning/attack-paths/{path_id}"))
        resp.raise_for_status()
        return resp.json()

    def advance_attack_path(
        self, path_id: str, *, status: str = "", finding_id: str = "", step: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"finding_id": finding_id}
        if status:
            body["status"] = status
        if step:
            body["step"] = step
        resp = self._client.post(self._url(f"/api/v1/reasoning/attack-paths/{path_id}/advance"), json=body)
        resp.raise_for_status()
        return resp.json()

    # --- Questions (plans/harness/05-world-model-and-attack-paths.md Step 4) ---
    def raise_question(
        self, engagement_id: str, *, text: str, raised_by: str = "operator", related_asset_id: str = "",
    ) -> dict[str, Any]:
        resp = self._client.post(
            self._url("/api/v1/reasoning/questions"),
            params={"engagement_id": engagement_id, "text": text, "raised_by": raised_by, "related_asset_id": related_asset_id},
        )
        resp.raise_for_status()
        return resp.json()

    def list_questions(self, engagement_id: str, *, open_only: bool = True) -> dict[str, Any]:
        resp = self._client.get(
            self._url("/api/v1/reasoning/questions"), params={"engagement_id": engagement_id, "open_only": open_only},
        )
        resp.raise_for_status()
        return resp.json()

    def answer_question(self, question_id: str, *, answer_text: str) -> dict[str, Any]:
        resp = self._client.post(
            self._url(f"/api/v1/reasoning/questions/{question_id}/answer"), params={"answer_text": answer_text},
        )
        resp.raise_for_status()
        return resp.json()

    def dismiss_question(self, question_id: str) -> dict[str, Any]:
        resp = self._client.post(self._url(f"/api/v1/reasoning/questions/{question_id}/dismiss"))
        resp.raise_for_status()
        return resp.json()

    # --- Hypotheses (plans/harness/05-world-model-and-attack-paths.md Step 4) ---
    def raise_hypothesis(
        self, engagement_id: str, *, statement: str, supporting_observation_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        params = [("engagement_id", engagement_id), ("statement", statement)]
        params += [("supporting_observation_ids", oid) for oid in (supporting_observation_ids or [])]
        resp = self._client.post(self._url("/api/v1/reasoning/hypotheses"), params=params)
        resp.raise_for_status()
        return resp.json()

    def list_hypotheses(self, engagement_id: str, *, active_only: bool = True) -> dict[str, Any]:
        resp = self._client.get(
            self._url("/api/v1/reasoning/hypotheses"), params={"engagement_id": engagement_id, "active_only": active_only},
        )
        resp.raise_for_status()
        return resp.json()

    def add_hypothesis_evidence(self, hypothesis_id: str, *, observation_id: str, supports: bool) -> dict[str, Any]:
        resp = self._client.post(
            self._url(f"/api/v1/reasoning/hypotheses/{hypothesis_id}/evidence"),
            params={"observation_id": observation_id, "supports": supports},
        )
        resp.raise_for_status()
        return resp.json()

    def resolve_hypothesis(self, hypothesis_id: str, *, status: str) -> dict[str, Any]:
        resp = self._client.post(
            self._url(f"/api/v1/reasoning/hypotheses/{hypothesis_id}/resolve"), params={"status": status},
        )
        resp.raise_for_status()
        return resp.json()

    # --- Priority (plans/harness/06-prioritization-engine.md) ---
    def top_priorities(self, engagement_id: str, *, kinds: str = "observation,asset,question,attack_path", limit: int = 20) -> dict[str, Any]:
        resp = self._client.get(
            self._url("/api/v1/priority/top"), params={"engagement_id": engagement_id, "kinds": kinds, "limit": limit},
        )
        resp.raise_for_status()
        return resp.json()

    def phase_priority(self, engagement_id: str, phase: str) -> dict[str, Any]:
        resp = self._client.get(
            self._url(f"/api/v1/priority/phase/{phase}"), params={"engagement_id": engagement_id},
        )
        resp.raise_for_status()
        return resp.json()

    # --- Context packet (plans/harness/07-context-packet.md) ---
    def get_context_packet(self, engagement_id: str) -> str:
        resp = self._client.get(self._url("/api/v1/context/packet"), params={"engagement_id": engagement_id})
        resp.raise_for_status()
        return resp.json().get("packet", "")

    # --- Skills (plans/harness/08-skill-system-at-scale.md) ---
    def list_skills_index(self, *, phase: str = "") -> dict[str, Any]:
        resp = self._client.get(self._url("/api/v1/capabilities/skills-index"), params={"phase": phase})
        resp.raise_for_status()
        return resp.json()

    def find_skills(
        self, *, query: str = "", phase: str = "", tags: str = "", mitre: str = "",
        nist_csf: str = "", domain: str = "", asset_type: str = "", limit: int = 8,
    ) -> dict[str, Any]:
        resp = self._client.get(
            self._url("/api/v1/capabilities/skills-find"),
            params={
                "query": query, "phase": phase, "tags": tags, "mitre": mitre,
                "nist_csf": nist_csf, "domain": domain, "asset_type": asset_type, "limit": limit,
            },
        )
        resp.raise_for_status()
        return resp.json()

    def get_skill_file(self, path: str) -> dict[str, Any]:
        resp = self._client.get(self._url("/api/v1/capabilities/skills-file"), params={"path": path})
        resp.raise_for_status()
        return resp.json()

    # --- Operator memory: graph links + reasoned findings ---
    def graph_link(
        self, *, engagement_id: str, source: str, target: str, relation: str, evidence: str,
        confidence: str = "likely", run_id: str = "", derived_from: str = "",
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "engagement_id": engagement_id, "run_id": run_id, "seed_target": "",
            "source": source, "target": target, "relation": relation,
            "evidence": evidence, "confidence": confidence,
        }
        if derived_from:
            body["derived_from"] = derived_from
        resp = self._client.post(self._url("/api/v1/hybrid/graph/link"), json=body)
        resp.raise_for_status()
        return resp.json()

    def record_observation(
        self, *, engagement_id: str, type: str, target: str = "", details: dict[str, Any] | None = None,
        source_tool: str = "operator_record", tags: list[str] | None = None, extracted_by: str = "llm",
    ) -> dict[str, Any]:
        resp = self._client.post(
            self._url("/api/v1/observations/"),
            json={
                "engagement_id": engagement_id, "type": type, "target": target,
                "details": details or {}, "source_tool": source_tool, "tags": tags or [],
                "extracted_by": extracted_by,
            },
        )
        resp.raise_for_status()
        return resp.json()

    def record_finding(
        self, *, engagement_id: str, title: str, evidence: str, finding_type: str = "observation",
        claim_severity: str = "none", description: str = "", source_tool: str = "operator_record",
        target: str = "", tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Record a reasoned conclusion — no prior Observation exists for it.
        Two calls under the hood (record_observation, then file_finding),
        same as platform_record_finding: confidence is computed from the
        attestation evidence, never asserted by the caller."""
        obs = self.record_observation(
            engagement_id=engagement_id, type="raw", target=target,
            details={"title": title, "description": description}, source_tool=source_tool,
            tags=tags or ["operator_recorded"],
        )
        return self.file_finding(
            engagement_id=engagement_id, title=title, finding_type=finding_type,
            observation_ids=[obs["id"]], claim_severity=claim_severity, description=description,
            evidence_records=[{"kind": "attestation", "source_tool": source_tool, "detail": evidence}],
            target=target, tags=tags or ["operator_recorded"],
        )

    # --- Benchmark harness (plans/harness/01-replay-benchmark-harness.md) ---
    def benchmark_list_fixtures(self) -> dict[str, Any]:
        resp = self._client.get(self._url("/api/v1/benchmark/fixtures"))
        resp.raise_for_status()
        return resp.json()

    def benchmark_install_builtin_fixtures(self) -> dict[str, Any]:
        resp = self._client.post(self._url("/api/v1/benchmark/fixtures/install-builtin"))
        resp.raise_for_status()
        return resp.json()

    def benchmark_record(self, *, engagement_id: str, name: str, target: str = "") -> dict[str, Any]:
        resp = self._client.post(
            self._url("/api/v1/benchmark/record"),
            json={"engagement_id": engagement_id, "name": name, "target": target},
        )
        resp.raise_for_status()
        return resp.json()

    def benchmark_run(self, fixture: str) -> dict[str, Any]:
        resp = self._client.post(self._url("/api/v1/benchmark/run"), json={"fixture": fixture})
        resp.raise_for_status()
        return resp.json()

    def benchmark_diff(self, baseline_run_id: str, candidate_run_id: str) -> dict[str, Any]:
        resp = self._client.get(
            self._url("/api/v1/benchmark/diff"),
            params={"baseline": baseline_run_id, "candidate": candidate_run_id},
        )
        resp.raise_for_status()
        return resp.json()

    # --- Operator profile (the human operator's preferences) ---
    def operator_profile(self) -> dict[str, Any]:
        resp = self._client.get(self._url("/api/v1/capabilities/operator-profile"))
        resp.raise_for_status()
        return resp.json()

    def add_operator_preference(self, preference: str) -> dict[str, Any]:
        resp = self._client.post(
            self._url("/api/v1/capabilities/operator-profile/add"),
            json={"preference": preference},
        )
        resp.raise_for_status()
        return resp.json()

    def approve_operator_preference(self, proposal_id: str) -> dict[str, Any]:
        resp = self._client.post(
            self._url(f"/api/v1/capabilities/operator-profile/{proposal_id}/approve")
        )
        resp.raise_for_status()
        return resp.json()

    def reject_operator_preference(self, proposal_id: str) -> dict[str, Any]:
        resp = self._client.delete(
            self._url(f"/api/v1/capabilities/operator-profile/{proposal_id}")
        )
        resp.raise_for_status()
        return resp.json()

    def start_expansion_job(
        self, engagement_id: str, *, run_id: str = "", max_passes: int = 5,
        include_low_confidence: bool = False,
    ) -> dict[str, Any]:
        """Engine mode: run the no-LLM InvestigationDirector as a background
        job (plans/harness/09-dual-mode-planner.md) — same job kind/endpoint
        the MCP `platform_expand` tool and the auto-fire-on-bind path use;
        the CLI is just another caller. Always does recon breadth AND, once
        priority.should_unlock_phase says there's real evidence to work
        with, vuln dispatch too — no caller-supplied boolean needed anymore;
        the director decides from the same priority signal either way."""
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

    def _iter_sse_lines(self, resp: httpx.Response) -> Iterator[tuple[str, dict[str, Any]]]:
        """Shared SSE line-parser — both the per-message stream and the
        persistent events stream speak the same `event:`/`data:` wire format."""
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
                    yield event_type, data
                continue
            if line.startswith("event:"):
                event_type = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].strip())
        if data_lines:
            yield event_type, json.loads("".join(data_lines))

    def stream_events(self, engagement_id: str) -> Iterator[tuple[str, dict[str, Any]]]:
        """The persistent live-activity stream for one engagement — opened
        ONCE and kept open for as long as the session cares about it, unlike
        a per-message request. Shows every background pipeline / spawned
        phase agent's tool calls as they happen (the CLI's own foreground
        loop, cli/agent/loop.py, renders its own turn directly and doesn't
        need this), tagged by `source` in each event's data — the
        fix for "background work is invisible": a harness has exactly one
        live activity feed, this is it. No read timeout — the connection is
        meant to sit open indefinitely; the caller decides when to stop
        iterating (e.g. the engagement changed, or the CLI is exiting).
        """
        try:
            with self._client.stream(
                "GET",
                self._url(f"/api/v1/agent/events/{engagement_id}"),
                timeout=httpx.Timeout(None, connect=30.0),
            ) as resp:
                resp.raise_for_status()
                yield from self._iter_sse_lines(resp)
        except httpx.HTTPStatusError as exc:
            yield "error", {"message": f"Event stream failed: {exc.response.status_code}"}
        except httpx.TransportError:
            # Backend restarted / connection dropped — let the caller decide
            # whether to reconnect; never raise into a background listener.
            return

    def get_agent_status(self) -> dict[str, Any]:
        try:
            resp = self._client.get(self._url("/api/v1/agent/status"))
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError:
            return {}

    def reset_conversation(self) -> None:
        """Clear the CLI's own agent conversation. Actually resets now — the
        old version only cleared a local mirror while the backend's own
        conversation thread stayed intact, so a follow-up prompt silently
        kept the "reset" history. There is no server-side thread anymore:
        the CLI's Runner (cli/agent/loop.py) is the one place conversation
        state lives, so clearing it here is a real, complete reset."""
        if self.agent_runner is not None:
            self.agent_runner.reset()
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
        loop = getattr(self, "agent_loop", None)
        if loop is not None and not loop.is_closed():
            loop.close()
