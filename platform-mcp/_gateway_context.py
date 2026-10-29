"""Gateway tools — context group (registers on _core.mcp)."""

from __future__ import annotations

import json
from typing import Any

import _gateway_core as _core
from _gateway_core import HTTP_TIMEOUT, _EngagementContext, _analyze_or_bind, _block, _client, _ctx_delta, _get, _memory_params, _post, _resolve_engagement, _safe, _session_header, mcp




def _fetch_context(context: _EngagementContext | None = None, *, full: bool = False) -> str:
    ctx = context or _resolve_engagement()
    eid = ctx.engagement_id
    tgt = ctx.target
    data = _get(
        "/api/v1/hybrid/context/auto",
        params={"engagement_id": eid, "seed_target": tgt},
    )

    # Jobs: compact one-liner from backend (config-driven max slots)
    jobs_line = (data.get("jobs_line") or "").strip()
    if not jobs_line:
        jobs = data.get("background_jobs") or []
        running = sum(1 for j in jobs if str(j.get("status") or "") in ("queued", "running"))
        jobs_line = f"jobs: {running}/? running"
        if jobs:
            labels = [
                f"{j.get('label') or j.get('tool_name') or j.get('kind')}"
                for j in jobs[:6]
                if str(j.get("status") or "") in ("queued", "running")
            ]
            if labels:
                jobs_line = f"jobs: {running}/? running [{', '.join(str(x) for x in labels)}]"

    idx = data.get("stdout_index") or {}
    idx_text = (idx.get("text") if isinstance(idx, dict) else "") or ""
    pipeline_line = (data.get("pipeline_line") or "").strip()
    readiness_text = data.get("phase_readiness_text") or ""

    parts = [_session_header(ctx), f"**Jobs:** {jobs_line}"]
    if pipeline_line:
        parts.append(f"**Pipeline:** {pipeline_line}")
    # Operator profile — the human's confirmed preferences. Placed high so any
    # driver (this CLI or an external harness) adapts to how the operator works.
    operator_profile = (data.get("operator_profile") or "").strip()
    if operator_profile:
        parts.append("**Operator profile — adapt to these preferences:**\n" + operator_profile)

    # The context packet (plans/harness/07-context-packet.md) — world-model,
    # priority, coverage, questions/hypotheses/attack-paths, recent evidence,
    # tools-already-run and RoE constraints, rebuilt fresh from stores every
    # call. Supersedes the old Finding-era network-surface/attack-surface-
    # tree/findings-summary/dispatch-rules sections it replaces below: those
    # were pre-Plan02/03 views built from Finding verdicts, not Observations;
    # everything they showed is available here with better provenance.
    if eid:
        packet = _get("/api/v1/context/packet", params={"engagement_id": eid}, timeout=30).get("packet", "")
    else:
        packet = "no engagement bound"
    parts.append(_ctx_delta(eid, "context_packet", packet, full=full, label="Context packet"))

    parts += [
        _ctx_delta(
            eid,
            "phase_readiness",
            "**Phase status (conductor) — spawn instructions:**\n" + (readiness_text or "(no engagement bound)"),
            full=full,
            label="Phase status",
        ),
        _ctx_delta(
            eid,
            "recent_artifacts",
            "**Recent artifacts:**\n" + (idx_text if idx_text else "(none — run a tool first)"),
            full=full,
            label="Recent artifacts",
        ),
    ]
    # Role guidance: short operator-mindset reminder — full skill text on demand via platform_skills
    rg = (data.get("role_guidance") or "").strip()
    if rg:
        parts.append(
            _ctx_delta(
                eid,
                "role_guidance",
                _block("Role guidance", rg[:700] + ("…" if len(rg) > 700 else "")),
                full=full,
                label="Role guidance",
            )
        )
    # Skills index: names + paths only — call platform_skills(path=...) to read one in full
    si = (data.get("skills_index") or "").strip()
    if si:
        parts.append(
            _ctx_delta(
                eid,
                "skills_index",
                _block("Skills available", si[:900] + ("…" if len(si) > 900 else "")),
                full=full,
                label="Skills available",
            )
        )

    parts.append(
        "---\n"
        "You decide the next probe. Phase status is evidence-based data, not an order — "
        "recon is always active, vuln/exploit unlock when they have real evidence to work with. "
        "Use platform_tools / platform_skills / platform_findings / platform_artifact "
        "only when you need detail. "
        "platform_graph_link_many (bulk — one call for a whole tool run's relationships) "
        "/ platform_graph_link / platform_script when inventing."
    )
    return "\n\n---\n\n".join(parts)


@mcp.tool()
def platform_context(target: str = "", engagement_id: str = "", full: bool = False) -> str:
    """
    Compact briefing from evidence: phase status, jobs, delta.

    Large, slow-changing sections (network surface, attack-surface tree, findings
    brief, role guidance, skills index) collapse to a one-line
    "unchanged" placeholder when identical to your previous context call, to save
    context. Pass full=true to expand every section.

    Call this not just to plan the next probe, but whenever you're stuck — a
    tool keeps failing, or you're unsure what to try next. Memory may already
    hold the answer.

    No phase argument. Pass target= only to analyze/switch.
    Pull details on demand: platform_tools, platform_skills, platform_findings.

    engagement_id: optional pin to a specific engagement (bypasses the shared
    ambient session without switching it) — see platform_exec. Ignored if
    target= is set, since target= always switches/binds first.
    """
    def _run() -> str:
        if target.strip():
            clarified = _analyze_or_bind(target)
            if clarified.startswith("## Target needs clarification"):
                return clarified
            # A fresh target bind is a first look — always render in full.
            return _fetch_context(full=True)
        return _fetch_context(_resolve_engagement(engagement_id), full=full)

    return _safe(_run)


@mcp.tool()
def platform_think(
    hypothesis: str,
    plan: str = "",
    evidence: str = "",
    next_tool: str = "",
    engagement_id: str = "",
) -> str:
    """
    Optional: persist a hypothesis into engagement memory (and mirror to operator).

    Not required before tools — use when a pivot needs a durable note. Prefer chat
    narration for routine moves. Stored as unverified observation (not proof).
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id) if engagement_id or _core._SESSION_ENGAGEMENT_ID else None
        parts = [
            "### OPERATOR MIRROR — THINKING",
            _session_header(ctx) if ctx else "(no engagement bound yet)",
            f"**Hypothesis:** {hypothesis.strip() or '(empty)'}",
        ]
        if plan.strip():
            parts.append(f"**Plan:** {plan.strip()}")
        if evidence.strip():
            parts.append(f"**Evidence so far:** {evidence.strip()}")
        if next_tool.strip():
            parts.append(f"**Next tool:** `{next_tool.strip()}`")
        if ctx and hypothesis.strip():
            data = _post(
                "/api/v1/hybrid/think",
                {
                    "engagement_id": ctx.engagement_id,
                    "run_id": ctx.run_id,
                    "hypothesis": hypothesis.strip(),
                    "plan": plan.strip(),
                    "evidence": evidence.strip(),
                    "next_tool": next_tool.strip(),
                },
                timeout=30,
            )
            parts.append(
                f"\nStored hypothesis_id=`{data.get('hypothesis_id')}` — "
                "visible via platform_hypothesis(action='list') / the context packet."
            )
        else:
            parts.append("\n(No engagement bound — not persisted. Call platform_set_target first.)")
        return "\n".join(parts)

    return _safe(_run)


@mcp.tool()
def platform_graph_link(
    source: str,
    target: str,
    relation: str,
    evidence: str,
    confidence: str = "likely",
    derived_from: str = "",
    engagement_id: str = "",
) -> str:
    """
    Create an operator-named graph edge (cognition write-back).

    source/target: 'host:erp.x.com' or bare hostname/IP/URL.
    relation: free name (e.g. same_app_as, shares_auth_cookie).
    confidence: confirmed|likely|hypothesis — non-confirmed becomes hypothesis_* edge
    (not proof for COMPLETE/CRITICAL). evidence= required (why the link exists).
    derived_from: optional comma-separated finding ids this link builds on.
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        body: dict[str, Any] = {
            "engagement_id": ctx.engagement_id,
            "run_id": ctx.run_id,
            "source": source,
            "target": target,
            "relation": relation,
            "evidence": evidence,
            "confidence": confidence,
        }
        if (derived_from or "").strip():
            body["derived_from"] = derived_from.strip()
        data = _post("/api/v1/hybrid/graph/link", body, timeout=30)
        return "\n".join(
            [
                "### OPERATOR MIRROR — GRAPH LINK",
                _session_header(ctx),
                f"**{data.get('source_id')}** --`{data.get('relationship')}`--> "
                f"**{data.get('target_id')}**",
                f"confidence={data.get('confidence')} hypothesis={data.get('hypothesis')} "
                f"derived_from={data.get('derived_from') or []}",
                data.get("hint") or "",
            ]
        )

    return _safe(_run)


@mcp.tool()
def platform_graph_link_many(
    evidence: str = "",
    confidence: str = "likely",
    source: str = "",
    relation: str = "",
    targets_json: Any = "[]",
    links_json: Any = "[]",
    derived_from: str = "",
    engagement_id: str = "",
) -> str:
    """
    Persist MANY operator-named graph edges in ONE call — the bulk sibling of
    platform_graph_link.

    Use this instead of calling platform_graph_link N times (e.g. after subfinder
    returns 35 subdomains, or dnsx resolves 30 IPs). The platform does not
    hardcode which relations exist — you still name every relation — this only
    removes the per-edge round-trip so persisting an entire tool run's findings
    is cheap enough to actually do, every time, not just when told to.

    Two ways to pass edges (combine freely):
      - Fan form: source= + relation= + targets_json=[...] — one source, many
        targets sharing the same relation/evidence/confidence. Example:
        source="domain:example.com", relation="has_subdomain",
        targets_json=["subdomain:a.example.com","subdomain:b.example.com"]
      - List form: links_json=[{"source":..,"target":..,"relation":..,
        "evidence":.. (optional, else shared evidence=),
        "confidence":.. (optional, else shared confidence=)}, ...] —
        independent edges with different relations in one call (e.g. a mixed
        batch of resolves_to + runs_tech + co_hosts from one recon pass).

    confidence: confirmed|likely|hypothesis — non-confirmed becomes
    hypothesis_* edges (not proof for COMPLETE/CRITICAL) per edge, same as the
    single-edge tool. evidence= required unless every links_json item supplies
    its own. derived_from: optional comma-separated finding ids shared by all
    edges in this call.
    """
    def _parse_list(raw: Any) -> list:
        if isinstance(raw, list):
            return raw
        if isinstance(raw, str):
            s = raw.strip()
            if not s:
                return []
            try:
                data = json.loads(s)
                return data if isinstance(data, list) else []
            except json.JSONDecodeError:
                return [x.strip() for x in s.replace(",", "\n").splitlines() if x.strip()]
        return []

    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        targets = _parse_list(targets_json)
        links = _parse_list(links_json)
        body: dict[str, Any] = {
            "engagement_id": ctx.engagement_id,
            "run_id": ctx.run_id,
            "evidence": evidence,
            "confidence": confidence,
            "source": source,
            "relation": relation,
            "targets": [str(t).strip() for t in targets if str(t).strip()],
            "links": [x for x in links if isinstance(x, dict)],
        }
        if (derived_from or "").strip():
            body["derived_from"] = derived_from.strip()
        data = _post("/api/v1/hybrid/graph/link-many", body, timeout=45)
        lines = [
            "### OPERATOR MIRROR — BULK GRAPH LINK",
            _session_header(ctx),
            f"Persisted {data.get('count', 0)} edge(s): "
            f"{data.get('confirmed_count', 0)} asserted, "
            f"{data.get('hypothesis_count', 0)} hypothesis.",
        ]
        for e in (data.get("edges") or [])[:8]:
            lines.append(f"  {e.get('source')} --`{e.get('relationship')}`--> {e.get('target')}")
        if data.get("count", 0) > 8:
            lines.append(f"  …(+{data['count'] - 8} more)")
        lines.append(data.get("hint") or "")
        return "\n".join(lines)

    return _safe(_run)


@mcp.tool()
def platform_memory_search(query: str, limit: int = 40, engagement_id: str = "") -> str:
    """
    Free-text search across engagement memory (findings, graph nodes, attempts).

    Use when you need to find a host, path, CVE string, cookie domain, or past try
    without dumping everything. You interpret hits — this is not a playbook.
    """
    if not (query or "").strip():
        return "ERROR: query is required (e.g. 'erp', '/api', 'Set-Cookie', 'amass')"

    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        data = _get(
            "/api/v1/hybrid/memory-search",
            params={
                **_memory_params(ctx),
                "q": query.strip(),
                "limit": max(5, min(int(limit), 80)),
            },
            timeout=45,
        )
        return (
            f"{_session_header(ctx)}\n\n"
            f"{data.get('text') or ''}\n\n"
            f"_{data.get('note') or ''}_"
        )

    return _safe(_run)


@mcp.tool()
def platform_related(limit: int = 20, engagement_id: str = "") -> str:
    """
    Read-only cross-finding correlation — candidate relationships from memory.

    Returns HYPOTHESES the platform noticed (hosts on one IP with matching page
    titles, hosts sharing a Set-Cookie domain) so you don't have to eyeball the
    whole findings list to spot them. Nothing here is written to the graph.
    Commit the ones you judge real with platform_graph_link; ignore the rest.
    Naturally useful right after a batch of findings lands, or before deciding
    where to dig next.
    """

    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        data = _post("/api/v1/hybrid/correlate", dict(_memory_params(ctx)), timeout=45)
        cands = data.get("candidates") or []
        if not cands:
            return f"{_session_header(ctx)}\n\nNo cross-finding correlations right now."
        lines: list[str] = []
        for c in cands[: max(1, min(int(limit), 60))]:
            if c.get("kind") == "link":
                lines.append(
                    f"LINK  {c.get('source')} --{c.get('relation')}--> {c.get('target')}  "
                    f"[{c.get('confidence')}, score={c.get('score')}]  {c.get('evidence')}"
                )
            else:
                lines.append(
                    f"TAG   {c.get('asset')}  role={c.get('role')} boost={c.get('boost')}  "
                    f"{c.get('evidence')}"
                )
        return (
            f"{_session_header(ctx)}\n\n"
            + "\n".join(lines)
            + f"\n\n_{data.get('note') or ''}_"
        )

    return _safe(_run)


@mcp.tool()
def platform_evidence_chain(
    finding_id: str, depth: int = 4, engagement_id: str = ""
) -> str:
    """
    Walk derived_from parents and children for one finding id.

    Use after graph_link/record_finding with derived_from=, or to explain how a
    claim was built. Soft structure — not a severity upgrade.
    """
    if not (finding_id or "").strip():
        return "ERROR: finding_id required"

    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        data = _get(
            "/api/v1/hybrid/evidence-chain",
            params={
                **_memory_params(ctx),
                "finding_id": finding_id.strip(),
                "depth": max(1, min(int(depth), 8)),
            },
            timeout=30,
        )
        if not data.get("ok"):
            return f"ERROR: {data.get('error') or data}"
        return (
            f"{_session_header(ctx)}\n\n"
            f"{data.get('text') or ''}\n\n"
            f"_{data.get('note') or ''}_"
        )

    return _safe(_run)


@mcp.tool()
def platform_attempts(
    asset: str = "", contains: str = "", limit: int = 40, engagement_id: str = ""
) -> str:
    """
    Advisory history of tools already tried near an asset (or engagement-wide).

    Data only — not a ban. Re-run with new params, force_refresh, job, or script
    whenever the experiment still makes sense.

    platform_context already shows a TOOLS ALREADY RUN summary every call —
    reach for THIS tool when you need it filtered to one asset=, or the
    notes/success detail the summary leaves out.
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        params = {**_memory_params(ctx), "limit": max(1, min(int(limit), 100))}
        if (asset or "").strip():
            params["asset"] = asset.strip()
        if (contains or "").strip():
            params["contains"] = contains.strip()
        data = _get("/api/v1/hybrid/attempts", params=params, timeout=30)
        return (
            f"{_session_header(ctx)}\n\n"
            f"{data.get('text') or ''}\n\n"
            f"_{data.get('note') or ''}_"
        )

    return _safe(_run)


@mcp.tool()
def platform_world_model(view: str, asset_id: str = "", asset_type: str = "", engagement_id: str = "") -> str:
    """
    Query the world model — plans/harness/05-world-model-and-attack-paths.md
    Step 2. A read model over the observation-backed graph, not a new store.

    view: assets | related | incomplete | unexplained | conflicts
      - assets: every asset node (optionally asset_type=host|port|service|…).
      - related: what connects to asset_id, closest first (undirected walk).
      - incomplete: HOST/SUBDOMAIN assets with no port evidence yet — raw
        material for "what haven't we scanned".
      - unexplained: observations not yet tied to any graph asset — raw
        material for a question/hypothesis (platform_question/platform_hypothesis).
      - conflicts: assets with a disputed slot (Step 2a, e.g. service@443
        nginx vs Apache) — both values kept, never silently picked.

    platform_context's WORLD MODEL SUMMARY and COVERAGE sections already
    cover a grouped/truncated view=assets and view=incomplete every call —
    reach for THIS tool when you need the full untruncated list, one
    asset_type= filter, or view=related/unexplained (not in context at all).
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        eid = ctx.engagement_id
        v = view.strip().lower()
        if v == "assets":
            params: dict[str, Any] = {"engagement_id": eid}
            if asset_type.strip():
                params["asset_type"] = asset_type.strip().lower()
            data = _get("/api/v1/reasoning/assets", params=params, timeout=30)
            items = data.get("assets") or []
            lines = [
                f"- {a['id']} confidence={a['confidence']} tools={a.get('source_tools')}"
                for a in items[:80]
            ]
        elif v == "related":
            if not asset_id.strip():
                return "ERROR: view='related' requires asset_id (e.g. 'host:example.com')."
            data = _get(
                "/api/v1/reasoning/related",
                params={"engagement_id": eid, "asset_id": asset_id.strip()}, timeout=30,
            )
            items = data.get("related") or []
            lines = [f"- {r['node_id']} ({r['hops']} hop via {r['via_relationship']})" for r in items[:80]]
        elif v == "incomplete":
            data = _get("/api/v1/reasoning/incomplete", params={"engagement_id": eid}, timeout=30)
            items = data.get("assets") or []
            lines = [f"- {a['asset_id']}: {a['gap']}" for a in items[:80]]
        elif v == "unexplained":
            data = _get("/api/v1/reasoning/unexplained", params={"engagement_id": eid}, timeout=30)
            items = data.get("observations") or []
            lines = [f"- {o['observation_id']} [{o['type']}] target={o['target']} via {o['source_tool']}" for o in items[:80]]
        elif v == "conflicts":
            data = _get("/api/v1/reasoning/conflicts", params={"engagement_id": eid}, timeout=30)
            items = data.get("conflicts") or []
            lines = [
                f"- {c['asset_id']}: " + "; ".join(
                    f"{slot}={[v['value'] for v in vals]}" for slot, vals in c["conflicts"].items()
                )
                for c in items[:80]
            ]
        else:
            return "ERROR: view must be one of assets|related|incomplete|unexplained|conflicts."
        return (
            "### OPERATOR MIRROR — WORLD MODEL\n"
            f"{_session_header(ctx)}\n"
            f"view={v} count={len(items)}\n"
            + ("\n".join(lines) if lines else "(none)")
        )

    return _safe(_run)


@mcp.tool()
def platform_attack_path(
    action: str,
    title: str = "",
    path_id: str = "",
    step_kind: str = "observation",
    step_ref_id: str = "",
    step_rationale: str = "",
    status: str = "",
    finding_id: str = "",
    engagement_id: str = "",
) -> str:
    """
    Attack path — a first-class reasoning object (plans/harness/05-world-
    model-and-attack-paths.md Step 3): an ordered chain of
    (observation|asset|hypothesis) steps with a rationale per hop, e.g.
    public API endpoint -> internal endpoint reference (observation) ->
    different authz boundary (observation) -> cross-user access (hypothesis).

    action: propose | advance | list
      - propose: title= + one step (step_kind/step_ref_id/step_rationale).
        Add more hops later via action=advance.
      - advance: path_id= required. Any of: status=investigating|validated|dead,
        finding_id=<id> (once a PoC validates the chain), or a new step
        (step_ref_id set) to append another hop.
      - list: active (hypothesized/investigating) paths for this engagement.
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        eid = ctx.engagement_id
        a = action.strip().lower()
        if a == "propose":
            if not title.strip() or not step_ref_id.strip():
                return "ERROR: propose requires title= and step_ref_id= (the first hop)."
            body = {
                "engagement_id": eid, "title": title.strip(),
                "steps": [{"kind": step_kind.strip().lower(), "ref_id": step_ref_id.strip(), "rationale": step_rationale.strip()}],
            }
            data = _post("/api/v1/reasoning/attack-paths", body, timeout=30)
            return (
                "### OPERATOR MIRROR — ATTACK PATH PROPOSED\n"
                f"{_session_header(ctx)}\nid={data.get('id')} status={data.get('status')}\n"
                "platform_attack_path(action='advance', path_id=..., step_ref_id=...) to add hops."
            )
        if a == "advance":
            if not path_id.strip():
                return "ERROR: advance requires path_id="
            body: dict[str, Any] = {"finding_id": finding_id.strip()}
            if status.strip():
                body["status"] = status.strip().lower()
            if step_ref_id.strip():
                body["step"] = {"kind": step_kind.strip().lower(), "ref_id": step_ref_id.strip(), "rationale": step_rationale.strip()}
            resp = _client().post(f"/api/v1/reasoning/attack-paths/{path_id.strip()}/advance", json=body, timeout=min(30.0, HTTP_TIMEOUT))
            if resp.status_code == 404:
                return f"ERROR: no attack path with id '{path_id}'."
            resp.raise_for_status()
            data = resp.json()
            return (
                "### OPERATOR MIRROR — ATTACK PATH ADVANCED\n"
                f"{_session_header(ctx)}\nid={data.get('id')} status={data.get('status')} "
                f"hops={len(data.get('steps') or [])}"
            )
        if a == "list":
            data = _get("/api/v1/reasoning/attack-paths", params={"engagement_id": eid}, timeout=30)
            paths = data.get("attack_paths") or []
            if not paths:
                return "No active attack paths. platform_world_model(view='unexplained') for raw material."
            lines = [f"- [{p['id']}] {p['status']}: {p['title']} ({len(p['steps'])} hop(s))" for p in paths]
            return "### OPERATOR MIRROR — ACTIVE ATTACK PATHS\n" + "\n".join(lines)
        return "ERROR: action must be propose|advance|list."

    return _safe(_run)


@mcp.tool()
def platform_question(
    action: str, text: str = "", question_id: str = "", answer_text: str = "",
    related_asset_id: str = "", engagement_id: str = "",
) -> str:
    """
    Open questions — the reasoning scaffold (plans/harness/05-world-model-
    and-attack-paths.md Step 4). Cheap, write freely, no approval needed.

    action: raise | answer | dismiss | list
    """
    def _run() -> str:
        eid = _resolve_engagement(engagement_id).engagement_id
        a = action.strip().lower()
        if a == "raise":
            if not text.strip():
                return "ERROR: raise requires text="
            resp = _client().post(
                "/api/v1/reasoning/questions",
                params={"engagement_id": eid, "text": text.strip(), "related_asset_id": related_asset_id.strip()},
                timeout=min(30.0, HTTP_TIMEOUT),
            )
            resp.raise_for_status()
            data = resp.json()
            return f"### OPERATOR MIRROR — QUESTION RAISED\nid={data.get('id')}: {data.get('text')}"
        if a == "answer":
            if not question_id.strip() or not answer_text.strip():
                return "ERROR: answer requires question_id= and answer_text="
            resp = _client().post(
                f"/api/v1/reasoning/questions/{question_id.strip()}/answer",
                params={"answer_text": answer_text.strip()}, timeout=min(30.0, HTTP_TIMEOUT),
            )
            if resp.status_code == 404:
                return f"ERROR: no question with id '{question_id}'."
            return f"### OPERATOR MIRROR — QUESTION ANSWERED\n{resp.json()}"
        if a == "dismiss":
            if not question_id.strip():
                return "ERROR: dismiss requires question_id="
            resp = _client().post(f"/api/v1/reasoning/questions/{question_id.strip()}/dismiss", timeout=min(30.0, HTTP_TIMEOUT))
            if resp.status_code == 404:
                return f"ERROR: no question with id '{question_id}'."
            return f"### OPERATOR MIRROR — QUESTION DISMISSED\n{question_id}"
        if a == "list":
            data = _get("/api/v1/reasoning/questions", params={"engagement_id": eid}, timeout=30)
            qs = data.get("questions") or []
            if not qs:
                return "No open questions."
            return "### OPERATOR MIRROR — OPEN QUESTIONS\n" + "\n".join(f"- [{q['id']}] {q['text']}" for q in qs)
        return "ERROR: action must be raise|answer|dismiss|list."

    return _safe(_run)


@mcp.tool()
def platform_hypothesis(
    action: str, statement: str = "", hypothesis_id: str = "", observation_id: str = "",
    supports: bool = True, status: str = "", engagement_id: str = "",
) -> str:
    """
    Active hypotheses — the reasoning scaffold (plans/harness/05-world-model-
    and-attack-paths.md Step 4). Distinct from a Finding's evidence: a
    hypothesis is an unresolved claim the reasoner is still testing.

    action: raise | evidence | resolve | list
      - evidence: hypothesis_id= + observation_id= + supports=true|false
        (attach evidence in either direction — a hypothesis can be
        strengthened OR weakened, unlike confidence_for's finding-only law).
      - resolve: hypothesis_id= + status=confirmed|refuted.
    """
    def _run() -> str:
        eid = _resolve_engagement(engagement_id).engagement_id
        a = action.strip().lower()
        if a == "raise":
            if not statement.strip():
                return "ERROR: raise requires statement="
            resp = _client().post(
                "/api/v1/reasoning/hypotheses",
                params={"engagement_id": eid, "statement": statement.strip()},
                timeout=min(30.0, HTTP_TIMEOUT),
            )
            resp.raise_for_status()
            data = resp.json()
            return f"### OPERATOR MIRROR — HYPOTHESIS RAISED\nid={data.get('id')}: {data.get('statement')}"
        if a == "evidence":
            if not hypothesis_id.strip() or not observation_id.strip():
                return "ERROR: evidence requires hypothesis_id= and observation_id="
            resp = _client().post(
                f"/api/v1/reasoning/hypotheses/{hypothesis_id.strip()}/evidence",
                params={"observation_id": observation_id.strip(), "supports": supports},
                timeout=min(30.0, HTTP_TIMEOUT),
            )
            if resp.status_code == 404:
                return f"ERROR: no hypothesis with id '{hypothesis_id}'."
            data = resp.json()
            return (
                "### OPERATOR MIRROR — HYPOTHESIS EVIDENCE ATTACHED\n"
                f"supporting={data.get('supporting_observation_ids')} "
                f"contradicting={data.get('contradicting_observation_ids')}"
            )
        if a == "resolve":
            if not hypothesis_id.strip() or status.strip().lower() not in ("confirmed", "refuted"):
                return "ERROR: resolve requires hypothesis_id= and status=confirmed|refuted"
            resp = _client().post(
                f"/api/v1/reasoning/hypotheses/{hypothesis_id.strip()}/resolve",
                params={"status": status.strip().lower()}, timeout=min(30.0, HTTP_TIMEOUT),
            )
            if resp.status_code == 404:
                return f"ERROR: no hypothesis with id '{hypothesis_id}'."
            return f"### OPERATOR MIRROR — HYPOTHESIS RESOLVED\n{resp.json()}"
        if a == "list":
            data = _get("/api/v1/reasoning/hypotheses", params={"engagement_id": eid}, timeout=30)
            hs = data.get("hypotheses") or []
            if not hs:
                return "No active hypotheses."
            return "### OPERATOR MIRROR — ACTIVE HYPOTHESES\n" + "\n".join(
                f"- [{h['id']}] {h['statement']} (support={len(h['supporting_observation_ids'])} "
                f"contra={len(h['contradicting_observation_ids'])})"
                for h in hs
            )
        return "ERROR: action must be raise|evidence|resolve|list."

    return _safe(_run)


@mcp.tool()
def platform_anomalies(engagement_id: str = "") -> str:
    """
    What looks weird right now — plans/harness/14-pentester-intelligence.md.
    Deterministic peer-comparison, no LLM: a host running much slower than
    its siblings on the same tool, or an older version of the same product
    its siblings run. Not a vuln class, just statistical surprise — the same
    "notice the outlier" instinct a senior tester applies without needing a
    rule for what's suspicious. Runs automatically after every recon pass
    already; call this when you want a fresh read right now instead of
    waiting for the next pass, or when platform_priority ranks something
    high and you want to know WHY it's flagged unexplained.

    Each result is also filed as an ordinary SCANNER_SIGNAL observation, so
    it flows through the same evidence pipeline as anything else (visible in
    platform_findings once corroborated, feeds platform_priority's
    unexplained_behavior factor).
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        data = _get("/api/v1/priority/anomalies", params={"engagement_id": ctx.engagement_id}, timeout=30)
        anomalies = data.get("anomalies") or []
        if not anomalies:
            return (
                "### OPERATOR MIRROR — ANOMALIES\n"
                f"{_session_header(ctx)}\n"
                "(nothing statistically odd yet — needs 3+ peer hosts under the same apex "
                "with comparable tool runs before an outlier means anything)"
            )
        lines = [f"- [{a.get('kind')}] {a.get('title')}" for a in anomalies]
        return (
            "### OPERATOR MIRROR — ANOMALIES\n"
            f"{_session_header(ctx)}\n"
            + "\n".join(lines)
        )

    return _safe(_run)


@mcp.tool()
def platform_graph_query(
    asset_type: str = "",
    contains: str = "",
    limit: int = 80,
    from_asset: str = "",
    max_hops: int = 0,
    engagement_id: str = "",
) -> str:
    """
    Query the engagement asset graph (not just the summary dump).

    Two modes:
    - Type/label filter (default): asset_type=subdomain|host|url|port|ip|technology|
      service|domain, contains=substring (e.g. vpn, oracle, api).
    - Multi-hop traversal: set from_asset (a hostname/IP/label, or 'type:label')
      + max_hops (1-6) instead. Walks the graph outward from that asset, undirected
      — the same way a human pentester follows relationships regardless of which
      way an edge was written — and returns everything reachable within max_hops,
      sorted closest first. Use this to answer "what's actually connected to X"
      beyond the 1-hop siblings you'd get from reading edges directly.
    """
    limit = max(1, min(int(limit), 500))
    max_hops = max(0, min(int(max_hops), 6))

    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        data = _get(
            "/api/v1/hybrid/graph/query",
            params={
                "engagement_id": ctx.engagement_id,
                "asset_type": asset_type,
                "contains": contains,
                "limit": str(limit),
                "from_asset": from_asset,
                "max_hops": str(max_hops),
            },
        )
        return "\n\n".join([_session_header(ctx), _block("Graph query", data)])

    return _safe(_run)
