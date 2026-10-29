"""Gateway tools — knowledge group (registers on _core.mcp)."""

from __future__ import annotations

import json
from typing import Any

import _gateway_core as _core
from _gateway_core import _block, _get, _log, _memory_params, _post, _resolve_engagement, _safe, _session_header, mcp
from _gateway_session import _execution_readiness_line




@mcp.tool()
def platform_artifact(
    path: str = "", offset: int = 0, limit: int = 80000, engagement_id: str = ""
) -> str:
    """
    Read a slice of a Kali artifact or a durable chat tool result (path='chat-event:<id>').
    Empty path → list recent index + workdir listing.
    path = basename or /tmp/pentest/<engagement>/….stdout.txt
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        params = dict(_memory_params(ctx))
        if not (path or "").strip():
            idx = _get("/api/v1/hybrid/stdout-index", params={**params, "limit": 8})
            listing = _get("/api/v1/hybrid/artifacts", params=params)
            return (
                f"{_session_header(ctx)}\n\n"
                f"**Index:**\n{idx.get('text') or '(empty)'}\n\n"
                f"**Workdir:** `{listing.get('workdir')}`\n"
                f"```\n{(listing.get('listing') or '')[:4000]}\n```\n"
                "Pass path= to read a file slice."
            )
        data = _get(
            "/api/v1/hybrid/artifacts/read",
            params={
                **params,
                "path": path,
                "offset": max(0, int(offset)),
                "limit": max(1, min(int(limit), 500_000)),
            },
        )
        if not data.get("ok"):
            return f"ERROR: {data.get('error') or data}"
        body = data.get("content") or ""
        return (
            f"{_session_header(ctx)}\n"
            f"path={data.get('path')} bytes={data.get('returned_bytes')}/"
            f"{data.get('total_bytes')} offset={data.get('offset')}\n"
            f"truncated={data.get('truncated')} next_offset={data.get('next_offset')}\n\n"
            f"```\n{body}\n```"
        )

    return _safe(_run)


@mcp.tool()
def platform_report_outline(engagement_id: str = "") -> str:
    """
    Structure a trusted report from memory: Confirmed / Likely / Hypotheses +
    the conductor's phase status. Call before COMPLETE or PARTIAL prose. Does
    not invent findings — only organizes what is stored.
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        data = _get(
            "/api/v1/hybrid/report-outline",
            params=_memory_params(ctx),
            timeout=45,
        )
        return (
            f"{_session_header(ctx)}\n\n"
            f"{data.get('text') or ''}\n\n"
            f"_{data.get('note') or ''}_"
        )

    return _safe(_run)


@mcp.tool()
def platform_tools(query: str = "", category: str = "", engagement_id: str = "") -> str:
    """
    List registered catalog tool names (fixes 404 from short names).

    query= filters by substring (e.g. query='dns' or 'nmap').
    category= recon|network|... optional.
    Prefer these exact names with platform_exec. Short aliases (subfinder→subfinder_scan)
    are also accepted.
    """
    def _run() -> str:
        ctx = (
            _resolve_engagement(engagement_id)
            if engagement_id or _core._SESSION_ENGAGEMENT_ID
            else None
        )
        params: dict[str, Any] = {}
        if category.strip():
            params["category"] = category.strip().lower()
        data = _get("/api/v1/tools/catalog", params=params or None, timeout=30)
        tools = data.get("tools") or []
        normalized = []
        for t in tools:
            if not isinstance(t, dict):
                continue
            name = t.get("name") or ""
            if not name and isinstance(t.get("tool"), dict):
                name = t["tool"].get("name", "")
            desc = t.get("description") or ""
            if not desc and isinstance(t.get("tool"), dict):
                desc = t["tool"].get("description", "")
            cat = t.get("category") or ""
            if not cat and isinstance(t.get("tool"), dict):
                cat = t["tool"].get("category", "")
            installed = t.get("installed")
            hint = t.get("install_hint") or ""
            if not hint and isinstance(t.get("tool"), dict):
                hint = t["tool"].get("install_hint", "")
            normalized.append(
                {
                    "name": name,
                    "description": (desc or "")[:100],
                    "category": cat,
                    "installed": installed,
                    "install_hint": (hint or "")[:160],
                }
            )
        tools = normalized
        q = query.strip().lower()
        lines = []
        for t in tools:
            name = t.get("name") or ""
            if not name:
                continue
            desc = t.get("description") or ""
            cat = t.get("category") or ""
            if q and q not in name.lower() and q not in desc.lower():
                continue
            flag = "OK" if t.get("installed") is True else (
                "MISSING" if t.get("installed") is False else "?"
            )
            # For a MISSING tool, show how to install it (hexstrike-style) so the
            # operator can answer "what else can I install for Osprey?".
            suffix = ""
            if flag == "MISSING" and t.get("install_hint"):
                suffix = f"  — install: {t['install_hint']}"
            lines.append(f"- [{flag}] {name}  [{cat}]  {desc}{suffix}")
        lines = lines[:120]
        ok_n = sum(1 for ln in lines if ln.startswith("- [OK]"))
        miss_n = sum(1 for ln in lines if ln.startswith("- [MISSING]"))
        readiness = _execution_readiness_line()
        return (
            "### OPERATOR MIRROR — TOOL CATALOG\n"
            f"{_session_header(ctx) if ctx else '(bind target optional for catalog)'}\n"
            + (readiness + "\n" if readiness else "")
            + f"Showing {len(lines)} tools (OK={ok_n} MISSING={miss_n})"
            + (f" matching {query!r}" if q else "")
            + "\n[OK] = runnable in your current execution environment; [MISSING] = not "
            "installed there (install per the hint, or `platform_install`, after asking "
            "the user). Compiled scanners are MISSING when no tools container/host tools "
            "are reachable — see README Path A/C.\n\n"
            + ("\n".join(lines) if lines else "(none — try empty query)")
            + "\n\nAliases: subfinder→subfinder_scan, amass→amass_scan, dnsenum→dnsenum_scan, "
            "httpx→httpx_probe, nmap→nmap_syn_scan, whois→whois_lookup, masscan→masscan_high_speed.\n"
            "Sequencing help: platform_playbook(). Playground: platform_script, platform_install, "
            "platform_record_finding."
        )

    return _safe(_run)


def _load_playbooks() -> dict[str, Any]:
    from pathlib import Path

    # YAML is the source of truth for config/ (see config/README.md); JSON is
    # only a legacy fallback if the yaml file is ever missing.
    root = Path(__file__).resolve().parents[1] / "config"
    yaml_path = root / "playbooks.yaml"
    json_path = root / "playbooks.json"
    try:
        if yaml_path.exists():
            import yaml  # type: ignore

            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
            return data.get("playbooks") or {}
        if json_path.exists():
            data = json.loads(json_path.read_text(encoding="utf-8"))
            return data.get("playbooks") or {}
    except Exception as exc:  # noqa: BLE001
        _log(f"playbooks load failed: {exc}")
    return {}


@mcp.tool()
def platform_playbook(
    name: str = "", target: str = "", engagement_id: str = ""
) -> str:
    """
    Advisory playbook only — does NOT auto-run tools.

    Returns a suggested tool sequence you may follow, edit, or ignore.
    Names: web_recon_light | network_port_confirm | dns_deep | smb_followup | web_depth_before_vuln
    Pass empty name to list available playbooks.
    """
    books = _load_playbooks()
    if not name.strip():
        lines = ["### OPERATOR MIRROR — PLAYBOOKS (advisory)", "Available:"]
        for key, meta in books.items():
            lines.append(f"- {key}: {(meta or {}).get('description', '')[:160]}")
        lines.append(
            "Call platform_playbook(name='web_recon_light', target='example.com') "
            "then decide yourself — nothing auto-executes."
        )
        return "\n".join(lines)

    key = name.strip().lower()
    meta = books.get(key)
    if not meta:
        return (
            f"ERROR: unknown playbook {name!r}. "
            f"Known: {', '.join(sorted(books)) or '(none — check config/playbooks.yaml)'}"
        )

    ctx = (
        _resolve_engagement(engagement_id)
        if engagement_id or _core._SESSION_ENGAGEMENT_ID
        else None
    )
    tgt = (target or (ctx.target if ctx else "") or "{{target}}").strip()
    steps = meta.get("steps") or []
    lines = [
        "### OPERATOR MIRROR — PLAYBOOK (advisory — you choose)",
        _session_header(ctx) if ctx else "(bind target optional)",
        f"**Playbook:** `{key}`",
        f"**Phase:** {meta.get('phase', '?')}",
        f"**Input:** {meta.get('input', 'target')} → `{tgt}`",
        f"**Description:** {(meta.get('description') or '').strip()}",
        "",
        "Suggested steps (adapt freely):",
    ]
    for i, step in enumerate(steps, 1):
        tool = step.get("tool", "?")
        why = step.get("why", "")
        fallback = step.get("fallback") or []
        params = step.get("suggested_params") or {}
        # Light template fill
        rendered = {
            k: (str(v).replace("{{target}}", tgt) if isinstance(v, str) else v)
            for k, v in params.items()
        }
        lines.append(f"{i}. **{tool}** — {why}")
        if rendered:
            lines.append(f"   suggested_params: {json.dumps(rendered)}")
        if fallback:
            lines.append(f"   fallback: {', '.join(fallback)}")
        if step.get("note"):
            lines.append(f"   note: {step['note']}")
    lines.append(
        "\nNothing was executed. Run the tools yourself (typed / exec / script / jobs). "
        "Edit or skip steps freely."
    )
    return "\n".join(lines)


@mcp.tool()
def platform_skills(
    path: str = "", phase: str = "", query: str = "",
    mitre: str = "", asset_type: str = "", tags: str = "", domain: str = "",
    limit: int = 8,
) -> str:
    """
    Browse or query platform skill markdown (plans/harness/08-skill-system-
    at-scale.md — ranked retrieval, not a flat dump).

    Empty path AND nothing else set → the router-level index (~1 line per
    domain, always cheap regardless of library size). Give ANY of query=/
    mitre=/asset_type=/tags=/domain= and this ranks every skill against what
    you gave and returns the top matches — narrow to what's actually
    relevant to the asset/technique in front of you instead of browsing
    everything. mitre='T1098', asset_type='graphql_endpoint', tags='sqli,web'
    are all valid alone or combined.

    path='shared/evidence-to-hypothesis.md' OR path='evidence-to-hypothesis'
    (bare skill name) → full text, on demand once you've picked one.
    """
    def _run() -> str:
        if path.strip():
            data = _get(
                "/api/v1/capabilities/skills-file",
                params={"path": path.strip()},
            )
            return "\n\n".join(
                [
                    "### OPERATOR MIRROR — SKILL",
                    f"**path:** `{data.get('path')}` — {data.get('title')}",
                    data.get("content") or "",
                ]
            )
        ranked = any(x.strip() for x in (query, mitre, asset_type, tags, domain))
        if ranked:
            data = _get(
                "/api/v1/capabilities/skills-find",
                params={
                    "query": query.strip(), "phase": phase.strip(), "tags": tags.strip(),
                    "mitre": mitre.strip(), "asset_type": asset_type.strip(),
                    "domain": domain.strip(), "limit": max(1, min(int(limit), 50)),
                },
            )
            header = "### OPERATOR MIRROR — SKILLS (ranked)"
        else:
            params: dict[str, str] = {}
            if phase.strip():
                params["phase"] = phase.strip()
            data = _get("/api/v1/capabilities/skills-index", params=params or None)
            header = "### OPERATOR MIRROR — SKILLS INDEX"
        lines = [
            header,
            f"count={data.get('count')}",
            "Call platform_skills(path='<name>') for full text.",
        ]
        items = data.get("skills") or []
        if not items:
            lines.append("(no matches — try broader terms, or omit filters for the full index)")
        for it in items:
            desc = it.get("description") or it.get("title") or ""
            lines.append(f"- [{it.get('phase')}] {it.get('name') or it.get('path')} — {desc}")
        return "\n".join(lines)

    return _safe(_run)


@mcp.tool()
def platform_propose_skill(
    name: str = "",
    phase: str = "",
    description: str = "",
    content: str = "",
    tags: str = "",
    evidence: str = "",
    update_existing: str = "",
    engagement_id: str = "",
) -> str:
    """
    Propose a reusable-technique skill capturing something you learned (or refine
    an existing learned skill).

    Use this ONLY for genuinely transferable methodology — a bypass/chain/playbook
    that worked and will help on FUTURE targets. NOT for: per-target facts (those
    belong in the engagement graph via platform_think / platform_record_finding).

    To IMPROVE an existing learned skill instead of adding a near-duplicate, pass
    its slug as update_existing= — the refinement overwrites it in place on
    approval, and the novelty check is skipped (only learned skills can be updated;
    shipped skills stay curated). This is how a skill gets better over time rather
    than accreting look-alikes.

    The proposal is INERT until the operator approves it (never auto-active, never
    committed, never shipped). Cite what it worked against in evidence=.

    name= short kebab title · phase= recon|network|web|vuln|exploit|osint|commander|shared
    description= one line (when to use it + what it does) · content= the methodology
    (markdown) · tags= comma-separated · evidence= the engagement facts it's grounded in
    · update_existing= slug of a learned skill to refine (optional).
    """
    def _run() -> str:
        ctx = (
            _resolve_engagement(engagement_id)
            if engagement_id or _core._SESSION_ENGAGEMENT_ID
            else None
        )
        body = {
            "name": name.strip(), "phase": phase.strip(), "description": description.strip(),
            "content": content, "evidence": evidence.strip(),
            "tags": [t.strip() for t in tags.split(",") if t.strip()],
            "engagement_id": ctx.engagement_id if ctx else "",
            "update_existing": update_existing.strip(),
        }
        data = _post("/api/v1/capabilities/learned-skills/propose", body)
        return (
            "### OPERATOR MIRROR — SKILL PROPOSED\n"
            f"id={data.get('id')} slug={data.get('slug')} phase={data.get('phase')}\n"
            f"{data.get('note', '')}\n"
            "It is NOT active yet — tell the user it awaits their approval "
            "(/skill approve <id> in the CLI). Continue the engagement meanwhile."
        )

    return _safe(_run)


@mcp.tool()
def platform_remember_preference(
    preference: str = "", rationale: str = "", engagement_id: str = ""
) -> str:
    """
    Remember a PREFERENCE of the human operator you inferred from how they work —
    e.g. "prefers concise output", "wants nuclei before nikto", "avoids brute-force
    without asking", "reports in CVSS". The confirmed profile is fed into every
    future engagement's context so the harness adapts to this operator.

    NOT for target facts (use platform_think / platform_record_finding) and NOT for
    reusable techniques (use platform_propose_skill). Inert until the operator
    approves it — never assume a proposed preference is in effect.

    preference= one clear line · rationale= what you observed that suggests it (optional).
    """
    def _run() -> str:
        ctx = (
            _resolve_engagement(engagement_id)
            if engagement_id or _core._SESSION_ENGAGEMENT_ID
            else None
        )
        body = {
            "preference": preference.strip(), "rationale": rationale.strip(),
            "engagement_id": ctx.engagement_id if ctx else "",
        }
        data = _post("/api/v1/capabilities/operator-profile/propose", body)
        return (
            "### OPERATOR MIRROR — PREFERENCE PROPOSED\n"
            f"id={data.get('id')}: {data.get('preference')}\n"
            f"{data.get('note', '')}\n"
            "Not active yet — it awaits the operator's approval (/profile approve <id>)."
        )

    return _safe(_run)


@mcp.tool()
def platform_config(name: str = "") -> str:
    """
    Read allowlisted platform YAML/JSON (playbooks, ingest_rules, recon_network_tools, …).
    Empty name → list. name='ingest_rules' → content.
    """
    def _run() -> str:
        if not name.strip():
            data = _get("/api/v1/capabilities/config-index")
            lines = ["### OPERATOR MIRROR — CONFIG INDEX", f"count={data.get('count')}"]
            for it in data.get("configs") or []:
                lines.append(f"- {it.get('name')} ({it.get('file')})")
            return "\n".join(lines)
        data = _get(
            "/api/v1/capabilities/config-file",
            params={"name": name.strip()},
        )
        content = data.get("content") or ""
        if len(content) > 120000:
            content = content[:120000] + "\n…[truncated]…"
        return "\n\n".join(
            [
                "### OPERATOR MIRROR — CONFIG",
                f"**{data.get('file')}**",
                content,
            ]
        )

    return _safe(_run)


@mcp.tool()
def platform_visualization(
    engagement_id: str = "",
    fmt: str = "mermaid",
    max_nodes: int = 200,
    max_edges: int = 400,
    node_type: str = "",
    exclude_urls: bool = True,
) -> str:
    """
    Attack-surface visualization: Mermaid (renders in markdown), Cytoscape JSON, or attack tree.

    Returns structured graph DATA — not rendered images. Use the data as you like:
    embed the Mermaid block in markdown, feed Cytoscape JSON to a web dashboard,
    or read the attack-tree hierarchy for a structured summary.

    fmt='mermaid' — styled graph TD with severity-coloured nodes (renders natively in
    OpenCode/Claude/IDE markdown previews). fmt='json' — Cytoscape-compatible {nodes,edges}
    for web dashboards. fmt='tree' — hierarchical domain→subdomain→IP→port→service tree.
    max_nodes/max_edges control output size. node_type filters to one asset type (host, subdomain…).
    exclude_urls=True filters static-asset URL noise (/assets/uploads/…).

    Note: graph data reflects what ingestion tools stored — third-party trackers
    (doubleclick.net etc.), parse artifacts ("Console" from js_recon), and duplicate
    type entries (domain+host for same name) come from the ingestion layer.
    Use node_type/host/domain to focus on the real target surface.
    """
    max_nodes = max(10, min(int(max_nodes), 1000))
    max_edges = max(10, min(int(max_edges), 2000))

    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        data = _get(
            f"/api/v1/engagements/{ctx.engagement_id}/visualization",
            params={
                "format": fmt,
                "max_nodes": str(max_nodes),
                "max_edges": str(max_edges),
                "node_type": node_type,
                "exclude_urls": str(exclude_urls).lower(),
            },
            timeout=30,
        )
        response_fmt = data.get("format", fmt)
        body = data.get("data", "")
        if response_fmt == "mermaid" and isinstance(body, str):
            return f"{_session_header(ctx)}\n\n## Attack Surface (Mermaid)\n\n```mermaid\n{body}\n```"
        return "\n\n".join(
            [_session_header(ctx), _block(f"Visualization ({response_fmt})", body)]
        )

    return _safe(_run)


@mcp.tool()
def platform_report_data(engagement_id: str = "") -> str:
    """
    Structured report data: metrics, severity breakdown, findings by severity,
    infrastructure notes, and Mermaid topology — everything an LLM needs to
    write a pentest report without guessing.

    Use platform_report_outline for the Observed/Inferred/Hypotheses scaffold.
    Use this tool for the quantitative payload (counts, grades, infra posture).
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        data = _get(
            f"/api/v1/engagements/{ctx.engagement_id}/report-data",
            timeout=30,
        )
        return "\n\n".join([_session_header(ctx), _block("Report data", data)])

    return _safe(_run)
