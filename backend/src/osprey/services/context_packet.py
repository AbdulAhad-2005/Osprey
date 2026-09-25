"""The context packet — plans/harness/07-context-packet.md.

A compact, structured state rebuilt DETERMINISTICALLY from the world model
every time it's asked for — never from conversation history, so nothing
about it can be lost to compaction. Every line traces to a store (Plans 02/
03/05/06); this module invents nothing.

Deliberately covers 9 of the plan's 10 sections, plus RELEVANT SKILLS
(plans/harness/08-skill-system-at-scale.md's Reconnect note — skills ranked
against what's currently hot). The plan's 10th section, LAST ACTION/NEXT, is
not included here on purpose: it describes what THIS PARTICULAR caller's
loop just did/said, which lives only in that caller's own local turn
history, not in any backend store — a second harness driving the same
engagement has a different last action. Each caller (cli/agent/loop.py,
an external MCP harness) appends its own last-action line locally; this
function is the shared, harness-agnostic part both build on.
"""

from __future__ import annotations

from datetime import datetime, timezone

from osprey.schemas.engagement_graph import AssetType
from osprey.services import attack_path_store, hypothesis_store, priority, question_store, world_model
from osprey.services.engagement_store import get_engagement_store
from osprey.services.evidence_store import get_evidence_store
from osprey.services.knowledge_browser import find_skills
from osprey.services.observation_store import get_observation_store
from osprey.services.tool_coverage_store import get_tool_coverage_store

_TOP_PRIORITIES_LIMIT = 8
_RECENT_EVIDENCE_LIMIT = 8
_TOOLS_RUN_ASSET_LIMIT = 15
_RELEVANT_SKILLS_LIMIT = 5


def _objective_and_scope(engagement_id: str) -> str:
    eng = get_engagement_store().get(engagement_id)
    if eng is None:
        return f"target: (unknown engagement {engagement_id})"
    lines = [f"target: {eng.target}" + (f" ({eng.name})" if eng.name and eng.name != eng.target else "")]
    scope = eng.rules_of_engagement.scope
    if scope.in_scope_targets:
        lines.append("in_scope: " + ", ".join(scope.in_scope_targets))
    if scope.out_of_scope:
        lines.append("out_of_scope: " + ", ".join(scope.out_of_scope))
    return "\n".join(lines)


def _world_model_summary(engagement_id: str) -> str:
    nodes = world_model.assets(engagement_id)
    if not nodes:
        return "(nothing discovered yet)"
    by_type: dict[str, list[str]] = {}
    for n in nodes:
        by_type.setdefault(getattr(n.asset_type, "value", str(n.asset_type)), []).append(n.label)
    lines = []
    # Stable, priority order: network/identity types first, noise-prone last.
    order = [t.value for t in AssetType]
    for atype in sorted(by_type, key=lambda t: order.index(t) if t in order else 99):
        labels = by_type[atype]
        shown = ", ".join(labels[:6])
        more = f" (+{len(labels) - 6} more)" if len(labels) > 6 else ""
        lines.append(f"{atype} ({len(labels)}): {shown}{more}")
    conflicts = world_model.conflicts(engagement_id, limit=5)
    if conflicts:
        lines.append(f"disputed slots ({len(conflicts)}): " + ", ".join(c["asset_id"] for c in conflicts[:5]))
    return "\n".join(lines)


def _coverage(engagement_id: str) -> str:
    gaps = world_model.assets_with_incomplete_investigation(engagement_id)
    if not gaps:
        return "no known gaps (every host/subdomain has port evidence)"
    shown = ", ".join(g["label"] for g in gaps[:8])
    more = f" (+{len(gaps) - 8} more)" if len(gaps) > 8 else ""
    return f"{len(gaps)} host(s)/subdomain(s) with no port evidence yet: {shown}{more}"


def _top_priorities_text(items: list) -> str:
    if not items:
        return "(nothing scored yet)"
    return "\n".join(
        f"[{it.total:.2f}] {it.item_kind}:{it.type_key} {it.label or it.target}" for it in items
    )


def _relevant_skills(items: list) -> str:
    """Skills ranked relevant to what's currently hot — plans/harness/08-
    skill-system-at-scale.md Reconnect: the context packet surfaces "skills
    relevant right now" instead of the operator/LLM having to separately
    think to go browse the library. Query terms come from the top few
    priority items' own type/label — no separate world-model read needed."""
    if not items:
        return "(nothing scored yet to match skills against)"
    terms = " ".join(f"{it.type_key} {it.label or it.target}" for it in items[:3])
    matches = find_skills(query=terms, limit=_RELEVANT_SKILLS_LIMIT)
    if not matches:
        return "(no skills matched the current top priorities)"
    return "\n".join(f"{m['name']} — {m['description']}" for m in matches)


def _open_questions(engagement_id: str) -> str:
    qs = question_store.list_open(engagement_id)
    if not qs:
        return "(none open)"
    return "\n".join(f"[{q.id}] {q.text}" for q in qs[:10])


def _active_hypotheses(engagement_id: str) -> str:
    hs = hypothesis_store.list_active(engagement_id)
    if not hs:
        return "(none active)"
    return "\n".join(
        f"[{h.id}] {h.statement} (support={len(h.supporting_observation_ids)} "
        f"contra={len(h.contradicting_observation_ids)})"
        for h in hs[:10]
    )


def _active_attack_paths(engagement_id: str) -> str:
    paths = attack_path_store.list_active(engagement_id)
    if not paths:
        return "(none active)"
    lines = []
    for p in paths[:8]:
        last_step = p.steps[-1] if p.steps else None
        last = f" — last: {last_step.rationale or last_step.ref_id}" if last_step else ""
        status = p.status.value if hasattr(p.status, "value") else str(p.status)
        lines.append(f"[{p.id}] {status}: {p.title} ({len(p.steps)} hop(s)){last}")
    return "\n".join(lines)


def _recent_evidence(engagement_id: str) -> str:
    items = get_evidence_store().list_for_engagement(engagement_id, limit=_RECENT_EVIDENCE_LIMIT)
    if not items:
        return "(no tool runs recorded yet)"
    lines = []
    for e in items:
        result = "ok" if e.exit_code == 0 else f"exit={e.exit_code}"
        lines.append(f"{e.tool_name} on {e.target or '(no target)'} — {result} — evidence_id={e.id}")
    return "\n".join(lines)


def _tools_already_run(engagement_id: str) -> str:
    records = get_tool_coverage_store().list_for_engagement(engagement_id, limit=2000)
    if not records:
        return "(none yet)"
    by_asset: dict[str, set[str]] = {}
    for r in records:
        by_asset.setdefault(r.asset, set()).add(r.tool_name)
    lines = []
    for asset in list(by_asset)[:_TOOLS_RUN_ASSET_LIMIT]:
        tools = sorted(by_asset[asset])
        lines.append(f"{asset}: {', '.join(tools)}")
    more = len(by_asset) - _TOOLS_RUN_ASSET_LIMIT
    if more > 0:
        lines.append(f"(+{more} more asset(s))")
    return "\n".join(lines)


def _constraints(engagement_id: str) -> str:
    eng = get_engagement_store().get(engagement_id)
    if eng is None:
        return "(unknown engagement)"
    roe = eng.rules_of_engagement
    bits = [
        f"exploitation={'allowed' if roe.allow_exploitation else 'BLOCKED'}",
        f"post_exploitation={'allowed' if roe.allow_post_exploitation else 'BLOCKED'}",
        f"destructive_actions={'allowed' if roe.destructive_actions_allowed else 'BLOCKED'}",
    ]
    if roe.scope.blocked_techniques:
        bits.append("blocked_techniques=" + ",".join(roe.scope.blocked_techniques))
    if roe.scope.time_window_start or roe.scope.time_window_end:
        bits.append(f"time_window={roe.scope.time_window_start or '00:00'}-{roe.scope.time_window_end or '23:59'} UTC")
    return " | ".join(bits)


def build_context_packet(engagement_id: str) -> str:
    """The full packet, rebuilt fresh from the world model — safe and cheap
    to call every turn (Step 2): every section is a bounded read over
    already-indexed store queries, nothing here re-derives from scratch."""
    eid = (engagement_id or "").strip()
    if not eid:
        return "CONTEXT PACKET: no engagement bound."

    ctx = priority.build_context(eid)
    top_items = priority.top_priorities(eid, limit=_TOP_PRIORITIES_LIMIT, ctx=ctx)
    sections = [
        ("OBJECTIVE + SCOPE", _objective_and_scope(eid)),
        ("WORLD MODEL SUMMARY", _world_model_summary(eid)),
        ("COVERAGE", _coverage(eid)),
        ("TOP PRIORITIES", _top_priorities_text(top_items)),
        ("RELEVANT SKILLS", _relevant_skills(top_items)),
        ("OPEN QUESTIONS", _open_questions(eid)),
        ("ACTIVE HYPOTHESES", _active_hypotheses(eid)),
        ("ACTIVE ATTACK PATHS", _active_attack_paths(eid)),
        ("RECENT EVIDENCE", _recent_evidence(eid)),
        ("TOOLS ALREADY RUN", _tools_already_run(eid)),
        ("CONSTRAINTS", _constraints(eid)),
    ]
    parts = [f"CONTEXT PACKET — generated {datetime.now(timezone.utc).isoformat(timespec='seconds')}"]
    parts += [f"## {title}\n{body}" for title, body in sections]
    return "\n\n".join(parts)
