"""Gateway tools — findings group (registers on _core.mcp)."""

from __future__ import annotations

import json
import re
from typing import Any

from _gateway_core import HTTP_TIMEOUT, _EngagementContext, _block, _client, _get, _post, _resolve_engagement, _safe, _session_header, mcp
from _gateway_exec import _coerce_params




@mcp.tool()
def platform_finalize_check(engagement_id: str = "") -> str:
    """
    The conductor's phase-readiness snapshot — evidence-based, not a gate.

    Call this when you're deciding whether to keep going or wrap up. Shows:
    recon is always the active/first phase; vuln/exploit show whether they've
    unlocked yet (real evidence crossed a threshold — live hosts, services,
    tech, URLs for vuln; vulnerabilities/credentials/secrets for exploit);
    and how many new host/subdomain findings look like they'd be worth
    another recon pass. Purely informational — you decide what to do with it.
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        data = _get(
            "/api/v1/hybrid/phase-readiness",
            params={"engagement_id": ctx.engagement_id},
            timeout=45,
        )
        parts = [
            "### OPERATOR MIRROR — PHASE READINESS",
            _session_header(ctx),
            data.get("text") or _block("phase_readiness", data),
        ]
        return "\n\n".join(parts)

    return _safe(_run)


_OBSERVATION_TYPE_VALUES = frozenset({
    "subdomain", "host", "url", "port", "service", "technology", "dns_record",
    "http_response", "header", "banner", "content_path", "js_endpoint", "endpoint",
    "cookie", "redirect", "cert", "waf", "share", "account", "asn", "email",
    "username", "person", "phone", "social_account", "organization", "document",
    "credential", "secret", "scanner_signal", "injection_point", "raw",
})


def _record_reasoned_finding(
    *,
    context: _EngagementContext,
    title: str,
    evidence: str,
    finding_type: str = "observation",
    claim_severity: str = "none",
    description: str = "",
    source_tool: str = "operator_record",
    derived_from: str = "",
    tags: str = "",
    metadata_json: Any = "",
) -> dict[str, Any] | str:
    """Record an operator/LLM-reasoned conclusion — no tool produced it, so
    there's no Observation for it yet. plans/harness/03-earned-finding-
    pipeline.md's one law (confidence = f(evidence), never asserted by a
    caller) applies here exactly like everywhere else: this used to POST
    straight to the raw Finding-create endpoint with a caller-supplied
    ``confidence`` string — the exact bypass Plan 03 exists to close, just
    not caught the first time since this call site predates the earned-
    finding pipeline's observation-write endpoint. Fixed the complete way:
    record an Observation first (extracted_by=llm — a fact, not a verdict),
    then file_finding against it with evidence_kind=attestation. Confidence is
    computed by confidence_for, never asserted; an agent attestation does NOT
    reach CONFIRMED (B0) — only a human operator confirms, out of band.

    Returns the filed/suppressed finding dict, or an ERROR string.
    """
    title = (title or "").strip()
    evidence = (evidence or "").strip()
    if not title or not evidence:
        return "ERROR: title and evidence are required"

    meta = _coerce_params(metadata_json) if metadata_json not in ("", None) else {}
    if isinstance(meta, str):  # _coerce_params returned an error
        return f"ERROR: metadata_json invalid — {meta}"

    tag_list = ["operator_recorded"]
    for t in re.split(r"[,\s]+", tags or ""):
        t = t.strip()
        if t and t not in tag_list:
            tag_list.append(t)

    ftype = (finding_type or "observation").strip().lower()
    obs = _post(
        "/api/v1/observations/",
        {
            "engagement_id": context.engagement_id,
            "run_id": context.run_id,
            "type": ftype if ftype in _OBSERVATION_TYPE_VALUES else "raw",
            "target": context.target,
            "details": {"title": title, "description": description, **meta},
            "source_tool": source_tool or "operator_record",
            "tags": tag_list,
            "extracted_by": "llm",
        },
        timeout=30,
    )

    # A structural fact (url/host/port/subdomain/technology/observation/…) is
    # recorded as an Observation (done above) and stops there — it is NOT a
    # finding (plan 19 Phase 7; the backend's file_finding rejects it anyway).
    # Only a brain-authored CONCLUSION (vulnerability/access/credential/secret)
    # continues to file_finding with the reasoning as an attestation.
    _CONCLUSION_FTYPES = {"vulnerability", "access", "credential", "secret"}
    if ftype not in _CONCLUSION_FTYPES:
        return {
            "recorded_observation": True,
            "finding": None,
            "observation_id": obs.get("id"),
            "note": (
                f"Recorded as an observation (type={obs.get('type')}). A {ftype!r} is a "
                "structural fact, not a conclusion — it lives in the observation store / asset "
                "graph, not the finding store. File a finding only for a vulnerability/access/"
                "credential/secret you've concluded, with evidence."
            ),
        }

    derived_ids = [x.strip() for x in (derived_from or "").replace(";", ",").split(",") if x.strip()]
    # FileFindingRequest (schemas/finding.py) has no confidence/source_tool
    # fields at the top level — confidence_for computes confidence from
    # evidence_records alone (Plan 03's one law), and source_tool belongs
    # inside the evidence record, not the finding.
    file_body: dict[str, Any] = {
        "engagement_id": context.engagement_id,
        "run_id": context.run_id,
        "title": title,
        "finding_type": ftype,
        "observation_ids": [obs["id"]],
        "claim_severity": (claim_severity or "none").strip().lower(),
        "description": description,
        "evidence_records": [{"kind": "attestation", "source_tool": source_tool or "operator_record", "detail": evidence}],
        "target": context.target,
        "tags": tag_list,
    }
    if derived_ids:
        file_body["metadata"] = {"derived_from": derived_ids}
    return _post("/api/v1/findings/file", file_body, timeout=30)


@mcp.tool()
def platform_record_finding(
    title: str,
    evidence: str,
    finding_type: str = "observation",
    claim_severity: str = "none",
    description: str = "",
    source_tool: str = "operator_record",
    derived_from: str = "",
    tags: str = "",
    metadata_json: Any = "",
    engagement_id: str = "",
) -> str:
    """
    Persist ONE conclusion that lives only in your reasoning — not tool output.

    Tool / script / shell output is ingested automatically; do not re-record it
    here (harmless no-op, wasted effort). Use this for what a tool did NOT emit:
    an interpretation you reasoned out (an IP-cluster grouping, a path pattern
    across GAU/wayback runs), a suspicion, a hand-verified fact. For a
    relationship between assets use platform_graph_link_many; for a hypothesis
    use platform_think. Prefer platform_record_findings (bulk) to flush several
    at a checkpoint. If it lives only in your chat answer, it should be here too.

    There is NO confidence parameter — like platform_file_finding, you attach
    evidence (the ``evidence`` text becomes an attestation — "I'm personally
    attesting to this"), the platform computes confidence from it. Claiming
    "confirmed" in your title changes nothing.
    finding_type: url|host|port|service|technology|observation|subdomain|
      vulnerability|credential|secret|http_response|access
      (use observation for anything that doesn't fit — it's the catch-all).
    claim_severity: the impact IF this is real — assign it honestly yourself;
      independent of confidence (see skills/vuln/verification-and-severity.md).
    derived_from: optional comma-separated parent finding ids (evidence chain).

    Flexibility (structure it your way — the platform stores whatever you give):
    - tags: comma/space list of your own labels (e.g. "oracle,weblogic,login-portal").
    - metadata_json: an object of arbitrary structured fields you choose
      (e.g. {"kind":"jwt","alg":"none","endpoint":"/api/v1/auth"}). Use this to
      record shapes the 7 finding types don't capture — the platform does not
      constrain the keys.
    For many facts at once, prefer platform_record_findings (one call).
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        result = _record_reasoned_finding(
            context=ctx,
            title=title,
            evidence=evidence,
            finding_type=finding_type,
            claim_severity=claim_severity,
            description=description,
            source_tool=source_tool,
            derived_from=derived_from,
            tags=tags,
            metadata_json=metadata_json,
        )
        if isinstance(result, str):
            return result
        if result.get("suppressed"):
            return (
                "### OPERATOR MIRROR — SUPPRESSED (FP-cache)\n"
                f"{_session_header()}\n"
                f"title: {title}\n"
                f"Not filed — matches a known false-positive pattern: {result.get('suppressed_reason')}"
            )
        if result.get("recorded_observation") and not result.get("finding"):
            return (
                "### OPERATOR MIRROR — RECORDED OBSERVATION\n"
                f"{_session_header(ctx)}\n"
                f"Stored observation id={result.get('observation_id')}\n"
                f"title: {title}\n"
                f"{result.get('note', '')}"
            )
        data = result.get("finding") or {}
        return (
            "### OPERATOR MIRROR — RECORDED FINDING\n"
            f"{_session_header(ctx)}\n"
            f"Stored id={data.get('id')} type={data.get('finding_type')} "
            f"confidence={data.get('confidence')} (computed) sev={data.get('claim_severity')}\n"
            f"title: {data.get('title')}\n"
            "Call platform_findings to verify; then platform_finalize_check again."
        )

    return _safe(_run)


@mcp.tool()
def platform_record_findings(items_json: Any, engagement_id: str = "") -> str:
    """
    Persist MANY reason-only conclusions in one call (bulk platform_record_finding).

    The checkpoint flush: at a query-back breakpoint, drop everything you concluded
    but no tool emitted (interpretations, hand-verified facts) in a single
    round-trip instead of one call per fact. Tool/script/shell output is already
    stored automatically — do not bulk-re-record it. Re-sends merge as extra
    observations (never duplicates, never a loss), so flushing is cheap and safe.

    items_json: a JSON array (or JSON string of one). Each item accepts the same
    fields as platform_record_finding (no confidence field — it's computed,
    not asserted) — at minimum title + evidence:
      [
        {"title":"...","evidence":"...","finding_type":"url",
         "tags":"oracle,api","metadata_json":{"status":401}},
        {"title":"...","evidence":"...","finding_type":"observation"}
      ]
    Each item records its own Observation + files it (same as one
    platform_record_finding call); duplicates still de-dupe by content.
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        raw = items_json
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError as exc:
                return f"ERROR: items_json is not valid JSON: {exc}"
        if isinstance(raw, dict):
            raw = [raw]
        if not isinstance(raw, list) or not raw:
            return "ERROR: items_json must be a non-empty JSON array of finding objects"
        if len(raw) > 100:
            return "ERROR: too many items (max 100 per call — split into batches)"

        stored: list[dict[str, Any]] = []
        observations_only = 0
        suppressed_count = 0
        errors: list[str] = []
        for i, item in enumerate(raw):
            if not isinstance(item, dict):
                errors.append(f"item {i}: not an object")
                continue
            result = _record_reasoned_finding(
                context=ctx,
                title=str(item.get("title") or ""),
                evidence=str(item.get("evidence") or ""),
                finding_type=str(item.get("finding_type") or "observation"),
                claim_severity=str(item.get("claim_severity") or "none"),
                description=str(item.get("description") or ""),
                source_tool=str(item.get("source_tool") or "operator_record"),
                derived_from=str(item.get("derived_from") or ""),
                tags=str(item.get("tags") or "") if not isinstance(item.get("tags"), list)
                else ",".join(str(x) for x in item.get("tags")),
                metadata_json=item.get("metadata_json") or item.get("metadata") or "",
            )
            if isinstance(result, str):
                errors.append(f"item {i}: {result}")
            elif result.get("suppressed"):
                suppressed_count += 1
            elif result.get("recorded_observation") and not result.get("finding"):
                observations_only += 1
            else:
                stored.append(result.get("finding") or {})

        if not stored and not suppressed_count and not observations_only:
            return "ERROR: no valid findings.\n" + "\n".join(errors[:20])

        parts = [
            "### OPERATOR MIRROR — RECORDED (bulk)",
            _session_header(ctx),
            f"Filed {len(stored)} conclusion finding(s) (of {len(raw)} submitted"
            + (f"; {observations_only} structural fact(s) recorded as observations" if observations_only else "")
            + (f"; {suppressed_count} suppressed by FP-cache" if suppressed_count else "")
            + ").",
        ]
        if errors:
            parts.append(_block(f"Skipped {len(errors)}", errors[:20]))
        parts.append("Call platform_findings to verify.")
        return "\n".join(parts)

    return _safe(_run)


@mcp.tool()
def platform_file_finding(
    title: str,
    finding_type: str,
    observation_ids: str,
    claim_severity: str = "none",
    description: str = "",
    evidence_kind: str = "",
    evidence_detail: str = "",
    evidence_source_tool: str = "",
    evidence_observation_id: str = "",
    engagement_id: str = "",
    target: str = "",
    tags: str = "",
) -> str:
    """
    File a finding backed by evidence — the earned-finding path
    (plans/harness/03-earned-finding-pipeline.md). There is NO confidence
    parameter: you attach evidence, the platform computes confidence from it.
    Claiming "confirmed" in your title changes nothing — only evidence does.

    observation_ids: comma-separated ids from platform_findings/platform_graph_query
    (an Observation must already exist — extract/record one first; this call
    fails if none of the ids resolve).

    evidence_kind (optional, attach ONE piece of evidence beyond the raw
    signal): corroboration|reproduction|verification|attestation.
      - corroboration: an independent tool also observed this (pass
        evidence_source_tool=<that tool's name>).
      - reproduction: you ran a controlled PoC and it reproduced (RoE/blast-
        radius still apply to whatever you actually ran). evidence_detail must
        quote a real excerpt (20+ chars) from that observation's actual
        recorded tool output — a paraphrase or bare "it worked" is rejected,
        deterministically, not on the platform's trust in you. Point
        evidence_observation_id at whichever of observation_ids has that
        output if it isn't the first one.
      - verification: you read the config/permission directly and confirmed it.
      - attestation: a note that you're vouching for this. NOTE (B0): an
        agent/tool attestation does NOT confirm — it never reaches CONFIRMED on
        its own say-so. Only a human operator, via the out-of-band confirm
        channel (CLI `/finding confirm <id>` or the dashboard button), can
        confirm a finding. To earn CONFIRMED yourself, show a grounded
        reproduction/verification excerpt instead.
    Omit evidence_kind for a bare signal with no extra evidence — it stays
    HYPOTHESIS unless >=2 independent source tools already observed it.

    claim_severity: the impact IF this is real — assign it honestly yourself
    (see skills/vuln/verification-and-severity.md); independent of confidence.
    finding_type: url|host|port|service|technology|observation|subdomain|
      vulnerability|credential|secret|http_response|access.
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        ids = [x.strip() for x in observation_ids.split(",") if x.strip()]
        if not ids:
            return "ERROR: observation_ids is required — at least one Observation id."
        evidence_records: list[dict[str, Any]] = []
        kind = evidence_kind.strip().lower()
        if kind:
            if kind not in ("corroboration", "reproduction", "verification", "attestation"):
                return f"ERROR: evidence_kind must be one of corroboration|reproduction|verification|attestation, got {kind!r}"
            evidence_records.append({
                "kind": kind,
                "source_tool": evidence_source_tool.strip(),
                "detail": evidence_detail.strip(),
                # Default to the first observation this finding is about —
                # explicit evidence_observation_id when it's a different one
                # of several. Needed so a 'reproduction' claim has something
                # concrete to be checked against (evidence_grounding.py).
                "observation_id": evidence_observation_id.strip() or ids[0],
            })
        sev = (claim_severity or "none").strip().lower()
        if sev not in ("none", "info", "low", "medium", "high", "critical"):
            sev = "none"
        tag_list = [t.strip() for t in tags.replace(",", " ").split() if t.strip()]
        body = {
            "engagement_id": ctx.engagement_id,
            "run_id": ctx.run_id,
            "title": title.strip()[:300],
            "finding_type": (finding_type or "observation").strip().lower(),
            "observation_ids": ids,
            "claim_severity": sev,
            "description": description.strip(),
            "evidence_records": evidence_records,
            "target": target.strip() or ctx.target,
            "tags": tag_list,
        }
        data = _post("/api/v1/findings/file", body, timeout=30)
        if data.get("suppressed"):
            return (
                "### OPERATOR MIRROR — SUPPRESSED (FP-cache)\n"
                f"{_session_header(ctx)}\n"
                f"title: {title}\n"
                f"Not filed — matches a known false-positive pattern: {data.get('suppressed_reason')}\n"
                "Visible in the audit trail (platform_fp_list shows patterns; the suppressed-"
                "promotion audit is at GET /api/v1/findings/fp/suppressed) — never a silent drop."
            )
        f = data.get("finding") or {}
        return (
            "### OPERATOR MIRROR — FILED FINDING\n"
            f"{_session_header(ctx)}\n"
            f"Stored id={f.get('id')} type={f.get('finding_type')} "
            f"confidence={f.get('confidence')} (computed) sev={f.get('claim_severity')}\n"
            f"title: {f.get('title')}\n"
            f"observation_ids: {f.get('observation_ids')}\n"
            f"source_tools: {f.get('source_tools')}\n"
            "Call platform_findings to verify."
        )

    return _safe(_run)


@mcp.tool()
def platform_mark_false_positive(finding_id: str, reason: str = "", target_glob: str = "") -> str:
    """
    Mark a finding as noise, once, forever — plans/harness/04-learning-fp-
    cache.md. Appends an FP-cache pattern keyed on the finding's own type and
    title, and retracts the finding from THIS engagement. Every future
    platform_file_finding call on a matching candidate is suppressed
    automatically — a human judgment captured once, applied forever.

    target_glob: left empty (the default), the pattern scopes to THIS
    finding's own target only — marking noise on one host can never suppress
    the same-titled signal on a different host by accident. Pass "*" (noise
    everywhere, e.g. a scanner's own banner) or a glob like "*.internal.corp"
    only when you deliberately want to widen it — that's an opt-in.

    The pattern is advisory metadata, never evidence deletion — the
    underlying Observations stay intact; platform_fp_list shows what's
    active, and removing a pattern re-enables promotion.
    """
    def _run() -> str:
        ctx = _resolve_engagement("")
        resp = _client().post(
            f"/api/v1/findings/{finding_id}/fp",
            params={"reason": reason.strip(), "target_glob": target_glob.strip()},
            timeout=min(30.0, HTTP_TIMEOUT),
        )
        if resp.status_code == 404:
            return f"ERROR: no finding with id '{finding_id}'."
        resp.raise_for_status()
        data = resp.json()
        pattern = data.get("pattern") or {}
        return (
            "### OPERATOR MIRROR — MARKED FALSE POSITIVE\n"
            f"{_session_header(ctx)}\n"
            f"Retracted finding {finding_id}. New FP-cache pattern id={pattern.get('id')} "
            f"scope={pattern.get('target_glob')} type={pattern.get('finding_type') or 'any'}\n"
            f"match: {pattern.get('observation_signature') or pattern.get('finding_fingerprint') or '(none)'}\n"
            "This pattern now suppresses matching candidates on every future promotion. "
            "platform_fp_list to review/prune."
        )

    return _safe(_run)


@mcp.tool()
def platform_reverify_finding(finding_id: str, run_id: str = "", engagement_id: str = "") -> str:
    """
    Re-check whether a finding still holds — re-runs the tool(s) behind its
    evidence and looks for the same signal.

    confidence_for computes confidence once, at filing time, and never
    revisits it — a finding CONFIRMED hours into a long engagement stays
    reported as CONFIRMED even if the target's since been patched or the
    WAF now blocks it. This closes that gap without ever touching history:
    it NEVER edits or deletes past evidence (Plan 03's evidence is
    append-only) — a recheck that fails to reproduce the signal appends a
    RECHECK_FAILED record, which confidence_for weighs by recency (a
    CONFIRMED finding whose most recent recheck failed reads as LIKELY, not
    CONFIRMED — a later successful re-verification clears it again).

    Only useful on a finding with a re-runnable observation behind it (a
    real catalog tool, not an operator/LLM-only attestation) — those report
    back plainly that there's nothing to re-run rather than guessing.

    Call this before a final report on anything CRITICAL/CONFIRMED you filed
    a while ago, or whenever you want to confirm a finding still holds right
    now rather than whenever it was first observed.

    engagement_id: optional pin — see platform_exec.
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        resp = _client().post(
            f"/api/v1/findings/{finding_id}/reverify",
            params={"run_id": run_id.strip() or ctx.run_id},
            timeout=min(120.0, HTTP_TIMEOUT),
        )
        if resp.status_code == 404:
            return f"ERROR: no finding with id '{finding_id}'."
        resp.raise_for_status()
        data = resp.json()
        if data.get("checked", 0) == 0:
            return f"### OPERATOR MIRROR — REVERIFY\n{_session_header(ctx)}\n{data.get('note')}"
        before, after = data.get("confidence_before"), data.get("confidence_after")
        moved = f"{before} -> {after}" if before != after else f"{after} (unchanged)"
        return (
            "### OPERATOR MIRROR — REVERIFY\n"
            f"{_session_header(ctx)}\n"
            f"Checked {data.get('checked')} tool(s) behind finding {finding_id}: "
            f"{data.get('reproduced')} reproduced, {data.get('failed')} did not.\n"
            f"Confidence: {moved}."
        )

    return _safe(_run)


@mcp.tool()
def platform_fp_list() -> str:
    """
    List active FP-cache patterns (plans/harness/04-learning-fp-cache.md
    Step 4) — audit what's currently suppressing promotion. A bad mark
    shouldn't hide real findings forever: remove a pattern via
    DELETE /api/v1/findings/fp/patterns/{id} (no MCP unmark tool yet — ask
    the operator to do this via the CLI/API if a pattern looks wrong).
    """
    def _run() -> str:
        data = _get("/api/v1/findings/fp/patterns", timeout=15)
        patterns = data.get("patterns") or []
        if not patterns:
            return "No FP-cache patterns yet. Mark noise with platform_mark_false_positive."
        lines = [
            f"- id={p.get('id')} scope={p.get('target_glob')} type={p.get('finding_type') or 'any'} "
            f"match='{p.get('observation_signature') or p.get('finding_fingerprint') or '(none)'}' "
            f"reason='{p.get('reason')}' marked_by={p.get('marked_by')}"
            for p in patterns
        ]
        return "### OPERATOR MIRROR — FP-CACHE PATTERNS\n" + "\n".join(lines)

    return _safe(_run)


@mcp.tool()
def platform_findings(
    limit: int = 120,
    finding_type: str = "",
    include_summary: bool = True,
    engagement_id: str = "",
) -> str:
    """
    Dump stored findings. Optional mid-engagement — use when the operator asks
    or before a final report. Tools already ingest into memory automatically.
    Optional finding_type: subdomain | host | url | port | service | technology | observation.

    engagement_id: optional pin to a specific engagement — see platform_exec.
    Use this if findings for a different target start showing up here; it
    usually means another chat sharing this MCP process switched the shared
    session with platform_set_target after you bound yours.
    """
    limit = max(10, min(int(limit), 500))

    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        params: dict[str, Any] = {
            "engagement_id": ctx.engagement_id,
            "limit": limit,
        }
        if finding_type.strip():
            params["finding_type"] = finding_type.strip().lower()

        parts = [
            "### OPERATOR MIRROR — FINDINGS",
            _session_header(ctx),
        ]
        if include_summary:
            summary = _get(
                "/api/v1/findings/summary",
                params={"engagement_id": ctx.engagement_id},
                timeout=30,
            )
            meta = summary if isinstance(summary, dict) else {}
            parts.append(_block("Findings summary", meta.get("summary", summary)))
            if meta.get("count") is not None:
                parts.append(
                    f"_count={meta.get('count')} | "
                    f"truncated={meta.get('truncated')} | "
                    f"generated_at={meta.get('generated_at', '')[:19]}_"
                )

        data = _get("/api/v1/findings/", params=params, timeout=45)
        findings = data.get("findings") or []
        total = data.get("total", len(findings))
        lines = []
        for f in findings:
            ft = f.get("finding_type", "")
            conf = f.get("confidence", "")
            sev = f.get("claim_severity") or (f.get("extra") or {}).get("claim_severity") or "none"
            title = f.get("title", "")
            tool = f.get("source_tool", "")
            tags = ",".join(f.get("tags") or [])
            lines.append(
                f"- [{ft}|sev={sev}|confidence={conf}] {title}  (via {tool})"
                + (f" tags={tags}" if tags else "")
            )
        parts.append(
            _block(
                f"Findings list (showing {len(findings)} / total field {total})",
                "\n".join(lines) if lines else "(none)",
            )
        )
        parts.append(
            "Paste important rows into your chat reply so the operator sees them. "
            "Support HIGH/CRITICAL claims with the strongest evidence available."
        )
        return "\n\n".join(parts)

    return _safe(_run)


@mcp.tool()
def platform_observations(
    limit: int = 120,
    observation_type: str = "",
    target: str = "",
    engagement_id: str = "",
) -> str:
    """
    Dump stored Observations — the structural facts parsers extracted
    (ports, services, technologies, scanner signals, injection points,
    credentials, …), each with an id. Tool output ingests into these
    automatically. Use this to find the observation_ids platform_file_finding
    requires — a finding must be filed against something actually observed.

    observation_type: optional filter, e.g. scanner_signal | injection_point |
      credential | secret | port | service | technology | subdomain | host |
      url | dns_record | cert | waf | share | account | asn | raw.
    target: optional filter to one asset's observations.
    engagement_id: optional pin to a specific engagement — see platform_exec.
    """
    limit = max(10, min(int(limit), 500))

    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        eid = ctx.engagement_id
        params: dict[str, Any] = {"engagement_id": eid, "limit": limit}
        if observation_type.strip():
            params["type"] = observation_type.strip().lower()
        if target.strip():
            params["target"] = target.strip()

        data = _get("/api/v1/observations/", params=params, timeout=45)
        items = data.get("observations") or []
        total = data.get("total", len(items))
        lines = []
        for o in items:
            details = o.get("details") or {}
            label = details.get("title") or details.get("url") or details.get("hostname") or o.get("target", "")
            lines.append(
                f"- id={o.get('id')} [{o.get('type')}] {label}  (via {o.get('source_tool', '')}, "
                f"seen {o.get('occurrence_count', 1)}x)"
            )
        parts = [
            "### OPERATOR MIRROR — OBSERVATIONS",
            _session_header(ctx),
            _block(
                f"Observations list (showing {len(items)} / total field {total})",
                "\n".join(lines) if lines else "(none)",
            ),
            "Use an id above with platform_file_finding(observation_ids=...) once you have "
            "evidence beyond the raw signal — the only route into the finding store. A raw "
            "scanner match stays a scanner_claim observation until a brain confirms it.",
        ]
        return "\n\n".join(parts)

    return _safe(_run)


@mcp.tool()
def platform_priority(
    kinds: str = "observation,asset,question,attack_path",
    limit: int = 20,
    phase: str = "",
    engagement_id: str = "",
) -> str:
    """
    What's worth doing next — plans/harness/06-prioritization-engine.md. A
    multi-factor score (objective relevance, evidence strength, novelty/decay,
    potential impact, graph centrality, unexplained/conflicting behavior,
    validation ease, coverage gaps, minus cost/repetition/risk) over the world
    model, ranked highest first. A DIFFERENT question from a Finding's
    confidence (Plan 03) — a low-confidence lead can still be the top
    priority; this never feeds back into confidence.

    platform_context already shows your top 8 every time you call it — call
    THIS tool only when you need more than 8, or a specific phase= unlock
    check. If you just read platform_context this turn, you likely don't
    need this call at all.

    kinds: comma-separated subset of observation|asset|question|attack_path.
    phase: optional — pass 'vuln' or 'exploit' instead to see whether that
    area has crossed its unlock threshold (replaces the old finding-count
    trigger) and what the single highest-priority item driving it is.
    """
    def _run() -> str:
        ctx = _resolve_engagement(engagement_id)
        eid = ctx.engagement_id
        if phase.strip():
            data = _get("/api/v1/priority/phase/" + phase.strip().lower(), params={"engagement_id": eid}, timeout=20)
            return (
                "### OPERATOR MIRROR — PHASE PRIORITY\n"
                f"{_session_header(ctx)}\n"
                f"phase={data.get('phase')} unlocked={data.get('unlocked')}\n"
                f"{data.get('gate_reason', '')}"
            )
        data = _get(
            "/api/v1/priority/top",
            params={"engagement_id": eid, "kinds": kinds.strip() or "observation,asset,question,attack_path", "limit": max(1, min(int(limit), 200))},
            timeout=30,
        )
        items = data.get("items") or []
        lines = [
            f"- [{it['total']:.2f}] {it['item_kind']}:{it['type_key']} {it.get('label') or it.get('target', '')}"
            for it in items
        ]
        return (
            "### OPERATOR MIRROR — TOP PRIORITIES\n"
            f"{_session_header(ctx)}\n"
            + ("\n".join(lines) if lines else "(nothing scored yet — no observations/assets/questions/attack paths)")
        )

    return _safe(_run)
