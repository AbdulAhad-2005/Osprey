from __future__ import annotations

import json
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from cli.api.client import APIClient

from cli.commands.scan_shared import (
    _api_error_text,
)
from cli.ui.display import (
    print_error,
    print_findings,
    print_findings_grouped,
    print_info,
    print_success,
)
from cli.commands.slash._meta import _require_engagement, _take_flag



def handle_findings(args: list[str], client: "APIClient") -> None:
    """Show findings for the active engagement, optionally filtered by keyword.

    Usage: /findings [keyword...] [--engagement <id>] [--all] [--flat]
    Grouped by default — the same issue firing on many host:port instances,
    or the same URL-crawl pattern across many paths, collapses into one row
    with an affected-target list instead of dozens of near-identical rows.
    Excludes unparsed/raw-output noise by default too (kept in the DB for
    evidence, just not shown). --all includes noise; --flat shows the raw
    one-row-per-instance view instead of grouping. Search by keyword (title,
    target, evidence, source tool) to cut through a large result set.
    """
    engagement_id = client.active_engagement_id
    if "--engagement" in args:
        idx = args.index("--engagement")
        if idx + 1 < len(args):
            engagement_id = args[idx + 1]
        args = args[:idx] + args[idx + 2 :]
    show_all = "--all" in args
    flat = "--flat" in args
    args = [a for a in args if a not in ("--all", "--flat")]
    query = " ".join(args).strip()

    if not engagement_id:
        print_info("No engagement bound. Run /scan <target> or /engage new <target> first.")
        return

    if flat:
        findings = client.list_findings(
            engagement_id, q=query, limit=500 if query else 100, exclude_noise=not show_all,
        )
        if not findings:
            if query:
                print_info(f"No findings matching '{query}' for engagement {engagement_id}.")
            else:
                print_info(f"No findings yet for engagement {engagement_id}.")
            return
        print_findings(findings)
        if not query and len(findings) == 100:
            print_info(
                "Showing the first 100 findings — this engagement may have more. "
                "Search with /findings <keyword>, e.g. /findings geo.tv or /findings exchange."
            )
        return

    data = client.list_findings_grouped(engagement_id, q=query, exclude_noise=not show_all)
    if not data.get("groups"):
        if query:
            print_info(f"No findings matching '{query}' for engagement {engagement_id}.")
        else:
            print_info(f"No findings yet for engagement {engagement_id}.")
        return
    print_findings_grouped(data)


def handle_finding(args: list[str], client: "APIClient") -> None:
    """Act on one finding by id — false-positive marking or re-verification.

    Usage: /finding fp <id> [--scope <glob>] [reason...]
           /finding reverify <id>
    plans/harness/04-learning-fp-cache.md: appends a pattern learned from
    this finding's (type, title) and retracts it from the current
    engagement. By default the pattern scopes to THIS finding's own target
    only — it cannot suppress the same-titled signal on a different host by
    accident. Pass --scope "*" (or a glob like "*.internal.corp") only when
    you deliberately want to widen it. /fp list to review.

    reverify: re-runs the tool(s) behind this finding's evidence and checks
    whether the signal still reproduces — never edits/deletes past evidence,
    only appends a record of what a fresh check found. See
    services.finding_reverification.
    """
    if args and args[0].lower() == "confirm" and len(args) >= 2:
        # Operator confirmation channel (B0) — human-only, by design not an MCP
        # tool. Stamps a human attestation so the finding can reach CONFIRMED.
        finding_id = args[1]
        note = " ".join(args[2:]).strip()
        try:
            result = client.confirm_finding(finding_id, note=note)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                print_error(f"No finding with id '{finding_id}'.")
            else:
                print_error(f"Confirm failed: {exc}")
            return
        conf = (result.get("finding") or {}).get("confidence", "?")
        print_success(f"Confirmed {finding_id} (operator attestation). Confidence now: {conf}.")
        return

    if args and args[0].lower() == "reverify" and len(args) >= 2:
        finding_id = args[1]
        try:
            result = client.reverify_finding(finding_id)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                print_error(f"No finding with id '{finding_id}'.")
            else:
                print_error(f"Reverify failed: {exc}")
            return
        if result.get("checked", 0) == 0:
            print_info(result.get("note") or "Nothing re-runnable for this finding.")
            return
        before, after = result.get("confidence_before"), result.get("confidence_after")
        moved = f"{before} -> {after}" if before != after else f"{after} (unchanged)"
        print_success(
            f"Reverified {finding_id}: checked {result.get('checked')} tool(s) "
            f"({result.get('reproduced')} reproduced, {result.get('failed')} did not). "
            f"Confidence: {moved}."
        )
        return

    if not args or args[0].lower() != "fp" or len(args) < 2:
        print_info(
            'Usage: /finding fp <id> [--scope "<glob>"] [reason...]\n'
            "       /finding reverify <id>\n"
            "       /finding confirm <id> [note...]"
        )
        return
    finding_id = args[1]
    rest = list(args[2:])
    target_glob = ""
    if rest and rest[0] == "--scope" and len(rest) >= 2:
        target_glob = rest[1]
        rest = rest[2:]
    reason = " ".join(rest).strip()
    try:
        result = client.mark_finding_fp(finding_id, reason=reason, target_glob=target_glob)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            print_error(f"No finding with id '{finding_id}'.")
        else:
            print_error(f"Mark-FP failed: {exc}")
        return
    pattern = result.get("pattern") or {}
    print_success(
        f"Retracted finding {finding_id}. Learned FP-cache pattern "
        f"[{pattern.get('id')}] scope={pattern.get('target_glob')} "
        f"match={_fp_matcher(pattern)} — suppresses matching "
        "candidates on every future promotion. /fp list to review."
    )


def _fp_matcher(p: dict) -> str:
    """How an FP pattern matches: its exact observation signature, else its
    structural finding fingerprint."""
    return p.get("observation_signature") or p.get("finding_fingerprint") or "(none)"


def handle_fp(args: list[str], client: "APIClient") -> None:
    """FP-cache pattern audit — plans/harness/04-learning-fp-cache.md Step 4.

    Usage: /fp list | /fp remove <pattern_id>
    A bad mark shouldn't hide real findings forever — removing a pattern
    re-enables promotion for matching candidates on the next scan/replay.
    """
    sub = (args[0].lower() if args else "list")
    if sub == "list":
        data = client.list_fp_patterns()
        patterns = data.get("patterns", [])
        if not patterns:
            print_info("No FP-cache patterns yet. Mark noise with /finding fp <id> [reason].")
            return
        print_info(f"FP-cache patterns ({len(patterns)}):")
        for p in patterns:
            print(
                f"  [{p['id']}] scope={p['target_glob']} type={p.get('finding_type') or 'any'} "
                f"match={_fp_matcher(p)} reason='{p.get('reason', '')}'"
            )
    elif sub == "remove" and len(args) > 1:
        try:
            client.remove_fp_pattern(args[1])
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                print_error(f"No FP pattern with id '{args[1]}'.")
            else:
                print_error(f"Remove failed: {exc}")
            return
        print_success(f"Removed pattern {args[1]} — matching promotions are no longer suppressed.")
    else:
        print_info("Usage: /fp list | /fp remove <pattern_id>")


def handle_observations(args: list[str], client: "APIClient") -> None:
    """List stored Observations — the structural facts parsers extracted
    (ports, services, technologies, scanner signals, injection points,
    credentials, …), each with an id.

    Usage: /observations [type] [--target <t>] [--engagement <id>] [--limit N]
    plans/harness/02-evidence-and-observation-layer.md: these are facts, not
    verdicts. Use an id shown here with /file to file an evidence-backed
    finding — the only route into the finding store (a brain citing evidence).
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    target, args = _take_flag(args, "--target")
    limit_s, args = _take_flag(args, "--limit")
    obs_type = args[0] if args else ""
    if not _require_engagement(engagement_id):
        return
    try:
        data = client.list_observations(
            engagement_id, observation_type=obs_type, target=target or "", limit=int(limit_s) if limit_s else 200,
        )
    except httpx.HTTPStatusError as exc:
        print_error(_api_error_text(exc))
        return
    items = data.get("observations") or []
    if not items:
        print_info(f"No observations yet for engagement {engagement_id}.")
        return
    print_info(f"Observations ({data.get('total', len(items))}):")
    for o in items:
        details = o.get("details") or {}
        label = details.get("title") or details.get("url") or details.get("hostname") or o.get("target", "")
        print(f"  id={o['id']} [{o['type']}] {label}  (via {o.get('source_tool', '')}, seen {o.get('occurrence_count', 1)}x)")


def handle_file(args: list[str], client: "APIClient") -> None:
    """File an evidence-backed finding — the only explicit (human/LLM) path
    into the finding store.

    Usage: /file <finding_type> <observation_id[,observation_id...]> "<title>"
           [--severity none|info|low|medium|high|critical]
           [--evidence corroboration|reproduction|verification|attestation]
           [--evidence-tool <tool>] [--evidence-detail "..."] [--desc "..."]
           [--tags a,b] [--target <t>] [--engagement <id>]
    plans/harness/03-earned-finding-pipeline.md: there is no confidence flag —
    you attach evidence, confidence_for computes it from what you attach.
    Omit --evidence for a bare signal (stays HYPOTHESIS unless >=2 independent
    tools already observed it).
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    severity, args = _take_flag(args, "--severity")
    evidence_kind, args = _take_flag(args, "--evidence")
    evidence_tool, args = _take_flag(args, "--evidence-tool")
    evidence_detail, args = _take_flag(args, "--evidence-detail")
    description, args = _take_flag(args, "--desc")
    tags_raw, args = _take_flag(args, "--tags")
    target, args = _take_flag(args, "--target")
    if not _require_engagement(engagement_id):
        return
    if len(args) < 3:
        print_info('Usage: /file <finding_type> <observation_id,...> "<title>" [--severity ...] [--evidence ...]')
        return
    finding_type, obs_ids_raw, *title_parts = args
    title = " ".join(title_parts).strip()
    observation_ids = [x.strip() for x in obs_ids_raw.split(",") if x.strip()]
    evidence_records = []
    if evidence_kind:
        evidence_records.append({"kind": evidence_kind, "source_tool": evidence_tool or "", "detail": evidence_detail or ""})
    tags = [t.strip() for t in (tags_raw or "").replace(",", " ").split() if t.strip()]
    try:
        result = client.file_finding(
            engagement_id=engagement_id, title=title, finding_type=finding_type,
            observation_ids=observation_ids, claim_severity=severity or "none",
            description=description or "", evidence_records=evidence_records,
            target=target or "", tags=tags,
        )
    except httpx.HTTPStatusError as exc:
        print_error(_api_error_text(exc))
        return
    if result.get("suppressed"):
        print_info(f"Not filed — matches a known false-positive pattern: {result.get('suppressed_reason')}")
        return
    f = result.get("finding") or {}
    print_success(
        f"Filed finding id={f.get('id')} type={f.get('finding_type')} "
        f"confidence={f.get('confidence')} (computed) sev={f.get('claim_severity')}"
    )


def handle_world(args: list[str], client: "APIClient") -> None:
    """Query the world model — a read model over the observation-backed graph,
    not a new store.

    Usage: /world assets|related|incomplete|unexplained|conflicts [asset_id]
           [--type <asset_type>] [--engagement <id>]
      - assets: every asset node (optionally --type host|port|service|…).
      - related <asset_id>: what connects to it, closest first.
      - incomplete: HOST/SUBDOMAIN assets with no port evidence yet.
      - unexplained: observations not yet tied to any graph asset — raw
        material for /question or /hypothesis.
      - conflicts: assets with a disputed slot — both values kept, never
        silently picked.
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    asset_type, args = _take_flag(args, "--type")
    if not _require_engagement(engagement_id):
        return
    if not args:
        print_info("Usage: /world assets|related|incomplete|unexplained|conflicts [asset_id] [--type <t>]")
        return
    view = args[0].lower()
    items: list = []
    try:
        if view == "assets":
            data = client.world_model_assets(engagement_id, asset_type=asset_type or "")
            items = data.get("assets") or []
            for a in items[:80]:
                print(f"  {a['id']} confidence={a.get('confidence')} tools={a.get('source_tools')}")
        elif view == "related":
            if len(args) < 2:
                print_error("view='related' requires asset_id (e.g. 'host:example.com').")
                return
            data = client.world_model_related(engagement_id, args[1])
            items = data.get("related") or []
            for r in items[:80]:
                print(f"  {r['node_id']} ({r['hops']} hop via {r['via_relationship']})")
        elif view == "incomplete":
            data = client.world_model_incomplete(engagement_id)
            items = data.get("assets") or []
            for a in items[:80]:
                print(f"  {a['asset_id']}: {a['gap']}")
        elif view == "unexplained":
            data = client.world_model_unexplained(engagement_id)
            items = data.get("observations") or []
            for o in items[:80]:
                print(f"  {o['observation_id']} [{o['type']}] target={o['target']} via {o['source_tool']}")
        elif view == "conflicts":
            data = client.world_model_conflicts(engagement_id)
            items = data.get("conflicts") or []
            for c in items[:80]:
                vals = "; ".join(f"{slot}={[v['value'] for v in vs]}" for slot, vs in c["conflicts"].items())
                print(f"  {c['asset_id']}: {vals}")
        else:
            print_error("view must be one of assets|related|incomplete|unexplained|conflicts.")
            return
    except httpx.HTTPStatusError as exc:
        print_error(_api_error_text(exc))
        return
    print_info(f"view={view} count={len(items)}")


def handle_attackpath(args: list[str], client: "APIClient") -> None:
    """Attack path — an ordered chain of (observation|asset|hypothesis) steps,
    each with a rationale for why it connects to the next.

    Usage:
      /attackpath propose "<title>" <step_kind> <step_ref_id> ["<rationale>"]
      /attackpath advance <path_id> [--status investigating|validated|dead]
                                     [--finding <id>]
                                     [--step <kind> <ref_id> ["<rationale>"]]
      /attackpath list [--all]
      /attackpath get <path_id>
    step_kind is observation|asset|hypothesis.
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    if not args:
        print_info("Usage: /attackpath propose|advance|list|get ...")
        return
    action, *rest = args
    action = action.lower()
    try:
        if action == "propose":
            if not _require_engagement(engagement_id):
                return
            if len(rest) < 3:
                print_error('propose requires: "<title>" <step_kind> <step_ref_id> ["<rationale>"]')
                return
            title, step_kind, step_ref_id, *rationale_parts = rest
            step = {"kind": step_kind.lower(), "ref_id": step_ref_id, "rationale": " ".join(rationale_parts)}
            data = client.propose_attack_path(engagement_id, title=title, steps=[step])
            print_success(f"Attack path proposed: id={data.get('id')} status={data.get('status')}")
        elif action == "advance":
            if not rest:
                print_error("advance requires <path_id>")
                return
            path_id, sub = rest[0], rest[1:]
            status, sub = _take_flag(sub, "--status")
            finding_id, sub = _take_flag(sub, "--finding")
            step = None
            if "--step" in sub:
                idx = sub.index("--step")
                step_parts = sub[idx + 1:]
                if len(step_parts) >= 2:
                    step = {"kind": step_parts[0].lower(), "ref_id": step_parts[1], "rationale": " ".join(step_parts[2:])}
            data = client.advance_attack_path(path_id, status=status or "", finding_id=finding_id or "", step=step)
            print_success(f"Attack path advanced: id={data.get('id')} status={data.get('status')} hops={len(data.get('steps') or [])}")
        elif action == "list":
            if not _require_engagement(engagement_id):
                return
            data = client.list_attack_paths(engagement_id, active_only="--all" not in rest)
            paths = data.get("attack_paths") or []
            if not paths:
                print_info("No active attack paths.")
                return
            for p in paths:
                print(f"  [{p['id']}] {p['status']}: {p['title']} ({len(p['steps'])} hop(s))")
        elif action == "get":
            if not rest:
                print_error("get requires <path_id>")
                return
            data = client.get_attack_path(rest[0])
            print(json.dumps(data, indent=2, default=str))
        else:
            print_error("action must be propose|advance|list|get.")
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            print_error("No attack path with that id.")
        else:
            print_error(_api_error_text(exc))


def handle_question(args: list[str], client: "APIClient") -> None:
    """Open questions — a cheap reasoning scaffold, write freely, no approval
    needed.

    Usage:
      /question raise "<text>" [--asset <asset_id>]
      /question list [--all]
      /question answer <id> "<answer text>"
      /question dismiss <id>
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    if not args:
        print_info("Usage: /question raise|list|answer|dismiss ...")
        return
    action, *rest = args
    action = action.lower()
    try:
        if action == "raise":
            if not _require_engagement(engagement_id):
                return
            related, rest = _take_flag(rest, "--asset")
            text = " ".join(rest).strip()
            if not text:
                print_error('raise requires "<text>"')
                return
            data = client.raise_question(engagement_id, text=text, related_asset_id=related or "")
            print_success(f"Question raised: id={data.get('id')}: {data.get('text')}")
        elif action == "list":
            if not _require_engagement(engagement_id):
                return
            data = client.list_questions(engagement_id, open_only="--all" not in rest)
            items = data.get("questions") or []
            if not items:
                print_info("No open questions.")
                return
            for q in items:
                print(f"  [{q['id']}] {q['text']}")
        elif action == "answer":
            if len(rest) < 2:
                print_error('answer requires <id> "<answer text>"')
                return
            qid, *answer_parts = rest
            client.answer_question(qid, answer_text=" ".join(answer_parts))
            print_success(f"Question {qid} answered.")
        elif action == "dismiss":
            if not rest:
                print_error("dismiss requires <id>")
                return
            client.dismiss_question(rest[0])
            print_success(f"Question {rest[0]} dismissed.")
        else:
            print_error("action must be raise|list|answer|dismiss.")
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            print_error("No question with that id.")
        else:
            print_error(_api_error_text(exc))


def handle_hypothesis(args: list[str], client: "APIClient") -> None:
    """Active hypotheses — an unresolved claim the reasoner is still testing,
    distinct from a Finding's evidence law (a hypothesis can be strengthened
    OR weakened).

    Usage:
      /hypothesis raise "<statement>" [observation_id...]
      /hypothesis list [--all]
      /hypothesis evidence <id> <observation_id> <true|false>
      /hypothesis resolve <id> <confirmed|refuted>
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    if not args:
        print_info("Usage: /hypothesis raise|list|evidence|resolve ...")
        return
    action, *rest = args
    action = action.lower()
    try:
        if action == "raise":
            if not _require_engagement(engagement_id):
                return
            if not rest:
                print_error('raise requires "<statement>"')
                return
            statement, *obs_ids = rest
            data = client.raise_hypothesis(engagement_id, statement=statement, supporting_observation_ids=obs_ids)
            print_success(f"Hypothesis raised: id={data.get('id')}: {data.get('statement')}")
        elif action == "list":
            if not _require_engagement(engagement_id):
                return
            data = client.list_hypotheses(engagement_id, active_only="--all" not in rest)
            items = data.get("hypotheses") or []
            if not items:
                print_info("No active hypotheses.")
                return
            for h in items:
                print(
                    f"  [{h['id']}] {h['statement']} (support={len(h.get('supporting_observation_ids') or [])} "
                    f"contra={len(h.get('contradicting_observation_ids') or [])})"
                )
        elif action == "evidence":
            if len(rest) < 3:
                print_error("evidence requires <id> <observation_id> <true|false>")
                return
            hid, oid, supports_raw = rest[0], rest[1], rest[2]
            data = client.add_hypothesis_evidence(hid, observation_id=oid, supports=supports_raw.lower() in ("true", "1", "yes"))
            print_success(
                f"Evidence attached. supporting={data.get('supporting_observation_ids')} "
                f"contradicting={data.get('contradicting_observation_ids')}"
            )
        elif action == "resolve":
            if len(rest) < 2:
                print_error("resolve requires <id> <confirmed|refuted>")
                return
            hid, status = rest[0], rest[1]
            client.resolve_hypothesis(hid, status=status.lower())
            print_success(f"Hypothesis {hid} resolved as {status.lower()}.")
        else:
            print_error("action must be raise|list|evidence|resolve.")
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            print_error("No hypothesis with that id.")
        else:
            print_error(_api_error_text(exc))


def handle_priority(args: list[str], client: "APIClient") -> None:
    """What's worth doing next — a multi-factor score over the world model
    (observations, assets, questions, attack paths), ranked highest first.
    Never feeds back into a Finding's confidence (Plan 03's one law) — a low-
    confidence lead can still be the top priority.

    Usage: /priority [--kinds observation,asset,...] [--limit N] [--engagement <id>]
           /priority phase vuln|exploit [--engagement <id>]
    The phase form shows whether that area has crossed its unlock threshold
    (plans/harness/06-prioritization-engine.md Step 4 — replaces the old
    finding-count trigger) and the single highest-priority item driving it.
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    if not _require_engagement(engagement_id):
        return
    try:
        if args and args[0].lower() == "phase":
            if len(args) < 2:
                print_error("phase requires vuln|exploit")
                return
            data = client.phase_priority(engagement_id, args[1].lower())
            status = "UNLOCKED" if data.get("unlocked") else "locked"
            print_info(f"{data.get('phase')}: {status}")
            print(f"  {data.get('gate_reason', '')}")
            return
        kinds, args = _take_flag(args, "--kinds")
        limit_s, args = _take_flag(args, "--limit")
        data = client.top_priorities(engagement_id, kinds=kinds or "observation,asset,question,attack_path", limit=int(limit_s) if limit_s else 20)
        items = data.get("items") or []
        if not items:
            print_info("Nothing scored yet — no observations/assets/questions/attack paths.")
            return
        print_info(f"Top priorities ({len(items)}):")
        for it in items:
            print(f"  [{it['total']:.2f}] {it['item_kind']}:{it['type_key']} {it.get('label') or it.get('target', '')}")
    except httpx.HTTPStatusError as exc:
        print_error(_api_error_text(exc))


def handle_anomalies(args: list[str], client: "APIClient") -> None:
    """What looks weird right now — plans/harness/14-pentester-intelligence.md.
    Deterministic peer comparison (timing/version drift among sibling hosts),
    no LLM. Runs automatically after every recon pass already; this is for a
    fresh read on demand.

    Usage: /anomalies [--engagement <id>]
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    if not _require_engagement(engagement_id):
        return
    try:
        data = client.anomalies(engagement_id)
        anomalies = data.get("anomalies") or []
        if not anomalies:
            print_info("Nothing statistically odd yet (needs 3+ peer hosts under the same apex).")
            return
        print_info(f"Anomalies ({len(anomalies)}):")
        for a in anomalies:
            print(f"  [{a.get('kind')}] {a.get('title')}")
    except httpx.HTTPStatusError as exc:
        print_error(_api_error_text(exc))


def handle_context(args: list[str], client: "APIClient") -> None:
    """The context packet — the exact same world-model-derived state the LLM
    gets injected fresh every turn (plans/harness/07-context-packet.md), so a
    human operator can see it too without needing an LLM in the loop.

    Usage: /context [--engagement <id>]
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    if not _require_engagement(engagement_id):
        return
    try:
        packet = client.get_context_packet(engagement_id)
    except httpx.HTTPStatusError as exc:
        print_error(_api_error_text(exc))
        return
    print(packet)


def handle_skills(args: list[str], client: "APIClient") -> None:
    """Browse or query the skill library — plans/harness/08-skill-system-
    at-scale.md. Ranked retrieval, not a flat dump: at scale (hundreds of
    skills) "list everything" stops being useful, so `find` scores every
    skill against whatever you give it and returns the top matches.

    Usage:
      /skills                                    router-level index (cheap, always available)
      /skills list [--phase <phase>]              browse a phase, unranked
      /skills find [<query>] [--phase ..] [--tags a,b] [--mitre T1098] [--asset-type ..] [--limit N]
      /skills get <path-or-name>                  full text of one skill
    (Distinct from /skill, which reviews LLM-proposed learned skills.)
    """
    if not args or args[0].lower() == "list":
        phase, rest = _take_flag(args[1:] if args else [], "--phase")
        try:
            data = client.list_skills_index(phase=phase or "")
        except httpx.HTTPStatusError as exc:
            print_error(_api_error_text(exc))
            return
        items = data.get("skills") or []
        print_info(f"Skills ({data.get('count', len(items))}):")
        for it in items:
            print(f"  [{it.get('phase')}] {it.get('name')} — {it.get('description', '')[:100]}")
        return

    action, *rest = args
    action = action.lower()
    if action == "find":
        phase, rest = _take_flag(rest, "--phase")
        tags, rest = _take_flag(rest, "--tags")
        mitre, rest = _take_flag(rest, "--mitre")
        asset_type, rest = _take_flag(rest, "--asset-type")
        limit_s, rest = _take_flag(rest, "--limit")
        query = " ".join(rest).strip()
        try:
            data = client.find_skills(
                query=query, phase=phase or "", tags=tags or "", mitre=mitre or "",
                asset_type=asset_type or "", limit=int(limit_s) if limit_s else 8,
            )
        except httpx.HTTPStatusError as exc:
            print_error(_api_error_text(exc))
            return
        items = data.get("skills") or []
        if not items:
            print_info("No matching skills — try broader terms.")
            return
        print_info(f"Top {len(items)} matching skill(s):")
        for it in items:
            print(f"  [{it.get('phase')}] {it.get('name')} — {it.get('description', '')[:100]}")
        print_info("Use /skills get <name> for full text.")
    elif action == "get":
        if not rest:
            print_error("get requires <path-or-name>")
            return
        try:
            data = client.get_skill_file(rest[0])
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                print_error(f"No skill found matching '{rest[0]}'.")
            else:
                print_error(_api_error_text(exc))
            return
        print(f"# {data.get('path')} — {data.get('title')}\n")
        print(data.get("content") or "")
    else:
        print_info("Usage: /skills [list [--phase ..]] | find <query> ... | get <path-or-name>")


def handle_link(args: list[str], client: "APIClient") -> None:
    """Create an operator-named graph edge — cognition write-back.

    Usage: /link <source> <relation> <target> "<evidence>" [--confidence confirmed|likely|hypothesis]
    source/target: 'host:erp.x.com' or bare hostname/IP/URL. relation: free
    name (e.g. same_app_as, shares_auth_cookie). Non-confirmed becomes a
    hypothesis_* edge — not proof for COMPLETE/CRITICAL. evidence is
    required (why the link exists).
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    confidence, args = _take_flag(args, "--confidence")
    derived_from, args = _take_flag(args, "--derived-from")
    if not _require_engagement(engagement_id):
        return
    if len(args) < 4:
        print_error('Usage: /link <source> <relation> <target> "<evidence>"')
        return
    source, relation, target, *evidence_parts = args
    evidence = " ".join(evidence_parts).strip()
    try:
        data = client.graph_link(
            engagement_id=engagement_id, source=source, target=target, relation=relation,
            evidence=evidence, confidence=confidence or "likely", derived_from=derived_from or "",
        )
    except httpx.HTTPStatusError as exc:
        print_error(_api_error_text(exc))
        return
    print_success(
        f"{data.get('source_id')} --{data.get('relationship')}--> {data.get('target_id')} "
        f"(confidence={data.get('confidence')} hypothesis={data.get('hypothesis')})"
    )


def handle_record(args: list[str], client: "APIClient") -> None:
    """Record a reasoned conclusion — no prior tool output backs it (an
    interpretation, a hand-verified fact). For a relationship use /link; for
    an open-ended hypothesis use /hypothesis raise.

    Usage: /record <finding_type> "<title>" "<evidence>" [--severity ..] [--desc ..] [--tags ..]
    There is no confidence flag — like /file, the evidence you give becomes
    an attestation and confidence_for computes confidence from it.
    """
    engagement_id, args = _take_flag(args, "--engagement")
    engagement_id = engagement_id or client.active_engagement_id
    severity, args = _take_flag(args, "--severity")
    description, args = _take_flag(args, "--desc")
    tags_raw, args = _take_flag(args, "--tags")
    target, args = _take_flag(args, "--target")
    if not _require_engagement(engagement_id):
        return
    if len(args) < 3:
        print_error('Usage: /record <finding_type> "<title>" "<evidence>" [--severity ..] [--desc ..]')
        return
    finding_type, title, *evidence_parts = args
    evidence = " ".join(evidence_parts).strip()
    tags = [t.strip() for t in (tags_raw or "").replace(",", " ").split() if t.strip()]
    try:
        result = client.record_finding(
            engagement_id=engagement_id, title=title, evidence=evidence, finding_type=finding_type,
            claim_severity=severity or "none", description=description or "", target=target or "",
            tags=tags or ["operator_recorded"],
        )
    except httpx.HTTPStatusError as exc:
        print_error(_api_error_text(exc))
        return
    if result.get("suppressed"):
        print_info(f"Not filed — matches a known false-positive pattern: {result.get('suppressed_reason')}")
        return
    f = result.get("finding") or {}
    print_success(
        f"Recorded finding id={f.get('id')} type={f.get('finding_type')} "
        f"confidence={f.get('confidence')} (computed) sev={f.get('claim_severity')}"
    )


def handle_report(args: list[str], client: "APIClient") -> None:
    """Write a human-readable recon report to a Markdown file: seed domain ->
    sister/associated domains -> subdomains (nested) -> IPs -> ports/services/
    tech, plus WHOIS/OSINT and a short vulnerability summary — the actual
    pipeline shape, not a flat findings table. A terminal table can't show
    this well; a saved file you can open, search, or hand to someone can.

    Usage: /report [--engagement <id>]
    """
    engagement_id = client.active_engagement_id
    if "--engagement" in args:
        idx = args.index("--engagement")
        if idx + 1 < len(args):
            engagement_id = args[idx + 1]

    if not engagement_id:
        print_info("No engagement bound. Run /scan <target> or /engage new <target> first.")
        return

    md = client.get_report_markdown(engagement_id)
    if md is None:
        print_error(f"Could not generate a report for engagement {engagement_id}.")
        return

    from datetime import datetime, timezone
    from pathlib import Path

    target_line = md.splitlines()[0] if md else ""
    target = target_line.replace("# Recon Report — ", "").strip() or engagement_id
    safe_target = "".join(c if c.isalnum() or c in ".-" else "_" for c in target)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    out_path = reports_dir / f"{safe_target}_{timestamp}.md"
    out_path.write_text(md, encoding="utf-8")

    print_success(f"Report written: {out_path.resolve()}")
    print_info("Open it in any Markdown viewer (VS Code, Obsidian, GitHub) to read it properly.")


def _parse_skill_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Minimal `--- key: value ---` frontmatter parse (mirrors the backend)."""
    stripped = text.lstrip("﻿")
    if not stripped.startswith("---"):
        return {}, text
    lines = stripped.splitlines()
    meta: dict[str, str] = {}
    body_start = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            body_start = i + 1
            break
        if ":" in lines[i]:
            k, _, v = lines[i].partition(":")
            meta[k.strip()] = v.strip().strip('"').strip("'")
    if body_start is None:
        return {}, text
    return meta, "\n".join(lines[body_start:]).lstrip("\n")


def handle_skill(args: list[str], client: "APIClient") -> None:
    """Operator surface for the learned-skills tier: add your own, or review/approve
    the LLM's proposals."""
    sub = (args[0].lower() if args else "list")
    try:
        if sub == "add" and len(args) > 1:
            import os
            path = " ".join(args[1:]).strip().strip('"')
            if not os.path.isfile(path):
                print_error(f"File not found: {path}")
                return
            meta, body = _parse_skill_frontmatter(open(path, encoding="utf-8").read())
            if not meta.get("phase") or not meta.get("description"):
                print_error(
                    "The .md needs frontmatter with at least `phase:` and `description:` "
                    "(and ideally `name:`). See any file under skills/ for the format."
                )
                return
            payload = {
                "name": meta.get("name") or os.path.splitext(os.path.basename(path))[0],
                "phase": meta["phase"],
                "description": meta["description"],
                "content": body,
                "tags": [t.strip() for t in meta.get("tags", "").strip("[]").split(",") if t.strip()],
            }
            r = client.add_learned_skill(payload)
            print_success(f"Added — active at skills/{r.get('path')} ({r.get('phase')} phase).")
            return
        if sub == "list":
            data = client.list_learned_skills()
            props = data.get("proposals", [])
            active = data.get("active", [])
            if not props and not active:
                print_info(
                    "No learned skills yet. When enable_learned_skills=true, the LLM proposes "
                    "them (platform_propose_skill); you approve them here."
                )
                return
            if props:
                print_info(f"Pending proposals ({len(props)}) — /skill show <id>, then /skill approve|reject <id>:")
                for p in props:
                    print(f"  [{p['id']}] [{p['phase']}] {p['name']} — {p['description']}")
                    similar = p.get("similar_to") or []
                    if similar:
                        top = ", ".join(f"{s['skill']} ({s['score']})" for s in similar[:3])
                        print(f"      similar to: {top}")
            if active:
                print_info(f"Active learned skills ({len(active)}):")
                for a in active:
                    print(f"  {a['name']} [{a['phase']}] — {a['description']}")
        elif sub == "show" and len(args) > 1:
            data = client.list_learned_skills()
            p = next((x for x in data.get("proposals", []) if x["id"] == args[1]), None)
            if not p:
                print_error(f"No pending proposal with id {args[1]}.")
                return
            print(f"[{p['phase']}] {p['name']}\n{p['description']}\n\n{p['content']}")
            if p.get("evidence"):
                print(f"\nGrounded in: {p['evidence']}")
            similar = p.get("similar_to") or []
            if similar:
                top = ", ".join(f"{s['skill']} ({s['score']})" for s in similar)
                print(f"\nSimilar to: {top} — weigh novelty before approving.")
        elif sub == "approve" and len(args) > 1:
            r = client.approve_learned_skill(args[1])
            print_success(f"Approved — now active at skills/{r.get('path')} ({r.get('phase')} phase).")
        elif sub == "reject" and len(args) > 1:
            client.reject_learned_skill(args[1])
            print_info(f"Rejected proposal {args[1]}.")
        else:
            print_info(
                "Usage: /skill add <file.md>  (author your own, goes live immediately) | "
                "/skill list | /skill show <id> | /skill approve <id> | /skill reject <id>"
            )
    except Exception as exc:  # noqa: BLE001 — surface the API error text
        print_error(_api_error_text(exc))
