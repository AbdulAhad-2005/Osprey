"""Shared tool execution pipeline for the MCP endpoint and the phase agents."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import HTTPException

from osprey.schemas.audit import AuditAction
from osprey.schemas.hybrid import EscalationQuery, HybridExecutionMeta
from osprey.schemas.tools import ToolExecutionRequest, ToolExecutionResponse, ToolSafetyLevel
from osprey.services.audit_log import get_audit_log
from osprey.services.command_builder import build_command_for_tool
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.engagement_store import get_engagement_store
from osprey.services.exec_cache import get_exec_cache
from osprey.services.mcp_client import get_mcp_client
from osprey.services.param_validator import validate_raw
from osprey.services.parameter_profiles import profile_flags, select_profile
from osprey.services.rate_governor import (
    banned_targets,
    is_exempt,
    mark_ban,
    register_call,
    scan_for_ban,
    wait_seconds_for,
)
from osprey.services.escalation_registry import (
    auto_fallback_config,
    detect_signals,
    suggest_escalations,
)
from osprey.services.run_store import get_run_store
from osprey.services.session_context import resolve_for_tool_execution, resolve_session
from osprey.services.summary_agent import summarize_execution
from osprey.services.target_utils import extract_target
from osprey.services.task_registry import get_tool_capability
from osprey.services.tech_dispatch import suggest_dispatch
from osprey.services.tool_coverage_store import get_tool_coverage_store
from osprey.services.tool_registry import get_tool_definition

logger = logging.getLogger(__name__)


import re as _re

# A returncode of 0 is not proof of a real result. Two high-precision shapes mean
# "exit 0 but the run did NOT do what was asked", and reporting them as success is
# actively misleading (an operator trusts the green card):
#   * the tool printed its usage/help text (a bad invocation, e.g. ffuf with a
#     flag it rejects), or
#   * the body is an upstream HTTP 5xx error PAGE (e.g. crt.sh answering with a
#     502 Bad Gateway HTML page) — the query reached a broken provider, not data.
# Kept deliberately narrow so a scan that legitimately *reports* a 5xx (httpx
# "url [502]") or mentions "usage" mid-output is never downgraded.
_CLI_HELP_RE = _re.compile(r"^\s*usage:\s", _re.I)
_UPSTREAM_ERR_RE = _re.compile(
    r"(?is)<(?:title|h1)[^>]*>\s*50[234]\b"
    r"|\b50[234]\s+(?:bad gateway|service unavailable|gateway time-?out)\b"
)


def _detect_soft_failure(stdout: str, stderr: str) -> str:
    """Return a reason string if an exit-0 run is really a failure, else ''."""
    out = stdout or ""
    if not out.strip():
        return ""  # empty is handled separately (empty_success)
    low = out.lower()
    head = out.lstrip()[:400]
    if (
        _CLI_HELP_RE.match(head)
        or "unrecognized arguments" in low
        or "the following arguments are required" in low
        or "invalid choice:" in low
    ):
        return "tool printed usage/help text — bad invocation, not a result"
    if _UPSTREAM_ERR_RE.search(out) and ("<html" in low or "<title" in low or "<body" in low):
        return "response body is an upstream HTTP 5xx error page — provider unreachable, not data"
    return ""


async def execute_tool_request(
    request: ToolExecutionRequest, *, _fallback_depth: int = 0
) -> ToolExecutionResponse:
    tool_def = get_tool_definition(request.tool_name)
    if tool_def is None:
        from osprey.services.tool_registry import suggest_tool_names

        hints = suggest_tool_names(request.tool_name)
        hint = f" Did you mean: {', '.join(hints)}?" if hints else (
            " Use platform_tools() for the registered catalog (names end in _scan/_probe)."
        )
        raise HTTPException(
            status_code=404,
            detail=f"Tool not registered: {request.tool_name}.{hint}",
        )

    # Propagate the resolved canonical name for the rest of this request.
    # get_tool_definition() already resolves aliases (e.g. autorecon_comprehensive
    # -> autorecon_scan) to build tool_def correctly, and command_builder.py
    # separately re-resolves to tool_def.name for the actual module path — so
    # the deployed docker-exec execution path was never broken by an alias
    # call. But request.tool_name itself stayed the raw alias string
    # everywhere else in this function: alternative_tools_for() lookups,
    # coverage/audit records (an alias and its canonical name would fragment into two
    # separate "tools" in history), and the shadow-recovery/chunk-detection
    # hooks added in this same function. Rewriting once here means every
    # future alias correctly consolidates under one name everywhere, instead
    # of each call site needing its own alias-awareness.
    request.tool_name = tool_def.name

    target = extract_target(request.params)

    # When MCP passes a bound engagement_id, keep it — tool params may be subdomains/hosts.
    if (request.engagement_id or "").strip():
        session = resolve_session(
            engagement_id=request.engagement_id,
            run_id=request.run_id,
            seed_target="",
        )
    else:
        try:
            session = resolve_for_tool_execution(
                engagement_id=request.engagement_id,
                run_id=request.run_id,
                seed_target=target,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    request.engagement_id = session.engagement_id
    request.run_id = session.run_id or request.run_id

    engagement = get_engagement_store().get(session.engagement_id)
    if engagement is None:
        raise HTTPException(status_code=404, detail=f"Engagement not found: {session.engagement_id}")

    if tool_def.safety_level == ToolSafetyLevel.GATED:
        roe = engagement.rules_of_engagement
        if not roe.allow_exploitation:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"{tool_def.name} is GATED (exploitation-tier): engagement "
                    f"RulesOfEngagement.allow_exploitation is False. Set it on the engagement "
                    f"before this tool can run."
                ),
            )
        if request.blast_radius == "destructive" and not roe.destructive_actions_allowed:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"{tool_def.name} destructive-tier call blocked: engagement "
                    f"RulesOfEngagement.destructive_actions_allowed is False. Retry with "
                    f"blast_radius='poc' or get destructive actions authorized on the engagement."
                ),
            )

    if request.run_id:
        get_run_store().ensure(run_id=request.run_id, engagement_id=session.engagement_id)

    exec_params = dict(request.params)
    if request.additional_args:
        exec_params.setdefault("additional_args", request.additional_args)

    # Fill primary target from engagement seed when agent omitted all aliases.
    from osprey.services.agent_arg_normalizer import primary_param_for_tool

    primary = primary_param_for_tool(request.tool_name)
    seed = (getattr(engagement, "target", None) or getattr(engagement, "seed_target", None) or "").strip()
    if primary and seed and not extract_target(exec_params):
        exec_params[primary] = seed
        logger.info(
            "Injected engagement seed %r into %s param %s",
            seed,
            request.tool_name,
            primary,
        )

    validation = validate_raw(
        request.tool_name,
        exec_params,
        additional_args=request.additional_args,
    )
    if not validation.approved:
        raise HTTPException(status_code=400, detail=validation.reason)

    # Per-apex canonicalization: email anti-spoofing posture (SPF/DKIM/DMARC) is
    # published at the registrable domain, so probing sub1.example.com and
    # sub2.example.com yields the SAME org-level answer. Rewrite the domain to
    # its apex so repeat calls on different subdomains dedup against one cache
    # entry (and the probe targets the authoritative name). NOT applied to
    # well_known_probe — robots.txt / sitemap.xml / security.txt are per-host,
    # so collapsing subdomains there would return the wrong file.
    if request.tool_name == "email_security_probe":
        from osprey.services.target_utils import registrable_apex

        for _key in ("domain", "target", "host"):
            _val = validation.normalized_params.get(_key)
            if _val and str(_val).strip():
                _apex = registrable_apex(str(_val))
                if _apex:
                    validation.normalized_params[_key] = _apex

    # Keep request.params aligned with what will actually run (aliases remapped).
    request.params = dict(validation.normalized_params)
    target = extract_target(request.params) or target

    # Component 2 — pre-flight chunking. Must run BEFORE enforce_scan_budget,
    # not as a reaction to its refusal: enforce_scan_budget raises synchronously
    # before any tool ever executes, so there is no failure to "recover from"
    # for the wide-range case — width has to be detected and split here, ahead
    # of the budget check, not caught after it. A routine wide-range request
    # (not a genuinely large/unusual one — see chunk_port_range's own cap)
    # transparently becomes N job-store-managed chunks with no human
    # interruption; confirm_expensive remains untouched as the gate for
    # anything chunk_port_range correctly declines to auto-split.
    from osprey.services.scan_budget import is_truthy

    if not is_truthy(request.params.get("confirm_expensive")):
        deferred = await _maybe_dispatch_chunked(request, session, target)
        if deferred is not None:
            return deferred

    # Expensive full-range / wide port scans: ask human first (unless confirm_expensive).
    from osprey.services.scan_budget import enforce_scan_budget

    try:
        enforce_scan_budget(
            tool_name=request.tool_name,
            params=request.params,
            additional_args=request.additional_args or "",
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    # Recon/network: always enable recovery suggestions.
    if tool_def.category.value in ("recon", "network"):
        request.use_recovery = True

    cache = get_exec_cache()
    cache_key = cache.make_key(
        engagement_id=session.engagement_id,
        tool_name=request.tool_name,
        params=validation.normalized_params,
        additional_args=request.additional_args or "",
    )
    # force_refresh always bypasses cache; still expose cache_key for transparency.
    use_cache = bool(request.use_cache) and not bool(request.force_refresh)
    if use_cache:
        cached = cache.get(cache_key)
        if cached is not None:
            cached.cache_hit = True
            cached.cache_key = cache_key
            # The cache-hit note (and the partial/timed-out re-run hint) is rendered
            # by the reading surface from cache_hit/timed_out/partial flags — no need
            # to bolt advisory text onto the response here.
            logger.info("exec cache hit tool=%s engagement=%s", request.tool_name, session.engagement_id)
            return cached

    cap = get_tool_capability(request.tool_name)
    freeform_field = cap.freeform_args_field if cap else "additional_args"

    # Intensity profile → extra flags, injected into the freeform args that BOTH
    # the preview and the real execution (mcp.call_tool reads normalized_params
    # ["additional_args"]) consume. Inert in the common case (NORMAL adds
    # nothing); STEALTH auto-engages when the rate governor has this target in
    # cooldown, so a blocking edge is probed gently rather than at full intensity.
    # Profile flags go first so any explicit flag the LLM passed still wins on
    # order-sensitive tools.
    target_hot = bool(target) and target.lower() in {
        t.lower() for t in banned_targets(session.engagement_id)
    }
    applied_profile = select_profile(
        explicit=str(validation.normalized_params.get("profile") or "") or None,
        target_hot=target_hot,
    )
    pflags = profile_flags(request.tool_name, applied_profile)
    if pflags:
        _existing = str(validation.normalized_params.get("additional_args") or "").strip()
        validation.normalized_params["additional_args"] = (
            f"{pflags} {_existing}".strip() if _existing else pflags
        )
    try:
        preview_command = build_command_for_tool(
            request.tool_name,
            validation.normalized_params,
            additional_args="",
            freeform_field=freeform_field,
        )
    except (ValueError, OSError, ImportError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Best-effort parallel-agent safety: two branches (e.g. separate web/network
    # jobs on the same engagement) hitting the same tool+asset concurrently is
    # wasted work, not a correctness issue — so a failed claim is logged and the
    # call proceeds anyway, same "advisory, never blocks" contract as the rest
    # of tool_coverage_store. A bug in claim bookkeeping must never stall or
    # error out normal single-agent execution.
    claim_asset = target or str(request.params.get("domain", ""))
    got_claim = True
    try:
        got_claim = get_tool_coverage_store().try_claim(
            engagement_id=session.engagement_id, tool_name=request.tool_name,
            asset=claim_asset, run_id=request.run_id or "",
        )
        if not got_claim:
            logger.debug(
                "Concurrent claim held for %s on %s (engagement %s) — proceeding anyway (advisory)",
                request.tool_name, claim_asset, session.engagement_id,
            )
    except Exception as exc:  # noqa: BLE001
        logger.debug("Claim attempt skipped: %s", exc)

    mcp = get_mcp_client()
    try:
        # Rate governor: pace calls per target (sliding window) so a mechanical
        # fan-out doesn't trip the target's WAF/rate-limiter mid-pass. A pacer,
        # never a gate — exempt passive/external lookups, and never wait longer
        # than the configured ceiling.
        if not is_exempt(request.tool_name):
            wait_s = wait_seconds_for(session.engagement_id, target)
            if wait_s > 0:
                logger.info(
                    "rate governor: pacing %s on %s for %.1fs (engagement %s)",
                    request.tool_name, target, wait_s, session.engagement_id,
                )
                await asyncio.sleep(wait_s)
            register_call(session.engagement_id, target)
        response = await mcp.call_tool(
            tool_name=request.tool_name,
            params=validation.normalized_params,
            timeout=request.timeout,
            prebuilt_command=preview_command,
        )
    finally:
        try:
            get_tool_coverage_store().release(
                engagement_id=session.engagement_id, tool_name=request.tool_name, asset=claim_asset,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Claim release skipped: %s", exc)

    response.cache_key = cache_key
    response.cache_hit = False
    response.force_refresh_applied = bool(request.force_refresh)
    if response.timed_out and (response.stdout or "").strip():
        response.partial = True
    if not response.command:
        response.command = preview_command

    # Ban detector: when a WAF/rate-limiter fingerprint shows up in the tool's
    # output, cool the target down (further calls to it get paced/spread by the
    # governor) and record ONE observation so the report explains why the
    # surface went thin instead of looking like a lazy pass. Deduped per
    # engagement+target by mark_ban's "already cooling down" return.
    if not is_exempt(request.tool_name):
        ban_signal = scan_for_ban(response.stdout or "")
        if ban_signal and mark_ban(session.engagement_id, target, ban_signal):
            try:
                from osprey.schemas.finding import (
                    EvidenceGrade,
                    Finding,
                    FindingConfidence,
                    FindingType,
                )

                from osprey.services.findings_store import get_findings_store

                get_findings_store().add(
                    Finding(
                        engagement_id=session.engagement_id,
                        run_id=request.run_id or "",
                        phase="recon",
                        finding_type=FindingType.OBSERVATION,
                        title=f"Rate-limited/blocked: {target} ({ban_signal})",
                        description=(
                            f"{request.tool_name} output shows a WAF/rate-limiter response "
                            f"('{ban_signal}'). Further calls to {target} are being paced "
                            f"to avoid escalating the block."
                        ),
                        evidence=(response.stdout or "")[:400],
                        confidence=FindingConfidence.CONFIRMED,
                        evidence_grade=EvidenceGrade.OBSERVED,
                        source_tool="rate_governor",
                        target=target,
                        tags=["rate_limited", "waf_blocked", "pacing"],
                    )
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("Ban observation ingest failed: %s", exc)

    # Honest status: a returncode-0 run whose body is help text or an upstream 5xx
    # page is a failure, not a success — downgrade before findings/coverage record
    # so nothing green is reported for it and recovery/fallback kicks in.
    if response.success and not response.timed_out:
        _soft = _detect_soft_failure(response.stdout or "", response.stderr or "")
        if _soft:
            response.success = False
            response.error = (response.error or _soft)
            logger.info(
                "soft-failure downgrade tool=%s engagement=%s: %s",
                request.tool_name, session.engagement_id, _soft,
            )

    asset = target or str(request.params.get("domain", ""))
    findings: list = []
    if request.record_findings:
        try:
            # Always persist raw/observation (even on failure) so memory is never empty.
            findings = await summarize_execution(
                response,
                engagement_id=session.engagement_id,
                run_id=request.run_id or "",
                target=target,
                force_raw_observation=True,
            )
            # Universal ingest — every tool inherits YAML rules (SPA demotion, banners, …).
            from osprey.services.ingest_promoter import apply_ingest_rules

            ingested = apply_ingest_rules(
                response.stdout or "",
                response.stderr or "",
                engagement_id=session.engagement_id,
                run_id=request.run_id or "",
                source_tool=request.tool_name,
                target=target or asset,
                persist=True,
            )
            titles = [f.title for f in findings] + [f.title for f in ingested]
            # de-dupe preserve order
            response.finding_titles = list(dict.fromkeys(titles))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Findings ingest failed for %s: %s", request.tool_name, exc)
        try:
            get_tool_coverage_store().record(
                engagement_id=session.engagement_id,
                tool_name=request.tool_name,
                asset=asset,
                run_id=request.run_id or "",
                findings_count=len(response.finding_titles or []),
                success=bool(response.success),
                notes="advisory mark only",
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Tool coverage record skip: %s", exc)

    if request.exploit_candidate_id:
        try:
            from osprey.services.exploit_candidate_store import get_exploit_candidate_store

            result_finding_id = findings[0].id if findings else ""
            attempt_success = bool(response.success) and bool(findings)
            updated_candidate = get_exploit_candidate_store().record_attempt(
                request.exploit_candidate_id,
                success=attempt_success,
                result_finding_id=result_finding_id,
            )
            candidate = get_exploit_candidate_store().get(request.exploit_candidate_id)
            if candidate and candidate.finding_id and findings:
                from osprey.services.findings_store import get_findings_store

                for f in findings:
                    existing = list(f.metadata.get("derived_from") or [])
                    if candidate.finding_id not in existing:
                        existing.append(candidate.finding_id)
                        f.metadata["derived_from"] = existing
                get_findings_store().add_many_result(findings)

            if candidate is not None:
                from osprey.services.exploit_chain_store import (
                    ExploitStep,
                    get_exploit_chain_store,
                    outcome_for_finding,
                )

                chain = get_exploit_chain_store().get_or_create_for_candidate(
                    engagement_id=session.engagement_id, candidate_id=candidate.id,
                )
                result_finding = findings[0] if findings else None
                outcome = (
                    outcome_for_finding(
                        result_finding, exhausted=bool(updated_candidate and updated_candidate.exhausted),
                    )
                    if result_finding is not None
                    else ("failed" if updated_candidate and updated_candidate.exhausted else "attempted")
                )
                get_exploit_chain_store().append_step(
                    chain.id,
                    ExploitStep(
                        asset=asset, technique=candidate.promotion_trigger,
                        tool=request.tool_name, result="success" if attempt_success else "no result",
                        evidence_finding_id=result_finding_id,
                    ),
                    outcome=outcome,
                )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Exploit candidate correlation skip: %s", exc)

    # Lightweight stdout index — path + snippet (full body on Kali when path set)
    try:
        from osprey.services.artifacts import write_text_artifact
        from osprey.services.stdout_index import record_stdout_entry

        arts = {}
        if isinstance(response.hybrid, dict):
            arts = response.hybrid.get("artifacts") or {}
        if not arts and isinstance(response.parsed, dict):
            arts = response.parsed.get("artifacts") or {}
        stdout_path = str(arts.get("stdout_path") or "")
        stderr_path = str(arts.get("stderr_path") or "")
        if not stdout_path and (response.stdout or "").strip():
            stdout_path = await write_text_artifact(
                session.engagement_id,
                prefix=request.tool_name or "tool",
                content=response.stdout or "",
            )
        record_stdout_entry(
            engagement_id=session.engagement_id,
            tool_name=request.tool_name,
            target=target or asset,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            snippet=(response.stdout or "")[:800],
            bytes_hint=len((response.stdout or "").encode("utf-8", errors="replace")),
            success=bool(response.success),
        )
        if stdout_path:
            hybrid_meta = response.hybrid if isinstance(response.hybrid, dict) else {}
            hybrid_meta = dict(hybrid_meta)
            arts_out = dict(hybrid_meta.get("artifacts") or {})
            arts_out["stdout_path"] = stdout_path
            if stderr_path:
                arts_out["stderr_path"] = stderr_path
            hybrid_meta["artifacts"] = arts_out
            response.hybrid = hybrid_meta
    except Exception as exc:  # noqa: BLE001
        logger.debug("stdout index skip: %s", exc)

    get_engagement_store().increment_tools_executed(session.engagement_id)

    # Recovery / fallbacks — always for fail, timeout, OR empty "success".
    empty_success = bool(response.success) and not (response.stdout or "").strip()
    _shadow_classify_and_observe(
        response,
        engagement_id=session.engagement_id,
        run_id=request.run_id or "",
        tool_name=request.tool_name,
        asset=asset,
        empty_success=empty_success,
    )
    need_recovery = bool(request.use_recovery) and (
        not response.success or response.timed_out or empty_success
    )
    if request.use_recovery or need_recovery:
        hybrid = _build_hybrid_meta(
            response,
            target=target,
            params=validation.normalized_params,
            engagement_id=session.engagement_id,
            run_id=request.run_id or "",
            phase=cap.phase if cap else tool_def.category.value,
            force_escalation=need_recovery,
        )
        if hybrid.escalation_suggestions:
            response.alternative_tool_suggested = hybrid.escalation_suggestions[0].tool_name
        prev_arts = {}
        if isinstance(response.hybrid, dict):
            prev_arts = dict((response.hybrid.get("artifacts") or {}))
        dumped = hybrid.model_dump()
        if prev_arts:
            arts = dict(dumped.get("artifacts") or {})
            arts.update(prev_arts)
            dumped["artifacts"] = arts
        response.hybrid = dumped

    # Parsed-output compression (a real transformation, not a nudge) stays; the
    # advisory recovery/parallel/memory hint text was removed — it duplicated the
    # skills + phase-readiness layer and bloated every tool response. The
    # deterministic recovery *actions* (_maybe_auto_fallback below,
    # _maybe_auto_scan_network_vulns in the conductor) remain.
    _attach_digest(response)

    if pflags:
        hm = dict(response.hybrid) if isinstance(response.hybrid, dict) else {}
        hm["parameter_profile"] = {
            "profile": applied_profile,
            "flags": pflags,
            "auto_stealth": bool(target_hot),
        }
        response.hybrid = hm

    if use_cache:
        cache.set(cache_key, response)

    get_audit_log().record(
        AuditAction(
            tool_name=request.tool_name,
            target=target,
            engagement_id=session.engagement_id,
            command=f"{request.tool_name}({request.params})",
            success=response.success,
            returncode=response.returncode,
            duration_seconds=response.duration_seconds,
            error=response.error,
            recovery_action=response.alternative_tool_suggested,
        )
    )

    # Auto-execute the top fallback on a clean failure (never on a WAF/rate-limit/
    # ban — those mean back off). Conservative: one hop, honours the rate governor.
    fb = await _maybe_auto_fallback(
        request,
        response,
        target=target,
        empty_success=empty_success,
        depth=_fallback_depth,
    )
    if fb is not None:
        return fb
    return response


# Only these keys carry across to a fallback tool — target identity, not the
# original tool's private flags (which may be meaningless or invalid elsewhere).
_CARRY_PARAM_KEYS = frozenset({"target", "domain", "url", "host", "hostname", "ip", "ports"})


async def _maybe_auto_fallback(
    request: ToolExecutionRequest,
    response: ToolExecutionResponse,
    *,
    target: str,
    empty_success: bool,
    depth: int,
) -> ToolExecutionResponse | None:
    """Run the top escalation for a failed tool automatically, or return None.

    Fires only on a clean failure (error / empty / timeout), never on a back-off
    signal (WAF / rate-limit / ban) and never against a target the rate governor
    has put in cooldown — so it saves the LLM a turn without ever escalating a
    failure into a scan flood. Capped by ``auto_fallback.max_depth`` (default 1).
    """
    if not request.use_recovery or response.cache_hit:
        return None
    cfg = auto_fallback_config()
    if not cfg.get("enabled") or depth >= int(cfg.get("max_depth") or 0):
        return None
    if not ((not response.success) or response.timed_out or empty_success):
        return None

    query = EscalationQuery(
        tool_name=response.tool_name,
        error=response.error or "",
        stderr=response.stderr or "",
        stdout=response.stdout or "",
        returncode=response.returncode,
        timed_out=response.timed_out,
        target=target,
    )
    signals = {s.lower() for s in detect_signals(query)}
    if signals & set(cfg.get("skip_signals") or ()):
        return None  # back-off signal — trying more tools would only make it worse
    if target and target.lower() in {t.lower() for t in banned_targets(request.engagement_id)}:
        return None

    pick = next(
        (
            s
            for s in suggest_escalations(query)
            if (s.tool_name or "").strip()
            and s.action in ("alternate_tool", "adjust_params", "alternate_path")
        ),
        None,
    )
    if pick is None:
        return None
    # A same-tool retry must actually change the invocation, else it just re-fails.
    if pick.tool_name == response.tool_name and not (pick.additional_args or pick.params):
        return None

    carry = {k: v for k, v in (request.params or {}).items() if k in _CARRY_PARAM_KEYS}
    fb_request = ToolExecutionRequest(
        tool_name=pick.tool_name,
        params={**carry, **(pick.params or {})},
        additional_args=pick.additional_args or "",
        engagement_id=request.engagement_id,
        run_id=request.run_id,
        use_recovery=True,
        use_cache=bool(request.use_cache),
    )
    logger.info(
        "auto-fallback: %s failed (%s) → running %s (engagement %s, depth %d)",
        response.tool_name, ",".join(sorted(signals)) or "empty",
        pick.tool_name, request.engagement_id, depth + 1,
    )
    try:
        fb = await execute_tool_request(fb_request, _fallback_depth=depth + 1)
    except HTTPException as exc:
        logger.debug("auto-fallback %s skipped: %s", pick.tool_name, exc.detail)
        return None

    hyb = dict(fb.hybrid) if isinstance(fb.hybrid, dict) else {}
    hyb["auto_fallback"] = {
        "from_tool": response.tool_name,
        "ran_tool": pick.tool_name,
        "reason": pick.reason,
        "original_signals": sorted(signals),
    }
    fb.hybrid = hyb
    fb.next_hint = (
        f"AUTO-FALLBACK: {response.tool_name} failed/empty "
        f"({', '.join(sorted(signals)) or 'no output'}); platform auto-ran "
        f"{pick.tool_name}. {fb.next_hint or ''}"
    ).strip()
    return fb


def _attach_digest(response: ToolExecutionResponse) -> None:
    """Compact per-tool digest (registry.digest_tool_output) alongside raw stdout.

    Built for the LLM-agent path (platform/adaptation.py) but never reached the
    OpenCode/MCP path — every operator front-end reads this same HTTP response,
    so computing it once here means both get it, instead of only the path that
    happened to call the digest function directly in-process.
    """
    if not response.success or not (response.stdout or "").strip():
        return
    try:
        from osprey.services.parsers.registry import digest_tool_output, ensure_parsers_loaded

        ensure_parsers_loaded()
        digest = digest_tool_output(response.tool_name, response.stdout)
        if not digest:
            return
        hybrid = dict(response.hybrid) if isinstance(response.hybrid, dict) else {}
        hybrid["digest"] = digest
        response.hybrid = hybrid
    except Exception:
        return


async def _maybe_dispatch_chunked(
    request: ToolExecutionRequest,
    session: Any,
    target: str,
) -> ToolExecutionResponse | None:
    """Component 2 pre-flight: if this is a routine wide port-range request on
    a chunkable tool, split it into narrow chunks and queue each as a job —
    return an immediate deferred response instead of ever attempting the wide
    call as one shot. None = not a chunkable-wide request; caller proceeds to
    the normal enforce_scan_budget path unchanged.

    Deliberately returns immediately rather than blocking for chunks to
    finish: a slow full-range scan can run for hours, which would just
    recreate the timeout this exists to solve, and blocking here would
    silently break the synchronous tool-call contract the caller expects.
    Findings from each chunk auto-ingest as that chunk's own job completes —
    the deferred response is honest about being partial, not a fabricated
    "done."
    """
    from osprey.services.scan_budget import chunk_port_range

    chunks = chunk_port_range(
        tool_name=request.tool_name,
        params=request.params,
        additional_args=request.additional_args or "",
    )
    if not chunks:
        return None

    from osprey.schemas.jobs import JobKind, JobStartRequest
    from osprey.services.job_store import get_job_store

    job_store = get_job_store()
    job_ids: list[str] = []
    for i, chunk_params in enumerate(chunks, start=1):
        chunk_args = str(chunk_params.pop("_additional_args_override", ""))
        try:
            job = job_store.create_and_spawn(
                JobStartRequest(
                    kind=JobKind.TOOL,
                    engagement_id=session.engagement_id,
                    run_id=request.run_id or "",
                    label=f"auto-chunk {i}/{len(chunks)}: {request.tool_name}({chunk_params.get('ports')})",
                    tool_name=request.tool_name,
                    params=chunk_params,
                    additional_args=chunk_args,
                    record_findings=bool(request.record_findings),
                    timeout=max(300, min(int(request.timeout or 300), 3600)),
                )
            )
            job_ids.append(job.job_id)
        except ValueError as exc:
            # Concurrency cap hit mid-dispatch — stop queuing more, report what
            # was actually queued rather than silently losing the rest of the
            # range. Not a failure: partial chunking is still real progress.
            logger.info("chunk dispatch stopped at %d/%d: %s", i - 1, len(chunks), exc)
            break

    if not job_ids:
        # Every chunk was refused (e.g. concurrency cap already full) — fall
        # through to the normal path rather than claiming a deferred success
        # that queued nothing.
        return None

    logger.info(
        "auto-chunked %s into %d/%d job(s) engagement=%s",
        request.tool_name,
        len(job_ids),
        len(chunks),
        session.engagement_id,
    )
    return ToolExecutionResponse(
        tool_name=request.tool_name,
        success=True,
        command=f"(chunked into {len(job_ids)} background job(s))",
        stdout="",
        stderr="",
        finding_titles=[],
        recovery_info={
            "deferred": True,
            "job_ids": job_ids,
            "chunk_count": len(job_ids),
            "requested_chunk_count": len(chunks),
            "reason": (
                f"Wide port range auto-chunked into {len(job_ids)} background job(s) "
                "instead of one oversized call. Poll with platform_job_poll / "
                "platform_job_result — findings auto-ingest as each chunk completes."
            ),
        },
        next_hint=(
            f"Chunked into {len(job_ids)} background job(s): {', '.join(job_ids)}. "
            "Continue other work; poll these with platform_job_poll."
        ),
    )


def _shadow_classify_and_observe(
    response: ToolExecutionResponse,
    *,
    engagement_id: str,
    run_id: str,
    tool_name: str,
    asset: str,
    empty_success: bool,
) -> None:
    """Component 1, shadow mode: classify this call's outcome and log what the
    recovery engine WOULD have recommended — never acts on it. Also backfills
    the comparison signal (llm_subsequent_tool/success) onto the most recent
    unresolved observation for the same (engagement, asset), since that's the
    only thing that tells us whether the fixed strategy order matches reality,
    not just the table's own internal self-consistency. Best-effort — must
    never affect the response or raise into the caller.
    """
    if not engagement_id or not tool_name:
        return
    try:
        from osprey.services.execution_recovery import classify_error, next_strategy
        from osprey.services.recovery_observation_store import get_recovery_observation_store

        store = get_recovery_observation_store()

        # Resolve whatever the PRIOR observation for this asset was waiting to
        # learn — this call IS that comparison signal for it.
        store.backfill_subsequent_action(
            engagement_id=engagement_id,
            asset=asset,
            subsequent_tool=tool_name,
            subsequent_success=bool(response.success) and not empty_success,
        )

        error_type = classify_error(
            exit_code=int(response.returncode or 0),
            stdout=response.stdout or "",
            stderr=response.stderr or "",
            empty_success=empty_success,
        )
        if error_type is None:
            return
        strategy = next_strategy(error_type, attempt=1)
        store.record(
            engagement_id=engagement_id,
            run_id=run_id,
            tool_name=tool_name,
            asset=asset,
            error_type=error_type.value,
            exit_code=int(response.returncode or 0),
            shadow_strategy=strategy.action.value if strategy else "",
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("shadow recovery classify skip: %s", exc)


def _build_hybrid_meta(
    response: ToolExecutionResponse,
    *,
    target: str,
    params: dict,
    engagement_id: str,
    run_id: str,
    phase: str,
    force_escalation: bool = False,
) -> HybridExecutionMeta:
    graph_pivots: list[str] = []
    graph = get_engagement_graph().summary(engagement_id=engagement_id, run_id=run_id)
    graph_pivots.extend(graph.pivot_hints)

    if target:
        sib = get_engagement_graph().siblings_same_ip(target, engagement_id=engagement_id)
        if sib.siblings:
            graph_pivots.append(sib.hint)

    escalations = []
    if force_escalation or not response.success or response.timed_out:
        query = EscalationQuery(
            tool_name=response.tool_name,
            error=response.error or "",
            stderr=response.stderr or "",
            stdout=response.stdout or "",
            returncode=response.returncode,
            timed_out=response.timed_out,
            target=target,
        )
        escalations = suggest_escalations(query)
    elif response.stdout:
        thin = EscalationQuery(
            tool_name=response.tool_name,
            stdout=response.stdout,
            returncode=0,
        )
        escalations = suggest_escalations(thin)

    dispatch = suggest_dispatch(engagement_id=engagement_id, run_id=run_id, phase=phase)

    return HybridExecutionMeta(
        escalation_suggestions=escalations[:5],
        dispatch_suggestions=dispatch[:5],
        graph_pivots=graph_pivots[:10],
    )
