"""Parser and stdout digest registries — phases register tools without changing the kernel.

Parsers extract structure only — they produce ``Observation``s, never a
``Finding``. See plans/harness/02-evidence-and-observation-layer.md.
"""

from __future__ import annotations

import logging
import re
from typing import Callable

from osprey.schemas.observation import Observation, ObservationType

logger = logging.getLogger(__name__)

ParserFn = Callable[..., list[Observation]]
DigestFn = Callable[[str], str]

_OUTPUT_PARSERS: dict[str, ParserFn] = {}
_OUTPUT_DIGESTERS: dict[str, DigestFn] = {}
_DEFAULT_PHASE = "unknown"


def register_output_parser(tool_name: str, parser: ParserFn) -> None:
    _OUTPUT_PARSERS[tool_name] = parser


def register_output_digester(tool_name: str, digester: DigestFn) -> None:
    _OUTPUT_DIGESTERS[tool_name] = digester


def register_many(
    tool_names: list[str],
    *,
    parser: ParserFn | None = None,
    digester: DigestFn | None = None,
) -> None:
    for name in tool_names:
        if parser is not None:
            register_output_parser(name, parser)
        if digester is not None:
            register_output_digester(name, digester)


def _raw_observation_fallback(
    tool_name: str, stdout: str, *, engagement_id: str, run_id: str, target: str
) -> list[Observation]:
    """Last-resort fallback when no deterministic parser exists and LLM
    extraction is unavailable/fails/suppressed — a single raw blob, never
    nothing."""
    if not stdout.strip():
        return []
    return [
        Observation(
            engagement_id=engagement_id,
            run_id=run_id,
            type=ObservationType.RAW,
            target=target,
            source_tool=tool_name,
            details={"snippet": stdout[:2000]},
            tags=["unparsed"],
        )
    ]


# Host-list tools whose OUTPUT IS the host list: when a run produces no
# host-like lines at all (e.g. amass without an API key prints only a
# "Session Scope" banner, subfinder hitting no sources, fierce on a domain
# with nothing to report), that is a legitimate EMPTY RESULT — LLM
# extraction would otherwise re-phrase the banner into a fake "Session
# Scope" observation and pad the report with noise.
_HOST_LIST_TOOLS = frozenset({"subfinder_scan", "amass_scan", "fierce_scan", "dnsenum_scan"})

_HOST_LIKE_RE = re.compile(r"^\s*[a-z0-9](?:[a-z0-9\-.]{0,251}[a-z0-9])?\.(?:[a-z]{2,24}|xn--[a-z0-9\-]+)\s*$", re.I)

# An upstream error page (502/503/429/… from nginx/Cloudflare/… behind a
# passive lookup like crt.sh) is not tool output — the tool never reached the
# service. Same shape discipline as the ban-signal check: HTML-document shape
# plus an explicit status or gateway marker, never a bare word like "error".
# These must not become "raw output" observations that pad the report.
_ERROR_PAGE_SIZE_CAP = 64 * 1024


def _looks_like_upstream_error(stdout: str) -> bool:
    low = (stdout or "").lower()
    if not low.strip() or len(low) > _ERROR_PAGE_SIZE_CAP:
        return False
    if "<html" not in low and "<!doctype html" not in low and "<title>" not in low:
        return False
    # Real error pages carry text after the status ('404 Not Found', '503
    # Service Unavailable') — allow anything up to the closing tag.
    if re.search(r"<(?:title|h1)[^>]*>\s*(?:error\s*)?([45]\d{2})[\s\S]{0,80}?</(?:title|h1)>", low):
        return True
    if ("bad gateway" in low or "gateway timeout" in low or "service unavailable" in low) and (
        "nginx" in low or "cloudflare" in low or "cf-ray" in low
    ):
        return True
    return False


# Verdict tools: when the tool genuinely ran (its run-marker appears in the
# output) but produced no verdict line, that is an AUTHORITATIVE empty result
# ("no WAF detected"), not something the LLM/raw fallback should re-phrase
# into a placeholder — same principle as the host-list tools above.
_VERDICT_TOOLS = frozenset({"wafw00f_scan"})


def _tool_genuinely_ran(tool_name: str, stdout: str) -> bool:
    if tool_name == "wafw00f_scan":
        low = (stdout or "").lower()
        return "wafw00f" in low or "w00f" in low or "[*] checking" in low
    return False


def _is_empty_host_list(tool_name: str, stdout: str) -> bool:
    """True when a host-list tool's output contains no host-like line: the
    deterministic parser found nothing, and there is genuinely nothing there."""
    if tool_name not in _HOST_LIST_TOOLS:
        return False
    if not stdout.strip():
        return True
    return not any(_HOST_LIKE_RE.match(line) for line in stdout.splitlines())


async def parse_tool_output(
    tool_name: str,
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
    phase: str = "",
    allow_llm_fallback: bool = True,
) -> list[Observation]:
    """A registered parser existing doesn't mean it recognized THIS run's
    output — a parser that legitimately finds nothing structured in a given
    stdout blob (e.g. crt_sh_query's JSON came back in an unexpected shape,
    wafw00f detected nothing) needs the exact same recovery as having no
    parser at all: try LLM structural extraction before giving up to a bare
    "raw output" placeholder. One recovery path, used either way.

    ``allow_llm_fallback=False`` disables that recovery path everywhere in
    this function (deterministic replay — see services/benchmark/replay.py);
    every other caller keeps the default and is unaffected. ``phase`` is
    accepted for call-site compatibility but no longer stamped onto anything
    here — Observations carry no phase; that's display-layer only now.
    """
    parser = _OUTPUT_PARSERS.get(tool_name)
    parsed: list[Observation] = []
    if parser is not None:
        # Parsers vary in accepted kwargs — try full then minimal.
        try:
            parsed = parser(stdout, engagement_id=engagement_id, run_id=run_id, target=target)
        except TypeError:
            parsed = parser(stdout, engagement_id=engagement_id, run_id=run_id)
        if parsed:
            # Shared parsers (e.g. parse_subfinder handles subfinder_scan AND
            # amass_scan AND fierce_scan) may hardcode a default source_tool
            # — observations must always be attributed to the tool that
            # actually ran, never to its sibling that shares the parser.
            relabeled: list[Observation] = []
            for o in parsed:
                if o.source_tool and o.source_tool != tool_name:
                    o = o.model_copy(update={"source_tool": tool_name})
                relabeled.append(o)
            return relabeled

        # domain_hunter that printed a findings snapshot (table or JSON) but
        # produced no sisters is an authoritative empty result — do not
        # LLM-rewrite progress banners into fake affiliated domains.
        if tool_name == "domain_hunter" and (
            "=== Findings" in (stdout or "") or "# DHJSON " in (stdout or "")
        ):
            return []

    # A host-list tool that found no hosts is a legitimate empty result — the
    # deterministic parser already said "nothing", and the LLM would only
    # re-word the tool's own banner (amass "Session Scope") into fake
    # observations. Skip extraction for these.
    if _is_empty_host_list(tool_name, stdout):
        return []

    if not stdout.strip():
        return []

    # A verdict tool that genuinely ran but produced no verdict line is an
    # authoritative empty result (wafw00f: "no WAF detected"), not raw output.
    if tool_name in _VERDICT_TOOLS and _tool_genuinely_ran(tool_name, stdout):
        return []

    # An upstream error page is not tool output — no observation at all, not
    # a raw placeholder.
    if _looks_like_upstream_error(stdout):
        return []

    if allow_llm_fallback:
        from osprey.services.parsers.observation_engine import extract as extract_observations

        extracted = await extract_observations(
            tool_name, stdout, engagement_id=engagement_id, run_id=run_id, target=target,
        )
        if extracted:
            return extracted
    return _raw_observation_fallback(
        tool_name, stdout, engagement_id=engagement_id, run_id=run_id, target=target
    )


def digest_tool_output(tool_name: str, stdout: str, *, max_items: int = 12) -> str:
    digester = _OUTPUT_DIGESTERS.get(tool_name)
    if digester is not None:
        try:
            return digester(stdout)
        except TypeError:
            return digester(stdout)

    lines = [ln for ln in stdout.splitlines() if ln.strip()]
    if len(lines) <= 3:
        return ""
    return f"{len(lines)} output lines; first: " + " | ".join(lines[:3])


def ensure_parsers_loaded() -> None:
    """Import phase parser modules so they self-register."""
    try:
        from osprey.services.parsers import recon_network  # noqa: F401
    except ImportError as exc:
        logger.debug("Parser module load skipped: %s", exc)
    try:
        from osprey.services.parsers import osint  # noqa: F401
    except ImportError as exc:
        logger.debug("OSINT parser module load skipped: %s", exc)
    try:
        from osprey.services.parsers import network_enum  # noqa: F401
    except ImportError as exc:
        logger.debug("Network-enum parser module load skipped: %s", exc)
    try:
        from osprey.services.parsers import web_recon  # noqa: F401
    except ImportError as exc:
        logger.debug("Web-recon parser module load skipped: %s", exc)
    try:
        from osprey.services.parsers import vuln  # noqa: F401
    except ImportError as exc:
        logger.debug("Vuln parser module load skipped: %s", exc)
    try:
        from osprey.services.parsers import browser  # noqa: F401
    except ImportError as exc:
        logger.debug("Browser parser module load skipped: %s", exc)
    try:
        from osprey.services.parsers import creds  # noqa: F401
    except ImportError as exc:
        logger.debug("Creds parser module load skipped: %s", exc)
    # Optional private-overlay parsers (for example, a company credential
    # manager). Absent in
    # public Osprey — a missing module is a no-op, not an error.
    try:
        from osprey.services.parsers import creds_private  # noqa: F401
    except ImportError:
        pass
