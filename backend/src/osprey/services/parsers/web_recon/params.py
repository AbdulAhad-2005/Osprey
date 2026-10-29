"""Parsers for the first-class web-recon tools (content / parameter / JS / policy).

All observations are RECON-phase structural facts: discovered paths, hidden
parameters, JS endpoints and secrets, cloud-storage exposure, and email/policy
posture. Parameters and endpoints are additionally tagged
``injection_point_candidate`` so the eventual vuln phase inherits a
ready-made attack-surface list instead of re-deriving it from raw URL dumps
(the "attack-surface handoff" seed).

Nothing here claims impact it did not observe — a content hit is a fact that
an HTTP response was seen at that status; whether a hardcoded secret is valid,
or a weak SPF policy is worth reporting, is `confidence_for`'s job (Plan 03),
never this module's.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlparse

from osprey.schemas.observation import Observation, ObservationType

from osprey.services.parsers.web_recon._shared import _host_of



# ---------------------------------------------------------------------------
# Parameter discovery — arjun text + passive extraction from URL corpora
# ---------------------------------------------------------------------------
_ARJUN_FOUND_RE = re.compile(r"(?i)parameters?\s+found\s*[:>-]*\s*(.+)$")


def _ensure_param_in_url(url: str, param: str) -> str:
    """A discovered parameter name is only a real, testable injection point if
    it actually appears in a request. Passive mining (extract_parameters_from_
    urls, reading gau/wayback/katana archives) already hands this a URL whose
    query string contains ``param``. Active discovery (arjun/x8) only reports
    the NAME against the bare endpoint it probed — plan 19 found this is
    exactly why sqlmap ran against a parameterless root URL and reported
    nothing. Synthesize a minimal test value here so every INJECTION_POINT
    observation carries one directly-testable URL regardless of which tool
    found it, instead of leaving that synthesis to a YAML dispatch rule."""
    if not url:
        return url
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
    except ValueError:
        return url
    if param in qs:
        return url
    separator = "&" if parsed.query else "?"
    return f"{url}{separator}{param}=1"


def _param_observation(param, url, *, source_tool, engagement_id, run_id, target):
    test_url = _ensure_param_in_url(url, param)
    return Observation(
        engagement_id=engagement_id,
        run_id=run_id,
        type=ObservationType.INJECTION_POINT,
        target=test_url or target,
        source_tool=source_tool,
        details={"parameter": param, "url": test_url, "hostname": _host_of(url)},
        tags=["parameter", "injection_point_candidate", source_tool],
    )


def parse_arjun(stdout, *, engagement_id="", run_id="", target=""):
    out: list[Observation] = []
    seen: set[str] = set()
    for line in (stdout or "").splitlines():
        m = _ARJUN_FOUND_RE.search(line.strip())
        if not m:
            continue
        for param in re.split(r"[,\s]+", m.group(1).strip()):
            param = param.strip().strip("'\"[]")
            if not param or not re.match(r"^[A-Za-z0-9_.\-\[\]]{1,40}$", param) or param in seen:
                continue
            seen.add(param)
            out.append(_param_observation(
                param, target, source_tool="arjun_scan",
                engagement_id=engagement_id, run_id=run_id, target=target,
            ))
    return out


_X8_FOUND_RE = re.compile(r"(?i)(?:found|discovered|reflects?|new)\b.*?[:\-]?\s*([A-Za-z0-9_.\-\[\]]{1,40})\s*$")
_X8_PARAM_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.\-\[\]]{1,40}$")


def parse_x8(stdout, *, engagement_id="", run_id="", target=""):
    """x8 active param brute output → injection-point candidate observations.

    x8's terminal output varies by version; it flags each discovered parameter,
    often as a bare token or after a 'found'/'reflects' marker. We accept both a
    JSON list of params and line tokens, and reuse the shared param observation.
    """
    out: list[Observation] = []
    seen: set[str] = set()
    text = (stdout or "").strip()

    def _emit(param: str) -> None:
        param = param.strip().strip("'\"[](),")
        if not param or param in seen or not _X8_PARAM_TOKEN_RE.match(param):
            return
        # Drop obvious non-params (status words, http verbs).
        if param.lower() in {"get", "post", "put", "delete", "found", "new", "reflects", "none", "true", "false"}:
            return
        seen.add(param)
        out.append(_param_observation(
            param, target, source_tool="x8_parameter_discovery",
            engagement_id=engagement_id, run_id=run_id, target=target,
        ))

    # JSON form: {"params": [...]} or a bare list.
    if text.startswith(("{", "[")):
        try:
            data = json.loads(text)
            items = data.get("params") if isinstance(data, dict) else data
            for it in items or []:
                _emit(str(it if not isinstance(it, dict) else it.get("name", "")))
            if out:
                return out
        except (json.JSONDecodeError, AttributeError, TypeError):
            pass

    for line in text.splitlines():
        line = line.strip()
        # x8 marks found params with a leading indicator or lists them plainly.
        m = _X8_FOUND_RE.search(line)
        if m:
            _emit(m.group(1))
    return out


def extract_parameters_from_urls(urls, *, source_tool, engagement_id, run_id, target, max_params=120):
    """Passive param mining: pull unique parameter names out of a URL corpus
    (gau / wayback / katana output). Cheap replacement for the flaky paramspider
    CLI — the archive URLs we already collect ARE the parameter source."""
    out: list[Observation] = []
    seen: set[tuple[str, str]] = set()
    for url in urls:
        try:
            qs = parse_qs(urlparse(url).query)
        except ValueError:
            continue
        host = _host_of(url)
        for param in qs:
            key = (host, param)
            if key in seen or not re.match(r"^[A-Za-z0-9_.\-\[\]]{1,40}$", param):
                continue
            seen.add(key)
            out.append(_param_observation(
                param, url, source_tool=source_tool,
                engagement_id=engagement_id, run_id=run_id, target=target,
            ))
            if len(out) >= max_params:
                return out
    return out
