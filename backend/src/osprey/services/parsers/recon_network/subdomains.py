"""Subdomain / liveness / domain-hunter parsers."""

from __future__ import annotations

import json
import re
from typing import Any

from osprey.schemas.observation import Observation, ObservationType
from osprey.services.target_utils import looks_like_domain, registrable_apex


def parse_subfinder(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    out: list[Observation] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        host = line.strip().lower()
        if not host or host.startswith("#") or " " in host:
            continue
        if "." not in host:
            continue
        if host in seen:
            continue
        seen.add(host)
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.SUBDOMAIN,
                target=target,
                source_tool="subfinder_scan",
                details={"hostname": host},
            )
        )
    return out


# httpx prints these bracketed markers (instead of a status code) when a
# probe could not connect — they are not technology fingerprints.
_HTTPX_FAILURE_MARKERS = {"failed", "timeout", "err", "error"}


def parse_httpx(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    out: list[Observation] = []
    for line in stdout.splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue

        brackets = re.findall(r"\[([^\]]*)\]", text)
        if any(b.strip().lower() in _HTTPX_FAILURE_MARKERS for b in brackets):
            # Connection failed — not a live endpoint, nothing to fingerprint.
            continue

        url_match = re.search(r"https?://\S+", text)
        url = url_match.group(0) if url_match else text.split()[0]

        # With -sc/-title/-td, httpx emits multiple bracket groups
        # (e.g. "[200] [Title] [nginx,PHP]"); tech-detect output is the
        # last one and, unlike a status code, is never purely numeric.
        tech = ""
        for b in reversed(brackets):
            b = b.strip()
            if b and not b.isdigit():
                tech = b
                break

        host = ""
        try:
            host = url.split("//")[-1].split("/")[0].split(":")[0].lower()
        except Exception:
            host = ""

        is_cf = _looks_like_cloudflare(text, tech)
        tags: list[str] = []
        details: dict = {"hostname": host} if host else {}
        details["url"] = url
        if tech:
            details["technology"] = tech
        if is_cf:
            details["is_cloudflare"] = True
            details["waf"] = "cloudflare"
            tags.append("cloudflare")

        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.URL,
                target=url,
                source_tool="httpx_probe",
                details={**details, "raw": text[:500]},
                tags=tags,
            )
        )
        if tech:
            out.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id,
                    type=ObservationType.TECHNOLOGY,
                    target=url,
                    source_tool="httpx_probe",
                    details={"name": tech, "hostname": host, "url": url},
                    tags=["cloudflare"] if is_cf else [],
                )
            )
    return out


_CF_RE = re.compile(
    r"cloudflare|cf-ray|cf-cache-status|__cf_bm|cf-mitigated|server:\s*cloudflare",
    re.IGNORECASE,
)


def _looks_like_cloudflare(text: str, tech: str = "") -> bool:
    blob = f"{text} {tech}"
    return bool(_CF_RE.search(blob))


_DH_ROW_RE = re.compile(
    r"^(?P<domain>\S+\.\S+)\s+(?P<method>.+?)\s+(?P<conf>low|medium|high)\s+(?P<live>Yes|No)\s*$"
)
_DHJSON_PREFIX = "# DHJSON "


def _domain_hunter_rows(stdout: str):
    """Yield (domain, method, confidence, live, score, evidence) from the last snapshot.

    Prefer the last ``# DHJSON`` line (including ``[]`` so a filtered-empty
    final result is not overwritten by earlier progress tables). Fall back to
    the last ``=== Findings ===`` table for older output.
    """
    json_blocks: list[list[tuple]] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith(_DHJSON_PREFIX):
            payload = stripped[len(_DHJSON_PREFIX) :]
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if isinstance(data, list):
                json_blocks.append([_dh_row_from_dict(item) for item in data if isinstance(item, dict)])
    if json_blocks:
        yield from (row for row in json_blocks[-1] if row is not None)
        return
    yield from _domain_hunter_table_rows(stdout)


def _dh_row_from_dict(row: dict) -> tuple | None:
    raw = str(row.get("domain", "") or "").strip()
    apex = registrable_apex(raw)
    if not apex or not looks_like_domain(apex):
        return None
    live = row.get("live")
    if isinstance(live, str):
        live = live.strip().lower() in {"yes", "true", "1"}
    else:
        live = bool(live)
    conf = str(row.get("confidence", "low") or "low").strip().lower()
    if conf not in ("low", "medium", "high"):
        conf = "low"
    return (
        apex.lower(),
        str(row.get("method", "") or "").strip() or "unknown",
        conf,
        live,
        row.get("score"),
        row.get("evidence") or [],
    )


def _domain_hunter_table_rows(stdout: str):
    """Last findings table, including an empty final ``(none)`` block."""
    last_block: list = []
    block: list = []
    in_findings = False
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("=== Findings"):
            if in_findings:
                last_block = block
            in_findings = True
            block = []
            continue
        if not in_findings:
            continue
        if stripped.startswith("Wrote ") or (stripped.startswith("===") and not stripped.startswith("=== Findings")):
            continue
        if not stripped or stripped.startswith("Domain ") or stripped == "(none)":
            continue
        match = _DH_ROW_RE.match(stripped)
        if match:
            apex = registrable_apex(match.group("domain"))
            if not apex or not looks_like_domain(apex):
                continue
            block.append(
                (
                    apex.lower(),
                    match.group("method").strip(),
                    match.group("conf"),
                    match.group("live") == "Yes",
                    None,
                    [],
                )
            )
    if in_findings:
        last_block = block
    yield from last_block


def parse_domain_hunter(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    out: list[Observation] = []
    seen: set[str] = set()
    seed_apex = registrable_apex(target) if target else ""
    for domain, method, conf, live, score, evidence in _domain_hunter_rows(stdout):
        if domain in seen:
            continue
        if seed_apex and domain == seed_apex.lower():
            continue
        seen.add(domain)
        evidence_text = evidence if isinstance(evidence, str) else " | ".join(str(item) for item in evidence if item)
        tags = ["sister_domain", "domain_hunter"]
        details: dict[str, Any] = {
            "hostname": domain,
            "method": method,
            "hunter_confidence": conf,
            "live": live,
            "role": "sister_domain",
        }
        if score is not None:
            details["score"] = score
        if evidence:
            details["hunter_evidence"] = evidence
            details["evidence_text"] = evidence_text
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.HOST,
                target=target,
                source_tool="domain_hunter",
                details=details,
                tags=tags,
            )
        )
    return out


_OS_DETAILS_RE = re.compile(r"^OS details:\s*(.+)$")
_OS_AGGRESSIVE_RE = re.compile(r"^Aggressive OS guesses:\s*(.+)$")
_OS_RUNNING_RE = re.compile(r"^Running:\s*(.+)$")
_OS_NO_MATCH_RE = re.compile(r"^No exact OS matches for host")

