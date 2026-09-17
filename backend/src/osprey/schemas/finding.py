"""Structured findings for Commander memory.

Designed for both clean parser output and messy/unstructured tool results:
- ``metadata`` — small typed-ish hints (hostname, port, …)
- ``extra`` — arbitrary nested JSON when shape is unknown
- ``tags`` — free-form labels (e.g. sister_domain, cloudflare, unverified)
- ``raw_data`` — truncated unstructured blob / extract when parse is incomplete
- ``notes`` — human or agent annotations
- ``confidence`` — confirmed | likely | hypothesis: how sure we are the finding is real
- ``claim_severity`` — impact if the finding is real; assigned honestly by the parser/agent,
  not derived or clamped from anything else. See skills/vuln/verification-and-severity.md.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class FindingType(StrEnum):
    SUBDOMAIN = "subdomain"
    HOST = "host"
    URL = "url"
    PORT = "port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    OBSERVATION = "observation"
    VULNERABILITY = "vulnerability"  # scanner/manual finding with a severity
    DNS_RECORD = "dns_record"  # MX/NS/CNAME/TXT and similar records for a domain/host
    # ── Passive OSINT identity producers (map 1:1 to AssetType entities) ──
    EMAIL = "email"
    USERNAME = "username"
    PERSON = "person"
    PHONE = "phone"
    SOCIAL_ACCOUNT = "social_account"
    ORGANIZATION = "organization"
    DOCUMENT = "document"
    # ── Downstream (exploit / post-exploit / dashboard) producers ──
    CREDENTIAL = "credential"  # username/password/token pair or account access material
    SECRET = "secret"  # API key, private key, hardcoded token found in output/code
    HTTP_RESPONSE = "http_response"  # response envelope (status/type/body ref) for an entry point
    ACCESS = "access"  # exploit-readiness / candidate entry point handed to the exploit agent


# Narrative findings: identity depends on title + evidence, not just the asset it
# concerns (two distinct vulns on one host differ by title/evidence). Structural
# findings (subdomain/host/port/…) are identified by the asset alone, so repeated
# observations of the same asset merge into one canonical finding.
_NARRATIVE_TYPES: frozenset[FindingType] = frozenset(
    {
        FindingType.OBSERVATION,
        FindingType.VULNERABILITY,
        FindingType.CREDENTIAL,
        FindingType.SECRET,
        FindingType.HTTP_RESPONSE,
        FindingType.ACCESS,
    }
)


class FindingConfidence(StrEnum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    HYPOTHESIS = "hypothesis"


class ClaimSeverity(StrEnum):
    NONE = "none"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    engagement_id: str = ""
    run_id: str = ""
    phase: str = ""
    finding_type: FindingType
    title: str
    description: str = ""
    evidence: str = ""
    confidence: FindingConfidence = FindingConfidence.CONFIRMED
    claim_severity: ClaimSeverity = ClaimSeverity.NONE
    source_tool: str = ""
    target: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary nested payload when tool output does not fit metadata.",
    )
    raw_data: str = Field(
        default="",
        description="Unstructured excerpt (stdout slice, HTML fragment, etc.).",
    )
    notes: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Read-only enrichment, populated when loaded from the store (ignored on write).
    occurrence_count: int | None = Field(
        default=None, description="Times this canonical fact was observed (read-only)."
    )
    node_id: str | None = Field(
        default=None, description="Primary graph node this finding concerns (read-only)."
    )


# Types whose label (title) recurs legitimately across hosts — the same technology
# or port number on two hosts is two distinct facts, so the host must anchor identity.
_HOST_ANCHOR_TYPES: frozenset[FindingType] = frozenset(
    {
        FindingType.TECHNOLOGY,
        FindingType.PORT,
        FindingType.SERVICE,
    }
)


def _normalize_ws(text: str) -> str:
    return " ".join((text or "").split()).strip().lower()


def _host_anchor(finding: Finding) -> str:
    """A host/target context used to disambiguate same-label facts across hosts."""
    meta = finding.metadata or {}
    for key in ("ip", "hostname", "host"):
        val = str(meta.get(key) or "").strip().lower()
        if val:
            return val
    return _normalize_ws(finding.target)


_VOLATILE_EVIDENCE_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}(?:\.\d+)?z?\b"  # ISO 8601 timestamp
    r"|\b\d{1,2}:\d{2}:\d{2}\b"  # bare HH:MM:SS
    r"|\(\d+(?:\.\d+)?s latency\)"  # nmap host latency
    r"|\bscanned in [\d.]+ seconds?\b",
    re.IGNORECASE,
)


def _normalize_evidence_for_fingerprint(evidence: str) -> str:
    """Evidence text can carry volatile substrings (timestamps, scan latency)
    and non-deterministically ordered multi-line content (e.g. nmap vulners
    CVE blocks, whose entry order isn't guaranteed identical run-to-run) that
    differ between two scans of the same underlying fact. Fingerprinting raw
    evidence would fracture one real, recurring finding into many canonical
    rows instead of building occurrence history across re-scans. Strip known
    volatile patterns and sort lines so the fingerprint reflects the
    evidence's content, not the specific run/ordering that produced it."""
    text = _VOLATILE_EVIDENCE_RE.sub("", evidence or "")
    lines = sorted(_normalize_ws(line) for line in text.splitlines() if line.strip())
    return "\n".join(lines) if lines else _normalize_ws(text)


def finding_fingerprint(finding: Finding) -> str:
    """Stable semantic identity for occurrence-vs-canonical de-duplication.

    Deliberately excludes ``source_tool`` so the same fact seen by two tools maps to
    one canonical finding (each tool recorded as a separate occurrence).

    Identity is anchored on the finding's own ``title`` — for structural findings the
    title *is* the asset (hostname, URL, email). ``target`` (the seed/parent a finding
    was discovered under) is never the sole anchor, so two sibling assets discovered
    under one seed never collapse. Host-anchored types (technology/port/service) fold
    in the host so the same label on two hosts stays distinct; narrative types fold in
    the target and an evidence signature so distinct facts on one asset never collapse.
    """
    title = _normalize_ws(finding.title)
    parts = [finding.engagement_id or "", finding.finding_type.value]
    if finding.finding_type in _HOST_ANCHOR_TYPES:
        parts.append(_host_anchor(finding))
        parts.append(title)
    elif finding.finding_type in _NARRATIVE_TYPES:
        parts.append(_normalize_ws(finding.target))
        parts.append(title)
        parts.append(
            hashlib.sha256(_normalize_evidence_for_fingerprint(finding.evidence).encode()).hexdigest()[:16]
        )
    else:
        parts.append(title or _normalize_ws(finding.target))
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


class FindingListResponse(BaseModel):
    findings: list[Finding]
    total: int


class GroupedFinding(BaseModel):
    """One row per distinct vuln/issue *pattern*, not per host:port instance —
    the same nmap NSE script firing on 8 ports of one host, or the same
    finding shape across many hosts, collapses into one row with an affected-
    target list, instead of 8 near-identical rows a human has to notice are
    the same thing. Display-layer only: every individual Finding still exists
    underneath, unmodified."""

    title: str
    finding_type: str
    source_tool: str
    severity: str
    confidence: str
    count: int
    affected_targets: list[str]
    sample_finding_id: str
    sample_evidence: str = ""


class GroupedFindingListResponse(BaseModel):
    groups: list[GroupedFinding]
    total_groups: int
    total_findings: int
