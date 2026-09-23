"""Structural facts extracted from tool output — never a verdict.

plans/harness/02-evidence-and-observation-layer.md: parsers may extract
structure (``port=443, service=nginx``) but may not decide something is a
vulnerability. ``Observation`` is the only thing structural extraction is
allowed to produce; findings (a judged claim) are earned from observations by
the pipeline in ``schemas/finding.py`` + ``services/confidence.py``.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ObservationType(StrEnum):
    SUBDOMAIN = "subdomain"
    HOST = "host"
    URL = "url"
    PORT = "port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    DNS_RECORD = "dns_record"
    HTTP_RESPONSE = "http_response"
    HEADER = "header"
    BANNER = "banner"
    CONTENT_PATH = "content_path"
    JS_ENDPOINT = "js_endpoint"
    ENDPOINT = "endpoint"
    COOKIE = "cookie"
    REDIRECT = "redirect"
    CERT = "cert"
    WAF = "waf"
    # SMB/AD/NetBIOS enumeration facts.
    SHARE = "share"
    ACCOUNT = "account"
    # BGP/ASN attribution (asn_enum).
    ASN = "asn"
    # Passive OSINT identity facts (map 1:1 to AssetType entities).
    EMAIL = "email"
    USERNAME = "username"
    PERSON = "person"
    PHONE = "phone"
    SOCIAL_ACCOUNT = "social_account"
    ORGANIZATION = "organization"
    DOCUMENT = "document"
    # Downstream material — still just a fact that was observed, not a verdict.
    CREDENTIAL = "credential"
    SECRET = "secret"
    # A scanner emitted a signal (template match, parameter surface, …) — a
    # fact that the scanner said something, never that a vuln exists.
    SCANNER_SIGNAL = "scanner_signal"
    INJECTION_POINT = "injection_point"
    # Last-resort structural extraction failed entirely — the raw blob is
    # still preserved as a fact ("this tool produced this output"), never a
    # placeholder Finding (see registry._raw_observation_fallback, replaced).
    RAW = "raw"


class ObservationSource(StrEnum):
    PARSER = "parser"
    LLM = "llm"
    HUMAN = "human"


class Observation(BaseModel):
    """A typed fact with provenance. Confidence is always literally
    ``"observed"`` — an observation never carries a judgment; ``confidence_for``
    (Plan 03) computes a *finding's* confidence from the evidence attached to
    it, of which observations are one input."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    engagement_id: str = ""
    run_id: str = ""
    evidence_id: str = ""
    type: ObservationType
    details: dict[str, Any] = Field(default_factory=dict)
    confidence: str = "observed"
    source_tool: str = ""
    target: str = ""
    extracted_by: ObservationSource = ObservationSource.PARSER
    # Structural categorization only ("typosquat", "empty_result", a network
    # name) — never a severity/verdict label. Kept free-form like Finding.tags
    # since many parsers already reason in these terms.
    tags: list[str] = Field(default_factory=list)
    signature: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Read-only enrichment populated when loaded from the store (ignored on write).
    occurrence_count: int | None = Field(
        default=None, description="Times this canonical fact was observed (read-only)."
    )
    last_seen_at: datetime | None = Field(default=None, description="Read-only.")


def _normalize_ws(text: str) -> str:
    return " ".join((text or "").split()).strip().lower()


def _normalize_details(details: dict[str, Any]) -> str:
    """Deterministic, order-independent string form of ``details`` for
    fingerprinting — same content, same signature, regardless of dict
    insertion order or an int vs str "port"."""
    items = sorted((str(k), str(v)) for k, v in (details or {}).items())
    return "|".join(f"{k}={_normalize_ws(v)}" for k, v in items)


def observation_signature(obs: Observation) -> str:
    """Stable identity for dedup: ``type + target + normalized-details``.

    Deliberately excludes ``source_tool``/``run_id``/``evidence_id`` so the
    same fact seen again (a re-scan, or a second tool corroborating it) merges
    into the existing row instead of creating a duplicate — see
    ``observation_store.record``.
    """
    parts = [
        obs.engagement_id or "",
        obs.type.value,
        _normalize_ws(obs.target),
        _normalize_details(obs.details),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


_VOLATILE_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}(?:\.\d+)?z?\b|\b\d{1,2}:\d{2}:\d{2}\b",
    re.IGNORECASE,
)


def strip_volatile(text: str) -> str:
    """Same volatile-substring stripping ``schemas.finding`` applies before
    fingerprinting evidence text — timestamps must not fracture one recurring
    fact into many canonical rows."""
    return _VOLATILE_RE.sub("", text or "")


class ObservationListResponse(BaseModel):
    observations: list[Observation]
    total: int


class Evidence(BaseModel):
    """Promoted, queryable record of one tool run's raw output — a first-class
    row over what ``stdout_index``/``artifacts`` already write, per Plan 02
    Step 1. The full untruncated body stays on disk (``stdout_path``); this
    row is the pointer + metadata every Observation cites via ``evidence_id``.
    """

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    engagement_id: str = ""
    run_id: str = ""
    tool_name: str = ""
    target: str = ""
    command: str = ""
    stdout_path: str = ""
    stderr_path: str = ""
    exit_code: int = 0
    duration_ms: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Whether structural extraction has run over this evidence yet — lets the
    # optional LLM observation-extraction layer (Plan 02 Step 5) work a
    # backlog instead of re-scanning everything.
    observed: bool = False
