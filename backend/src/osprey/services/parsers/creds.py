"""Parsers for credential-harvesting sources (IntelX, Resecurity, and the shared
helper the private creds-manager overlay reuses).

These turn a source tool's JSON stdout into typed findings:

* CREDENTIAL — a username/email + password pair. The real values are kept intact
  (offensive use, never masked) so the report can show the leaked credential, and
  the exploit phase (`exploit_pipeline._credential_candidates`) can promote it to a
  ``credential_bruteforce`` task. ``metadata.hostname`` links it to its host in the
  engagement graph (``exposes_credential`` edge).
* EMAIL — every address seen (harvested or leaked), an INFERRED identity lead.
* SUBDOMAIN — hosts IntelX's phonebook surfaces for the domain.

Priority ordering (what the operator asked for): credentials *scraped live during
the engagement* outrank a *verified-working* credential-manager hit, which outranks
an *unverified* breach-DB leak. That order is carried by ``evidence_grade`` (scraped
= OBSERVED; breach = INFERRED, capped at MEDIUM) plus an explicit
``metadata.cred_priority`` integer for downstream sorting.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

from osprey.schemas.finding import (
    ClaimSeverity,
    EvidenceGrade,
    Finding,
    FindingConfidence,
    FindingType,
)
from osprey.services.parsers.email_extract import (
    email_domain,
    is_valid_email,
    normalize_email,
)
from osprey.services.parsers.registry import register_many

# source_class → (evidence grade, claimed severity, priority weight).
# The Finding clamp caps INFERRED at MEDIUM, so working/scraped stay HIGH while
# unverified breach leaks can never over-claim.
_SOURCE_POLICY = {
    "scraped": (EvidenceGrade.OBSERVED, ClaimSeverity.HIGH, 100),
    "creds_manager_working": (EvidenceGrade.OBSERVED, ClaimSeverity.HIGH, 90),
    "creds_manager_unknown": (EvidenceGrade.INFERRED, ClaimSeverity.MEDIUM, 60),
    "creds_manager_not_working": (EvidenceGrade.INFERRED, ClaimSeverity.LOW, 30),
    "breach_db": (EvidenceGrade.INFERRED, ClaimSeverity.MEDIUM, 40),
}


def _host_from(*values: str) -> str:
    """First value that yields a hostname (bare host or from a URL)."""
    for val in values:
        v = (val or "").strip().lower()
        if not v:
            continue
        if "://" in v or "/" in v:
            parsed = urlparse(v if "://" in v else f"//{v}")
            v = (parsed.netloc or parsed.path.split("/")[0]).split("@")[-1].split(":")[0]
        v = v.rstrip(".")
        if v and "." in v and " " not in v:
            return v
    return ""


def _policy_key(source_class: str, creds_status: str) -> str:
    if source_class == "creds_manager":
        status = (creds_status or "unknown").lower()
        if status in ("working", "not_working"):
            return f"creds_manager_{status}"
        return "creds_manager_unknown"
    return source_class if source_class in _SOURCE_POLICY else "breach_db"


def _email_finding(
    addr: str, *, tool: str, engagement_id: str, run_id: str, target: str,
    source: str, extra_meta: dict | None = None,
) -> Finding | None:
    normalized = normalize_email(addr)
    if not is_valid_email(normalized):
        return None
    meta = {"source": source, "email_domain": email_domain(normalized)}
    if extra_meta:
        meta.update(extra_meta)
    return Finding(
        engagement_id=engagement_id, run_id=run_id, phase="osint",
        finding_type=FindingType.EMAIL, title=normalized[:200],
        description=f"Email surfaced via {source}", evidence=normalized[:400],
        confidence=FindingConfidence.LIKELY, source_tool=tool, target=target,
        metadata=meta, tags=["osint", "email", source],
    )


def credential_findings(
    records: list[dict],
    *,
    tool: str,
    provider: str,
    source_class: str,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Finding]:
    """Turn normalized credential dicts into CREDENTIAL (+ EMAIL) findings.

    Each record: {username, password, email, url?, host?, creds_status?, is_admin?,
    significance?, password_type?, source?}. Shared by the IntelX/Resecurity parsers
    and the private creds-manager overlay so all three store identically.
    """
    out: list[Finding] = []
    seen: set[tuple] = set()
    for rec in records:
        if not isinstance(rec, dict):
            continue
        username = str(rec.get("username") or rec.get("user") or "").strip()
        password = str(rec.get("password") or "").strip()
        email = normalize_email(str(rec.get("email") or "")) if rec.get("email") else ""
        if not email and is_valid_email(username):
            email = normalize_email(username)
        identity = username or email
        if not identity or not password:
            continue
        creds_status = str(rec.get("creds_status") or rec.get("status") or "").strip().lower()
        key = (identity.lower(), password, creds_status)
        if key in seen:
            continue
        seen.add(key)

        host = _host_from(str(rec.get("host") or ""), str(rec.get("url") or ""), target)
        grade, severity, priority = _SOURCE_POLICY[_policy_key(source_class, creds_status)]
        is_admin = bool(rec.get("is_admin"))
        if is_admin and severity == ClaimSeverity.HIGH:
            severity = ClaimSeverity.CRITICAL  # admin + verified → crown-jewel; clamp still applies

        meta = {
            "username": username,
            "password": password,           # kept intact — offensive use / report visibility
            "email": email,
            "url": str(rec.get("url") or ""),
            "hostname": host,               # graph reads this to build exposes_credential edge
            "provider": provider,
            "source_class": source_class,
            "creds_status": creds_status or "unknown",
            "password_type": str(rec.get("password_type") or "plain"),
            "is_admin": is_admin,
            "significance": str(rec.get("significance") or ""),
            "breach_source": str(rec.get("source") or provider),
            "cred_priority": priority,
        }
        tags = ["credential", provider, source_class]
        if creds_status:
            tags.append(creds_status)
        if is_admin:
            tags.append("admin")
        if grade == EvidenceGrade.INFERRED:
            tags.append("verify_creds")  # unverified against the live target — test it

        title = f"{identity} @ {host}" if host else identity
        out.append(Finding(
            engagement_id=engagement_id, run_id=run_id, phase="osint",
            finding_type=FindingType.CREDENTIAL, title=title[:200],
            description=(
                f"Credential for {host or target or 'target'} via {provider} "
                f"({source_class}, status={creds_status or 'unknown'})"
            ),
            evidence=f"{identity}:{password}"[:400],
            confidence=FindingConfidence.CONFIRMED if grade == EvidenceGrade.OBSERVED
            else FindingConfidence.LIKELY,
            evidence_grade=grade, claim_severity=severity,
            source_tool=tool, target=host or target, metadata=meta, tags=tags,
        ))
        if email:
            ef = _email_finding(
                email, tool=tool, engagement_id=engagement_id, run_id=run_id,
                target=host or target, source=f"{provider}_leak",
            )
            if ef:
                out.append(ef)
    return out


# ---------------------------------------------------------------------------
# IntelX

def parse_intelx(
    stdout: str, *, engagement_id: str = "", run_id: str = "", target: str = ""
) -> list[Finding]:
    try:
        data = json.loads((stdout or "").strip())
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []

    # `all` mode nests the two sub-results; phonebook/leaks return flat.
    phonebook = data.get("phonebook") if "phonebook" in data else (
        data if data.get("mode") == "phonebook" else {}
    )
    leaks = data.get("leaks") if "leaks" in data else (
        data if data.get("mode") == "leaks" else {}
    )

    out: list[Finding] = []
    tgt = target or str(data.get("term") or "")

    if isinstance(phonebook, dict):
        for addr in phonebook.get("emails") or []:
            ef = _email_finding(str(addr), tool="intelx_scan", engagement_id=engagement_id,
                                run_id=run_id, target=tgt, source="intelx_phonebook")
            if ef:
                out.append(ef)
        for dom in phonebook.get("domains") or []:
            host = str(dom).strip().lower()
            if host and "." in host and (tgt.lower() in host or host.endswith(tgt.lower())):
                out.append(Finding(
                    engagement_id=engagement_id, run_id=run_id, phase="osint",
                    finding_type=FindingType.SUBDOMAIN, title=host[:200],
                    description="Host surfaced in IntelX phonebook", evidence=host[:400],
                    source_tool="intelx_scan", target=tgt, metadata={"hostname": host},
                    tags=["osint", "intelx"],
                ))

    if isinstance(leaks, dict):
        out.extend(credential_findings(
            leaks.get("credentials") or [], tool="intelx_scan", provider="intelx",
            source_class="breach_db", engagement_id=engagement_id, run_id=run_id, target=tgt,
        ))
    return out


# ---------------------------------------------------------------------------
# Resecurity

def parse_resecurity(
    stdout: str, *, engagement_id: str = "", run_id: str = "", target: str = ""
) -> list[Finding]:
    try:
        data = json.loads((stdout or "").strip())
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    tgt = target or str(data.get("target") or "")
    out = credential_findings(
        data.get("credentials") or [], tool="resecurity_scan", provider="resecurity",
        source_class="breach_db", engagement_id=engagement_id, run_id=run_id, target=tgt,
    )
    for addr in data.get("emails") or []:
        ef = _email_finding(str(addr), tool="resecurity_scan", engagement_id=engagement_id,
                            run_id=run_id, target=tgt, source="resecurity")
        if ef:
            out.append(ef)
    return out


def _register_creds_parsers() -> None:
    register_many(["intelx_scan"], parser=parse_intelx)
    register_many(["resecurity_scan"], parser=parse_resecurity)


_register_creds_parsers()
