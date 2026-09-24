"""Parsers for credential-harvesting sources (IntelX, Resecurity, and the shared
helper the private creds-manager overlay reuses).

These turn a source tool's JSON stdout into typed Observations — structural
facts, never a judged CREDENTIAL finding:

* CREDENTIAL observation — a username/email + password pair. The real values
  are kept intact (offensive use, never masked) so a human/LLM can act on the
  leaked credential, and the exploit phase can source a
  ``credential_bruteforce`` candidate from it (Plan 03 Step 6). ``details.hostname``
  links it to its host in the engagement graph.
* EMAIL observation — every address seen (harvested or leaked).
* SUBDOMAIN observation — hosts IntelX's phonebook surfaces for the domain.

Source priority (scraped-live > verified creds-manager hit > unverified
breach-DB leak) is preserved as structural fact (``details.source_class``,
``details.creds_status``, ``details.cred_priority``) — it is no longer baked
into a confidence/severity policy table here. Whether a credential earns a
``confirmed`` finding is ``confidence_for``'s job (Plan 03): a live-scraped or
verified-working credential is exactly the kind of fact a verification-evidence
capability turns into a reproduction/verification record.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

from osprey.schemas.observation import Observation, ObservationType
from osprey.services.parsers.email_extract import (
    email_domain,
    is_valid_email,
    normalize_email,
)
from osprey.services.parsers.registry import register_many


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
    return source_class


# source_class/status → relative priority weight for downstream sorting only
# (no confidence/severity implied — structural fact, not a verdict).
_PRIORITY = {
    "scraped": 100,
    "creds_manager_working": 90,
    "creds_manager_unknown": 60,
    "creds_manager_not_working": 30,
    "breach_db": 40,
}


def _email_observation(
    addr: str, *, tool: str, engagement_id: str, run_id: str, target: str,
    source: str, extra_details: dict | None = None,
) -> Observation | None:
    normalized = normalize_email(addr)
    if not is_valid_email(normalized):
        return None
    details = {"email": normalized, "email_domain": email_domain(normalized), "source": source}
    if extra_details:
        details.update(extra_details)
    return Observation(
        engagement_id=engagement_id, run_id=run_id,
        type=ObservationType.EMAIL,
        target=target, source_tool=tool,
        details=details,
    )


def credential_observations(
    records: list[dict],
    *,
    tool: str,
    provider: str,
    source_class: str,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    """Turn normalized credential dicts into CREDENTIAL (+ EMAIL) observations.

    Each record: {username, password, email, url?, host?, creds_status?, is_admin?,
    significance?, password_type?, source?}. Shared by the IntelX/Resecurity parsers
    and the private creds-manager overlay so all three store identically.
    """
    out: list[Observation] = []
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
        policy_key = _policy_key(source_class, creds_status)
        priority = _PRIORITY.get(policy_key, _PRIORITY["breach_db"])
        is_admin = bool(rec.get("is_admin"))

        details = {
            "username": username,
            "password": password,  # kept intact — offensive use / report visibility
            "email": email,
            "url": str(rec.get("url") or ""),
            "hostname": host,  # graph reads this to build exposes_credential edge
            "provider": provider,
            "source_class": source_class,
            "creds_status": creds_status or "unknown",
            "password_type": str(rec.get("password_type") or "plain"),
            "is_admin": is_admin,
            "significance": str(rec.get("significance") or ""),
            "breach_source": str(rec.get("source") or provider),
            "cred_priority": priority,
        }

        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.CREDENTIAL,
            target=host or target, source_tool=tool,
            details=details,
        ))
        if email:
            ef = _email_observation(
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
) -> list[Observation]:
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

    out: list[Observation] = []
    tgt = target or str(data.get("term") or "")

    if isinstance(phonebook, dict):
        for addr in phonebook.get("emails") or []:
            ef = _email_observation(str(addr), tool="intelx_scan", engagement_id=engagement_id,
                                     run_id=run_id, target=tgt, source="intelx_phonebook")
            if ef:
                out.append(ef)
        for dom in phonebook.get("domains") or []:
            host = str(dom).strip().lower()
            if host and "." in host and (tgt.lower() in host or host.endswith(tgt.lower())):
                out.append(Observation(
                    engagement_id=engagement_id, run_id=run_id,
                    type=ObservationType.SUBDOMAIN,
                    target=tgt, source_tool="intelx_scan",
                    details={"hostname": host, "source": "intelx_phonebook"},
                ))

    if isinstance(leaks, dict):
        out.extend(credential_observations(
            leaks.get("credentials") or [], tool="intelx_scan", provider="intelx",
            source_class="breach_db", engagement_id=engagement_id, run_id=run_id, target=tgt,
        ))
    return out


# ---------------------------------------------------------------------------
# Resecurity

def parse_resecurity(
    stdout: str, *, engagement_id: str = "", run_id: str = "", target: str = ""
) -> list[Observation]:
    try:
        data = json.loads((stdout or "").strip())
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    tgt = target or str(data.get("target") or "")
    out = credential_observations(
        data.get("credentials") or [], tool="resecurity_scan", provider="resecurity",
        source_class="breach_db", engagement_id=engagement_id, run_id=run_id, target=tgt,
    )
    for addr in data.get("emails") or []:
        ef = _email_observation(str(addr), tool="resecurity_scan", engagement_id=engagement_id,
                                 run_id=run_id, target=tgt, source="resecurity")
        if ef:
            out.append(ef)
    return out


def _register_creds_parsers() -> None:
    register_many(["intelx_scan"], parser=parse_intelx)
    register_many(["resecurity_scan"], parser=parse_resecurity)


_register_creds_parsers()
