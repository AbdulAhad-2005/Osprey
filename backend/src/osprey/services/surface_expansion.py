"""Surface expansion — config-driven stage tables and per-host state helpers
consumed by ``investigation_capabilities.py``'s atomic opportunity engine.

This module used to also own the root BFS pass itself
(``run_expansion_pass``/``_expand_host``/``_expand_contacts``) — deleted
(Plan 18) once every piece of that pass was reimplemented as one-tool-call-
per-opportunity in ``investigation_capabilities.list_step``/
``execute_capability``, which import the shared pieces below directly. What
remains here is the reusable substrate: ``config/expansion.yaml``'s stage
tables (``_installed_steps``), permutation-candidate generation, sister/apex
ownership classification, and per-host state queries
(``_host_open_ports``/``_host_has_services``/``_host_is_live_web``) — no
root loop, no tool dispatch, no target parser.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from osprey.schemas.engagement_graph import AssetNode, AssetType
from osprey.services.config_loader import read_config_layered
from osprey.services.config_validation import ConfigValidationError, validate_expansion
from osprey.services.target_utils import resolve_host_ip
from osprey.services.tool_registry import get_tool

logger = logging.getLogger(__name__)


# Data-driven frontier tool map (config/expansion.yaml). Making the tool
# selection config instead of a hardcoded tuple is what generalizes the engine
# beyond its original subdomain-only shape; _installed_steps() then drops any
# tool not present in the active environment so the same pass works in Kali,
# BYO-tools, or native mode.
_DEFAULT_EXPANSION: dict[str, Any] = {
    "sister_discovery": [
        {"tool": "domain_hunter", "param": "domain"},
        {"tool": "crt_sh_query", "param": "domain"},
    ],
    "domain_only": [
        {"tool": "whois_lookup", "param": "target"},
        {"tool": "dnsenum_scan", "param": "domain"},
    ],
    "wordlist_discovery": [
        {"tool": "subfinder_scan", "param": "domain"},
        {"tool": "amass_scan", "param": "domain"},
        {"tool": "gau_discovery", "param": "domain"},
        {"tool": "waybackurls_discovery", "param": "domain"},
        {"tool": "tlsx_inspect", "param": "target"},
    ],
    "dns_bruteforce": [
        {"tool": "gobuster_scan", "param": "target", "mode": "dns", "wordlist": "subdomains"},
    ],
    "host_expansion": [
        {"tool": "httpx_probe", "param": "target"},
        {"tool": "naabu_port_scan", "param": "target"},
        {"tool": "tech_stack_analyze", "param": "target"},
        {"tool": "wafw00f_scan", "param": "target"},
        {"tool": "cdn_origin_probe", "param": "domain"},
    ],
    "web_depth": [
        {"tool": "well_known_probe", "param": "target"},
        {"tool": "js_recon", "param": "target"},
        {"tool": "feroxbuster_scan", "param": "target"},
        {"tool": "waybackurls_discovery", "param": "domain"},
    ],
    "ptr_expansion": [
        {"tool": "dnsx_reverse", "param": "target"},
        {"tool": "asn_enum", "param": "target"},
    ],
    "batch": {"domain": 25, "live_host": 15},
    "phases": {"vuln_scan": False},
    # Associated domains are discovered but held back (never worked) unless
    # an operator explicitly enables work_sisters — see _sister_expandable.
    "work_sisters": False,
    "permutation_patterns": {
        "prefixes": ["dev", "stage", "staging", "test", "qa", "uat", "sit", "beta",
                     "pre", "prod", "old", "new", "v2", "v3", "api", "admin", "app",
                     "web", "mail", "webmail", "vpn", "portal", "sso", "owa", "db",
                     "cache", "cdn", "edge", "origin", "internal", "intranet",
                     "extranet", "backup", "docs", "status", "git", "ci", "jenkins",
                     "grafana", "kibana", "secure", "remote", "noc", "corp", "hq",
                     "eu", "us", "asia", "apac", "in", "uk", "de", "fr", "prod2"],
        "suffixes": ["dev", "stage", "staging", "test", "qa", "uat", "beta", "pre",
                     "prod", "old", "new", "v2", "v3", "api", "admin", "backup",
                     "internal", "demo", "sandbox", "sit", "2", "3"],
        "separators": ["-", ""],
        "max_words": 30,
        "max_candidates": 1500,
    },
}


@lru_cache(maxsize=1)
def _expansion_config() -> dict[str, Any]:
    """Expansion stage map — SINGLE source of truth is config/expansion.yaml
    (+ its expansion.local.yaml overlay, plans/harness/13-systematic-vuln-
    dispatch-and-extensibility.md Step 1 — an operator's own added step for
    an existing section, e.g. host_expansion/web_depth, appends and actually
    runs; entries have no `id` field in the shipped file today, so an
    overlay entry can only ADD a step to a section, not edit/disable a
    specific built-in one yet).

    The code defaults below exist only as a safety net for environments that
    ship without the config file; when the file is present it REPLACES each
    section wholesale (per-section merge, so a section added in code but not
    yet in the file still gets its default). This is what keeps the engine
    data-driven: edit the YAML, not the code.
    """
    data = {
        section: list(entries) for section, entries in _DEFAULT_EXPANSION.items()
        if section not in ("batch", "phases", "work_sisters")
    }
    data["work_sisters"] = bool(_DEFAULT_EXPANSION.get("work_sisters", False))
    batch_defaults = dict(_DEFAULT_EXPANSION.get("batch") or {})
    raw = read_config_layered("expansion.yaml")
    if isinstance(raw, dict):
        try:
            validate_expansion(raw)  # loud fail on a malformed operator edit (G1)
        except ConfigValidationError:
            # Keep the shipped defaults rather than half-applying a bad edit (G3).
            logger.exception("expansion.yaml rejected — keeping built-in defaults")
            raw = {}
        for section, entries in raw.items():
            if section == "batch" and isinstance(entries, dict):
                batch_defaults.update(entries)
            elif section == "phases" and isinstance(entries, dict):
                data["phases"] = dict(entries)
            elif section == "permutation_patterns" and isinstance(entries, dict):
                data["permutation_patterns"] = dict(entries)
            elif section == "work_sisters" and isinstance(entries, bool):
                data["work_sisters"] = entries
            elif isinstance(entries, list):
                data[section] = entries
    data["batch"] = batch_defaults
    data.setdefault("phases", {})
    return data


def _phase_enabled(name: str) -> bool:
    """Whether a named phase gate is enabled in expansion config (default off)."""
    return bool((_expansion_config().get("phases") or {}).get(name, False))


def _work_sisters_enabled() -> bool:
    """Master switch for sister-domain work (config/expansion.yaml
    `work_sisters`). When false — the default — associated domains are
    DISCOVERED (domain_hunter/crt still record them) but never enumerated,
    live-probed, or port-scanned: the seed domain and its own subdomains are
    the only worked surface. Held-back sisters are surfaced at the end of the
    run for an operator decision instead of being silently dropped."""
    return bool(_expansion_config().get("work_sisters", False))


def reload_expansion_config() -> dict[str, Any]:
    _expansion_config.cache_clear()
    return _expansion_config()


def _installed_steps(section: str) -> list[tuple[str, str, dict[str, Any]]]:
    """(tool, param, extra_params) steps for a frontier section, filtered to
    installed tools. extra_params carries the entry's static fields beyond
    tool/param (mode, wordlist, additional_args, …) so the YAML can configure
    per-tool invocation without hardcoding it in the engine."""
    steps: list[tuple[str, str, dict[str, Any]]] = []
    for entry in _expansion_config().get(section, []) or []:
        tool = str(entry.get("tool", "")).strip()
        param = str(entry.get("param", "target")).strip() or "target"
        availability = get_tool(tool) if tool else None
        if availability is not None and availability.installed:
            extra = {
                k: v for k, v in entry.items()
                if k not in ("tool", "param") and v not in (None, "")
            }
            steps.append((tool, param, extra))
    return steps


def _permutation_patterns() -> dict[str, Any]:
    """Mutation patterns for the permutation pass (config/expansion.yaml)."""
    return _expansion_config().get("permutation_patterns") or {}


def _generate_permutation_candidates(graph, engagement_id: str, apex: str, patterns: dict[str, Any]) -> list[str]:
    """Mutate already-known subdomains of an apex into new candidate names.

    Whole-class mechanism: candidates are generated from what the graph
    actually knows (first-labels of discovered subdomains × prefix/suffix/
    separator patterns), not from a hardcoded per-domain guess — so it works
    the same on any apex. Wildcard-guarded: a random-token canary subdomain
    that resolves means the apex is a wildcard domain and EVERY mutation would
    resolve, flooding the graph with fake subdomains — so permutations are
    skipped (returns []) instead of ingested.
    """
    if not patterns:
        return []
    subs = [
        n.label for n in graph.list_nodes(engagement_id=engagement_id, asset_type=AssetType.SUBDOMAIN, limit=5000)
        if n.label.endswith("." + apex)
    ]
    suffix = "." + apex
    words = sorted(
        {label[: -len(suffix)].split(".")[0].lower() for label in subs if len(label) > len(suffix)},
        key=lambda w: (len(w), w),
    )
    if not words:
        return []
    if _apex_is_wildcard(apex):
        return []
    prefixes = [str(p).strip() for p in patterns.get("prefixes", []) if str(p).strip()]
    suffixes = [str(s).strip() for s in patterns.get("suffixes", []) if str(s).strip()]
    seps = [str(s) for s in patterns.get("separators", ["-", ""])]
    try:
        max_words = max(1, int(patterns.get("max_words", 30)))
        max_candidates = max(1, int(patterns.get("max_candidates", 1500)))
    except (TypeError, ValueError):
        max_words, max_candidates = 30, 1500
    known = set(subs)
    candidates: set[str] = set()
    for word in words[:max_words]:
        for sep in seps:
            for p in prefixes:
                candidates.add(f"{p}{sep}{word}{suffix}")
            for s in suffixes:
                candidates.add(f"{word}{sep}{s}{suffix}")
    for w1 in words[:15]:
        for sep in seps:
            for w2 in words[:15]:
                candidates.add(f"{w1}{sep}{w2}{suffix}")
    candidates.difference_update(known)
    return sorted(candidates)[:max_candidates]


def _apex_is_wildcard(apex: str) -> bool:
    """Canary check: a random-token subdomain resolving ⇒ wildcard DNS.

    Uses the backend's own resolver (same one the live-host pool gates on);
    a wildcard answer here means every permutation would resolve too.
    """
    import secrets

    token = f"rd-{secrets.token_hex(8)}"
    try:
        return bool(resolve_host_ip(f"{token}.{apex}"))
    except Exception:
        return True

# Apex-level only — whois/typosquat OSINT return the same answer for every
# subdomain of a domain, so these run once per DOMAIN node, never per
# SUBDOMAIN (that would be redundant, identical calls repeated dozens of
# times on a domain with many subdomains).
_DOMAIN_ONLY_TOOLS: tuple[tuple[str, str], ...] = (
    ("whois_lookup", "target"),
    ("dnstwist", "domain"),
)

# DNS-record enumeration — A/AAAA/CNAME/NS/MX via dnsx_resolve (which also
# creates the IP graph nodes downstream stages pivot on) plus MX/SPF/DKIM/DMARC
# posture via email_security_probe. Runs per resolving domain/subdomain so the
# graph carries real DNS records, not just a resolved IP.
_DNS_RECORD_TOOLS: tuple[tuple[str, str], ...] = (
    ("dnsx_resolve", "target"),
    ("email_security_probe", "domain"),
)

# OSINT contact discovery — apex-only harvest of emails/phones/people/socials.
# Enrichment of the *individual* contacts these surface (holehe on emails,
# phoneinfoga on phones, email_permute on people) is a separate step keyed on
# the discovered contacts, not fired blindly on the domain — those tools need a
# concrete email/phone/name as input, not a hostname.
_CONTACT_DISCOVERY_TOOLS: tuple[tuple[str, str], ...] = (
    ("theharvester", "domain"),
    ("web_contact_harvest", "domain"),
)

# Domain-wide breach/passive-intel tools — AGENTS.md steps 2-3 ("Passive intel
# when keyed", "Credential/identity leaks when keyed") used to be LLM-judgment
# calls only: real, valuable, but easy to forget on any given engagement. A
# senior tester who HAS the access always checks breach data; whether they
# have the access is exactly what an API key configured in .env already
# tells this platform, mechanically, with no judgment call needed — the same
# pattern this file already uses for shodan_host_info (see the
# SHODAN_API_KEY check at the live-host stage). Each entry only fires when
# its own env var is actually set, so an unkeyed engagement pays nothing.
# Findings mint into the SAME observation/exploit-candidate pipeline any
# LLM-driven call would (exploit_pipeline.py's CREDENTIAL handling already
# auto-suggests credential_bruteforce/hash_crack) — no separate wiring needed.
#
# Config-driven (config/breach_intel_tools.yaml + its .local.yaml overlay,
# plans/harness/13-systematic-vuln-dispatch-and-extensibility.md Step 1) —
# not a hardcoded tuple — so an operator's own keyed OSINT tool actually
# gets run by this mechanical pass on every engagement once added there, the
# same way the three built-in ones are, no Python edit needed.
@lru_cache(maxsize=1)
def _breach_intel_tool_entries() -> tuple[tuple[str, str, str], ...]:
    data = read_config_layered("breach_intel_tools.yaml")
    out: list[tuple[str, str, str]] = []
    for entry in data.get("tools") or []:
        if not isinstance(entry, dict) or entry.get("disabled"):
            continue
        try:
            out.append((str(entry["env_var"]), str(entry["tool"]), str(entry["param"])))
        except KeyError:
            logger.warning("breach_intel_tools.yaml: skipping malformed entry %r", entry)
    return tuple(out)

# Netblocks larger than this are recorded (asn_enum's own finding) but never
# auto-swept — sweeping an arbitrary /16 (65k addresses) on discovery would be
# a mechanical DoS risk, not a bounded recon step. A /24 or smaller (<=256
# addresses) is the same order of magnitude as a live-host batch already is.
_MAX_AUTO_SWEEP_ADDRESSES = 256

# Hard per-task ceilings. ToolExecutionRequest.timeout defaults to 900s and
# mcp_client retries a failing call up to 3x internally — a lightweight OSINT
# lookup (crt.sh, whois) inheriting that budget can legitimately eat 45
# minutes when the upstream service is just slow/flaky (crt.sh's 502s under
# load are routine), and one such call inside an asyncio.gather batch blocks
# the entire pass since gather waits for every task. These bound each call's
# real cost instead of the generic default: sized per stage, not one blanket
# value, since a passive curl lookup and a full port+vuln scan are not the
# same kind of work.
# Fallback when SYN-based port discovery (naabu) found nothing on a live host:
# per-host firewalls (and some CDN edges) drop raw SYN probes while permitting
# established connections. TCP-connect (-sT) reaches those services. Bounded:
# common-service port set, few retries, hard host timeout — never a full-range
# sweep without explicit approval.
# Web-depth tools (feroxbuster is the slow one) get a longer budget than a
# passive probe but still bounded — a recursive content scan on a large app
# can legitimately run minutes, not hours.

# Contact enrichment (holehe/phoneinfoga/email_permute) can otherwise fan out to
# one call per email/phone/person on a large harvest — bound how many discovered
# contacts get enriched per pass so it spreads across passes like every other
# batch instead of blocking one pass on hundreds of lookups.

# Cap on how many apex domains get contact discovery (theharvester /
# web_contact_harvest) per pass — same spread-across-passes rationale as the
# other batch caps, so a large engagement doesn't block one pass on dozens of
# OSINT crawls.

# cdn_origin_probe stamps a 0-1 confidence on every "origin_candidate" it
# proposes. Below this, it's a guess, not a finding — auto-expanding it means
# port/vuln-scanning whatever IP the guess landed on, which can be a shared
# hosting/mail provider with no relation to the target (this is exactly what
# happened scanning a target's mail relay hosted on a third-party provider's
# shared IP range). Held back, not scanned, surfaced in the final report
# instead so an operator (or the LLM) decides — not skipped silently.
_MIN_ORIGIN_CONFIDENCE = 0.6

# A name the public resolver cannot answer is NOT dead until the zone's own
# authoritative nameservers also answer nothing — and even then only after
# _DEAD_KILL_PASSES consecutive failed passes (a flaky DNS window costs
# passes, never the whole engagement). Authoritative checks are bounded per
# pass so a long brute-force miss list cannot stall one pass on DNS.
_DEAD_KILL_PASSES = 2


def _origin_confidence(node: AssetNode) -> float:
    try:
        return float(node.metadata.get("confidence", 1.0) or 0.0)
    except (TypeError, ValueError):
        return 1.0


# domain_hunter stamps each sister with a confidence grade (high/medium/low) plus
# live/noise flags (see parsers.recon_network.parse_domain_hunter). Only sisters
# that actually link to the target (high/medium confidence, confirmed live, not
# scrape noise like freevisitorcounters) get expanded. Everything else is stored
# as an asset and surfaced in the report, but never enumerated — expanding a
# low-confidence look-alike (e.g. "example.info") means subfinder/amass/whois on
# an unrelated domain, and expanding scrape noise means wordlists on a domain the
# target has nothing to do with.
_SISTER_EXPANDABLE_CONFIDENCES = ("high", "medium")


def _sister_expandable(node: AssetNode) -> bool:
    # Master switch: by default associated domains are held back, never
    # worked — the operator decides at the end (see _work_sisters_enabled).
    if not _work_sisters_enabled():
        return False
    meta = node.metadata or {}
    if meta.get("role") != "sister_domain":
        return False
    if meta.get("scrape_noise") or not meta.get("live"):
        return False
    return str(meta.get("hunter_confidence") or "").lower() in _SISTER_EXPANDABLE_CONFIDENCES


# OSINT-identity roles are minted by engagement_graph from a finding's content,
# NOT by a domain-discovery tool: `email_domain` (mailbox host of a harvested
# address — theharvester's canned test email cmartorella@edge-security.com is
# exactly this), `dns_owner` (the owner side of an NS/MX record). A DOMAIN node
# carrying one of these roles was linked as an identity, not discovered as an
# asset — letting it into the apex frontier makes the engine whois/dnsenum/crt/
# domain_hunter a third party's domain and treat that domain's registrar NS
# hosts as "sisters". The engagement seed stays expandable no matter what role
# metadata a later finding merged onto it (the seed's own MX records make it a
# dns_owner too).
_OSINT_IDENTITY_DOMAIN_ROLES = frozenset({"email_domain", "dns_owner"})


def _is_expandable_apex(node: AssetNode, *, target_label: str) -> bool:
    """A DOMAIN node is an expansion apex iff it is the engagement seed itself,
    or it never accumulated an OSINT-identity role (email mailbox host / DNS
    record owner). Role-less DOMAIN nodes minted by whois / domain_hunter / crt
    on a real sister stay in the frontier. Sister-role nodes are additionally
    held back while work_sisters is off — same master switch as
    _sister_expandable, so an associated domain can never slip into the
    frontier through the DOMAIN path."""
    if str(node.label or "").lower() == str(target_label or "").lower():
        return True
    if not _work_sisters_enabled() and str((node.metadata or {}).get("role") or "").lower() == "sister_domain":
        return False
    return str((node.metadata or {}).get("role") or "").lower() not in _OSINT_IDENTITY_DOMAIN_ROLES


def _host_is_live_web(engagement_id: str, *, host: str) -> bool:
    """True when this host already has a URL finding (i.e. something answered
    HTTP). Web-depth probing (content discovery, JS mining, robots/.well-known)
    is wasted on a host that never speaks HTTP."""
    from osprey.schemas.finding import FindingType
    from osprey.services.findings_store import get_findings_store

    store = get_findings_store()
    host_l = (host or "").lower()
    for f in store.list(engagement_id=engagement_id, finding_type=FindingType.URL, limit=300):
        if str(f.metadata.get("hostname") or "").lower() == host_l:
            return True
        title = str(f.title or "").lower()
        if f"//{host_l}" in title or f"https://{host_l}/" in title:
            return True
    return False


def _host_open_ports(engagement_id: str, *, host: str, ip: str | None) -> list[str]:
    """Open TCP ports already ingested for this specific host/IP, sorted numeric.

    Scopes the follow-up nmap -sV to exactly the ports naabu found on THIS host
    (matched by hostname or resolved IP in finding metadata), not every port
    seen anywhere in the engagement.
    """
    from osprey.schemas.finding import FindingType
    from osprey.services.findings_store import get_findings_store

    store = get_findings_store()
    findings = store.list(engagement_id=engagement_id, finding_type=FindingType.PORT, limit=500)
    findings += store.list(engagement_id=engagement_id, finding_type=FindingType.SERVICE, limit=500)
    host_l = (host or "").lower()
    ports: set[str] = set()
    for f in findings:
        meta = f.metadata or {}
        if (str(meta.get("hostname") or "").lower() == host_l) or (ip and str(meta.get("ip") or "") == ip):
            port = str(meta.get("port") or "").strip()
            if port.isdigit():
                ports.add(port)
    return sorted(ports, key=int)


def _host_has_services(engagement_id: str, *, host: str, ip: str | None) -> bool:
    """True when a service/version finding already exists for this host/IP —
    i.e. SYN-based discovery produced a usable service profile and no connect
    retry is needed."""
    from osprey.schemas.finding import FindingType
    from osprey.services.findings_store import get_findings_store

    store = get_findings_store()
    host_l = (host or "").lower()
    for f in store.list(engagement_id=engagement_id, finding_type=FindingType.SERVICE, limit=500):
        meta = f.metadata or {}
        if (
            str(f.target or "").lower() == host_l
            or str(meta.get("hostname") or "").lower() == host_l
            or (ip and str(meta.get("ip") or "") == ip)
        ):
            return True
    return False


