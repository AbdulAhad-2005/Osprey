"""Surface Expansion Engine — one deterministic BFS pass over the attack
surface graph: passive subdomain/sister discovery -> live-host probe -> port
scan -> tech/CDN detection -> origin-IP discovery -> the existing vuln
auto-scan. Mechanical, evidence-producing work only; it never decides
whether recon is "done" (that's the commander's call, informed by the
delta this returns) and it never blocks or replaces whatever the LLM
chooses to do on top of it — additive, not a takeover of the phase.

Mirrors the placement/best-effort style of
``phase_supervisor._maybe_auto_scan_network_vulns``: every dispatched tool call
is wrapped so one failure never aborts the pass, and the whole function is
safe to call every recon round — it does nothing once the frontier is
empty and everything upstream has already been expanded.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
from functools import lru_cache
from typing import Any, Callable

from pydantic import BaseModel

from osprey.schemas.engagement_graph import AssetNode, AssetType
from osprey.services.config_loader import read_config
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.parallelism_config import max_running_jobs
from osprey.services.target_utils import is_ipv4, registrable_apex, resolve_host_ip
from osprey.services.surface_expansion_store import (
    ExpansionState,
    get_surface_expansion_store,
)
from osprey.services.tool_registry import list_tools

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
    """Expansion stage map — SINGLE source of truth is config/expansion.yaml.

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
    raw = read_config("expansion.yaml")
    if isinstance(raw, dict):
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
    installed = {t.name for t in list_tools() if t.installed}
    steps: list[tuple[str, str, dict[str, Any]]] = []
    for entry in _expansion_config().get(section, []) or []:
        tool = str(entry.get("tool", "")).strip()
        param = str(entry.get("param", "target")).strip() or "target"
        if tool and tool in installed:
            extra = {
                k: v for k, v in entry.items()
                if k not in ("tool", "param") and v not in (None, "")
            }
            steps.append((tool, param, extra))
    return steps


def _batch_cap(name: str, default: int) -> int:
    batch = _expansion_config().get("batch") or {}
    try:
        return max(1, int(batch.get(name, default)))
    except (TypeError, ValueError):
        return default


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
_DOMAIN_DISCOVERY_TIMEOUT = 90
_DOMAIN_ONLY_TIMEOUT = 60
_DNS_RECORD_TIMEOUT = 45
_DNS_BRUTE_TIMEOUT = 150
_LIVE_HOST_TIMEOUT = 120
_VULN_SCAN_TIMEOUT = 420
_SERVICE_SCAN_TIMEOUT = 240
# Fallback when SYN-based port discovery (naabu) found nothing on a live host:
# per-host firewalls (and some CDN edges) drop raw SYN probes while permitting
# established connections. TCP-connect (-sT) reaches those services. Bounded:
# common-service port set, few retries, hard host timeout — never a full-range
# sweep without explicit approval.
_CONNECT_FALLBACK_FLAGS = "-Pn -sT -sV --top-ports 100 --max-retries 1 --host-timeout 90s"
_PTR_TIMEOUT = 45
_CONTACT_TIMEOUT = 90
_CONTACT_ENRICH_TIMEOUT = 60
# Web-depth tools (feroxbuster is the slow one) get a longer budget than a
# passive probe but still bounded — a recursive content scan on a large app
# can legitimately run minutes, not hours.
_WEB_DEPTH_TIMEOUT = 240
_WPSCAN_TIMEOUT = 300

# Contact enrichment (holehe/phoneinfoga/email_permute) can otherwise fan out to
# one call per email/phone/person on a large harvest — bound how many discovered
# contacts get enriched per pass so it spreads across passes like every other
# batch instead of blocking one pass on hundreds of lookups.
_CONTACT_ENRICH_BATCH_CAP = 20

# Cap on how many apex domains get contact discovery (theharvester /
# web_contact_harvest) per pass — same spread-across-passes rationale as the
# other batch caps, so a large engagement doesn't block one pass on dozens of
# OSINT crawls.
_DOMAIN_BATCH_CAP = 25

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
_AUTH_CHECK_PASS_CAP = 12


def _origin_confidence(node: AssetNode) -> float:
    try:
        return float(node.metadata.get("confidence", 1.0) or 0.0)
    except (TypeError, ValueError):
        return 1.0


def _owned_apexes(graph, engagement_id: str, target_label: str) -> set[str]:
    """Registrable apexes this engagement actually owns, per the engine's own
    expansion rules: the seed, every role-less/DOMAIN node the engine would
    re-expand (_is_expandable_apex), and every expandable sister
    (_sister_expandable). A SUBDOMAIN node whose apex is NOT in this set is
    third-party infrastructure (typically a CNAME chain target like
    outlook.com from the seed's own mail records) — recorded as an asset, but
    never given the ports/services/tech battery: scanning Microsoft's or
    anyone else's shared estate is budget the target never sees."""
    owned = {str(target_label or "").strip().lower()}
    for node in graph.list_nodes(engagement_id=engagement_id, asset_type=AssetType.DOMAIN, limit=5000):
        if _is_expandable_apex(node, target_label=target_label):
            owned.add(str(node.label or "").strip().lower())
    for node in graph.list_nodes(engagement_id=engagement_id, asset_type=AssetType.HOST, limit=5000):
        if _sister_expandable(node):
            owned.add(str(node.label or "").strip().lower())
    return {a for a in owned if a}


def _apex_is_owned(label: str, owned_apexes: set[str]) -> bool:
    """True when the label's registrable apex is in the owned set — structural
    match via the PSL, never a bare substring ('samaa.tv' must not contain
    'aa.tv'-style prefixes on 'notsamaa.tv')."""
    label = (label or "").strip().lower()
    if not label:
        return False
    return registrable_apex(label) in owned_apexes


def _authoritative_host_ip(host: str) -> str | None:
    """Second source for the live-pool's resolution gate: ask the zone's OWN
    authoritative nameservers directly (dig @<NS> name A semantics), bypassing
    public-resolver caches and validation — a public resolver answering
    nothing is not proof a name is dead. Returns an IP only when an
    authoritative server itself serves an A/AAAA record; None on empty/
    NXDOMAIN answers, unreachable/unknown NS, or when dnspython is absent
    (caller then falls back to deferral instead of a kill)."""
    try:
        import dns.resolver  # noqa: PLC0415
    except ImportError:
        # Optional dependency (dnspython) — its absence must degrade this
        # check to None (deferral), never crash the whole engine pass.
        return None

    from osprey.services.target_utils import resolve_ipv4

    host = (host or "").strip().lower().rstrip(".")
    if not host or is_ipv4(host):
        return None
    apex = registrable_apex(host)
    if not apex:
        return None
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = 2.0
        resolver.lifetime = 4.0
        ns_answers = resolver.resolve(apex, "NS", lifetime=4.0)
        ns_ips: list[str] = []
        for rr in ns_answers:
            ns_name = str(rr.target).rstrip(".")
            ns_ip = resolve_ipv4(ns_name)
            if ns_ip:
                ns_ips.append(ns_ip)
        if not ns_ips:
            return None
        auth = dns.resolver.Resolver(configure=False)
        auth.nameservers = ns_ips[:3]
        auth.timeout = 2.0
        auth.lifetime = 4.0
        for qtype in ("A", "AAAA"):
            try:
                for rr in auth.resolve(host, qtype, lifetime=4.0):
                    ip = str(rr)
                    if ":" in ip or is_ipv4(ip):
                        return ip
            except dns.resolver.NXDOMAIN:
                return None
            except dns.resolver.NoAnswer:
                continue
            except Exception:
                continue
        return None
    except Exception:
        return None


def _has_live_evidence(engagement_id: str, host: str) -> bool:
    """Does the graph already carry live proof for this host (URLs, open
    ports, HTTP responses, DNS records)? If yes, a resolution failure right
    now is a transient blip, not death — the host gets deferred, never
    permanently killed. Used by the live-host pool's dead-candidate pass."""
    from osprey.schemas.finding import FindingType
    from osprey.services.findings_store import get_findings_store

    host_l = (host or "").lower()
    store = get_findings_store()
    for ftype in (FindingType.URL, FindingType.PORT, FindingType.HTTP_RESPONSE):
        for f in store.list(engagement_id=engagement_id, finding_type=ftype, limit=500):
            target = str(f.target or "").lower()
            if _target_matches_host(target, host_l):
                return True
    # DNS records (A/MX/NS) for the name also count as live evidence — a
    # name with published DNS records existed and may simply be flaky right
    # now. (Findings here are DNS_RECORD, title e.g. "samaa.tv MX -> ...".)
    for f in store.list(engagement_id=engagement_id, finding_type=FindingType.DNS_RECORD, limit=500):
        if (f.target or "").lower() == host_l:
            return True
    return False


def _target_matches_host(target: str, host_l: str) -> bool:
    """Structural host match: exact label, or a URL/port string rooted at it
    (https://host/path, host:443). Never a bare substring — 'samaa.tv' must
    not match 'notsamaa.tv'."""
    target = target.strip()
    if target == host_l:
        return True
    if target.startswith(f"{host_l}:"):
        return True
    for scheme in ("http://", "https://"):
        if target.startswith(scheme + host_l):
            return True
    return False


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


class ExpansionDelta(BaseModel):
    engagement_id: str
    frontier_processed: int
    new_nodes: int
    new_edges: int
    exhausted: bool
    total_passes: int

    def summary_line(self) -> str:
        if self.frontier_processed == 0:
            return "Surface expansion: nothing new to expand this pass."
        if self.exhausted:
            return (
                f"Surface expansion: +{self.new_nodes} assets, +{self.new_edges} edges "
                f"from {self.frontier_processed} seed(s) — surface exhausted "
                f"(2 consecutive passes with nothing new)."
            )
        return (
            f"Surface expansion: +{self.new_nodes} assets, +{self.new_edges} edges "
            f"from {self.frontier_processed} seed(s) this pass."
        )


def _tool_health_summary(tool_health: dict[str, Any], new_nodes: int) -> str | None:
    """One honest line about this pass's tool execution, or None when there is
    nothing worth saying (no tools ran, or a healthy pass that found things).

    The point is to disambiguate a wall of "nothing new": if every scanner ran
    but none produced data, that is an execution-backend problem (almost always
    the Kali container can't reach the internet/DNS), not an empty target.
    """
    ran = int(tool_health.get("ran", 0))
    if ran == 0:
        return None
    ok = int(tool_health.get("ok", 0))
    empty = int(tool_health.get("empty", 0))
    failed = int(tool_health.get("failed", 0))
    timeout = int(tool_health.get("timeout", 0))

    parts = [f"{ok} ok"]
    if empty:
        parts.append(f"{empty} returned no data")
    if failed:
        parts.append(f"{failed} failed")
    if timeout:
        parts.append(f"{timeout} timed out")
    summary = f"⚙ tool health: {ran} ran — " + ", ".join(parts)

    # The alarming case: tools ran, none produced usable output, and the pass
    # added nothing. Point straight at the execution backend with a one-line
    # confirmation the operator can paste.
    if ok == 0 and new_nodes == 0:
        summary += (
            " — every tool ran but produced no data. This is almost always the "
            "execution backend (the Kali container can't reach the internet/DNS), "
            "not an empty target. Confirm with: "
            "docker exec osprey-kali subfinder -d example.com"
        )
        errors = tool_health.get("errors") or []
        if errors:
            summary += f"  [sample: {errors[0]}]"
    return summary


async def run_expansion_pass(
    *,
    engagement_id: str,
    run_id: str,
    on_progress: Callable[[str], None] | None = None,
    min_origin_confidence: float = _MIN_ORIGIN_CONFIDENCE,
) -> ExpansionDelta:
    if not engagement_id:
        return ExpansionDelta(
            engagement_id=engagement_id, frontier_processed=0, new_nodes=0,
            new_edges=0, exhausted=False, total_passes=0,
        )

    graph = get_engagement_graph()
    before_node_ids = {n.id for n in graph.list_nodes(engagement_id=engagement_id, limit=20_000)}
    before_edge_keys = {
        (e.source_id, e.target_id, e.relationship)
        for e in graph.list_edges(engagement_id=engagement_id, limit=50_000)
    }

    sem = asyncio.Semaphore(max(1, max_running_jobs()))

    # Live "what's running right now" visibility: every in-flight tool call
    # registers itself here for the duration of its own wait_for-bounded call,
    # so a caller polling mid-pass sees actual tool names, not just silence
    # until the whole pass finishes.
    in_flight: set[str] = set()

    # Per-pass tool-execution health. A stage reporting "nothing new" is
    # ambiguous by itself — it looks identical whether the tool genuinely found
    # nothing, returned empty output (exit 0, no data), failed, or timed out.
    # Tallying every dispatch here lets the pass emit one honest diagnostic:
    # "12 tools ran, 0 produced data" is an environment problem (usually the
    # Kali container's egress/DNS), not an empty target — and the operator
    # should be told which, not left guessing at a wall of "nothing new".
    tool_health: dict[str, Any] = {
        "ran": 0, "ok": 0, "empty": 0, "failed": 0, "timeout": 0, "errors": [],
    }

    def _record_health(kind: str, *, tool: str = "", err: str = "") -> None:
        tool_health["ran"] += 1
        tool_health[kind] += 1
        if err and len(tool_health["errors"]) < 3:
            snippet = " ".join(str(err).split())[:160]
            if snippet:
                tool_health["errors"].append(f"{tool}: {snippet}")

    def _report(stage: str) -> None:
        if on_progress is None:
            return
        if not in_flight:
            on_progress(f"{stage}: finishing up…")
            return
        shown = sorted(in_flight)[:4]
        more = len(in_flight) - len(shown)
        tail = f" (+{more} more)" if more > 0 else ""
        on_progress(f"{stage}: running {', '.join(shown)}{tail}")

    # Structured, persistent results — distinct from the ephemeral in-flight
    # ticker above via the "RESULT::" prefix (callers keep these in scrollback
    # instead of overwriting them like a spinner line), so "what's running"
    # and "what was actually found" are both visible throughout the run, not
    # just in a summary dumped at the very end.
    from osprey.services.findings_store import get_findings_store

    store = get_findings_store()

    def _report_result(text: str) -> None:
        if on_progress is not None:
            on_progress(f"RESULT::{text}")

    def _snapshot_finding_ids() -> set[str]:
        return {f.id for f in store.list(engagement_id=engagement_id, limit=5000)}

    def _report_stage_findings(before_ids: set[str], label: str) -> None:
        if on_progress is None:
            return
        after = store.list(engagement_id=engagement_id, limit=5000)
        new_titles = [f.title for f in after if f.id not in before_ids]
        if not new_titles:
            _report_result(f"✓ {label}: nothing new")
            return
        shown = new_titles[:6]
        more = len(new_titles) - len(shown)
        tail = f" (+{more} more)" if more > 0 else ""
        _report_result(f"✓ {label}: found {len(new_titles)} — {', '.join(shown)}{tail}")

    async def _dispatch(tool_name: str, params: dict, *, stage: str = "expand", timeout: int = 120, extra: dict | None = None) -> None:
        # A step may declare its own budget (expansion.yaml `timeout:` field,
        # e.g. wafw00f_scan needs more than the 120s live-host default). It is
        # a dispatch concern, not a tool param — pop it before the static
        # fields merge into params.
        per_tool_timeout = None
        if extra:
            per_tool_timeout = extra.pop("timeout", None)
            merged = dict(params)
            merged.update(extra)
            params = merged
        target_label = next((str(v) for v in params.values() if v), "")
        label = f"{tool_name}({target_label})"
        async with sem:
            in_flight.add(label)
            _report(stage)
            try:
                from osprey.schemas.tools import ToolExecutionRequest
                from osprey.services.tool_execution import execute_tool_request

                resp = await asyncio.wait_for(
                    execute_tool_request(
                        ToolExecutionRequest(
                            tool_name=tool_name,
                            params=params,
                            engagement_id=engagement_id,
                            run_id=run_id,
                            record_findings=True,
                            # A per-attempt budget scoped to this stage's real
                            # cost — not the schema's 900s default, which is
                            # sized for heavy scans, not a curl-based lookup.
                            timeout=min(int(per_tool_timeout or timeout), 300),
                        )
                    ),
                    timeout=timeout,
                )
                # Classify the outcome for the pass-level health diagnostic. An
                # exit-0 run with empty stdout is the silent case that makes a
                # broken execution backend look like an empty target.
                if getattr(resp, "timed_out", False):
                    _record_health("timeout", tool=tool_name)
                elif not getattr(resp, "success", False):
                    _record_health(
                        "failed", tool=tool_name,
                        err=getattr(resp, "error", "") or (getattr(resp, "stderr", "") or ""),
                    )
                elif not (getattr(resp, "stdout", "") or "").strip():
                    _record_health("empty", tool=tool_name)
                else:
                    _record_health("ok", tool=tool_name)
            except TimeoutError:
                _record_health("timeout", tool=tool_name)
                logger.debug(
                    "Surface expansion: %s timed out after %ss for %s (non-fatal, pass continues)",
                    tool_name, timeout, params,
                )
            except Exception as exc:
                _record_health("failed", tool=tool_name, err=str(exc))
                logger.debug(
                    "Surface expansion: %s failed for %s (non-fatal, pass continues)",
                    tool_name, params, exc_info=True,
                )
            finally:
                in_flight.discard(label)
                _report(stage)

    # --- 0. Self-seed: if the graph has no domain root yet, create one from the
    # engagement record. Binding creates the engagement, not the node — so every
    # entry point (MCP bind, HTTP /expand, orchestrator recon loop) gets a
    # frontier even on the very first pass. Idempotent: ensure_node upserts by
    # node id, and an already-expanded root stays untouched. ---
    from osprey.services.engagement_store import get_engagement_store

    # Engagement record is needed by every stage (self-seed target, apex
    # expandability against the seed, OSINT apex list) — resolve it once, up
    # front, instead of inside the self-seed branch: a conditional assignment
    # leaves `engagement` unbound on later passes (when the seed node already
    # exists), and every frontier built against it then crashes.
    engagement = get_engagement_store().get(engagement_id)
    target_label = (engagement.target if engagement else "") or ""

    existing_domains = graph.list_nodes(
        engagement_id=engagement_id, asset_type=AssetType.DOMAIN, limit=1,
    )
    if not existing_domains:
        if engagement and engagement.target:
            graph.ensure_node(
                engagement_id=engagement_id,
                asset_type=AssetType.DOMAIN,
                label=engagement.target,
                metadata={"expanded": False, "depth": 0},
            )

    # --- 1a. Sister/associated-domain discovery — runs first, across the apex
    # frontier, and is awaited to completion before stage 1b starts. The
    # frontier is DOMAIN nodes ONLY: sister discovery finds apex domains
    # related to apex domains. Subdomains are themselves the OUTPUT of this
    # stage — re-running domain_hunter/crt on a subdomain re-finds the same
    # names (or worse, scrape noise) and burns the pass budget on duplicates.
    domain_nodes = [
        n for n in graph.list_nodes(engagement_id=engagement_id, asset_type=AssetType.DOMAIN, limit=5000)
        if not n.metadata.get("expanded") and _is_expandable_apex(n, target_label=target_label)
    ]
    domain_frontier = domain_nodes[: _batch_cap("domain", 25)]

    if domain_frontier:
        _report_result(f"▶ stage 1 — sister & associated domains: {len(domain_frontier)} apex domain(s)")
    before_sister = _snapshot_finding_ids()

    sister_tasks = [
        _dispatch(tool, {param: node.label}, extra=extra, stage="sister discovery", timeout=_DOMAIN_DISCOVERY_TIMEOUT)
        for node in domain_frontier
        for tool, param, extra in _installed_steps("sister_discovery")
    ]
    sister_tasks += [
        _dispatch(tool, {param: node.label}, extra=extra, stage="sister discovery", timeout=_DOMAIN_ONLY_TIMEOUT)
        for node in domain_frontier
        for tool, param, extra in _installed_steps("domain_only")
    ]
    if sister_tasks:
        await asyncio.gather(*sister_tasks)
        _report_stage_findings(before_sister, "sister & associated domains")

    # --- 1b. Wordlist/enumeration-based subdomain discovery — runs on the
    # seed apex PLUS high-confidence sisters that actually link to it.
    # Sisters land in the graph as HOST nodes with domain_hunter's metadata
    # (hunter_confidence / live / scrape_noise); only live, non-noise sisters
    # with at least medium confidence are worth enumerating — the rest are
    # recorded as assets but never expanded. SUBDOMAIN nodes never enter this
    # frontier: a discovered subdomain is an asset to profile (ports/services/
    # web depth), not a seed to re-enumerate. Capped the same way as the
    # frontier itself so many new sisters still spread across passes. ---
    apex_ids = {n.id for n in domain_frontier}
    sister_candidates = [
        n for n in graph.list_nodes(engagement_id=engagement_id, asset_type=AssetType.HOST, limit=5000)
        if n.metadata.get("role") == "sister_domain"
        and not n.metadata.get("expanded")
        and _sister_expandable(n)
    ]
    held_back_sisters = [
        n for n in graph.list_nodes(engagement_id=engagement_id, asset_type=AssetType.HOST, limit=5000)
        if n.metadata.get("role") == "sister_domain"
        and not n.metadata.get("expanded")
        and not _sister_expandable(n)
    ]
    if held_back_sisters:
        shown = ", ".join(f"{n.label} ({n.metadata.get('hunter_confidence', '?')})" for n in held_back_sisters[:8])
        tail = f" (+{len(held_back_sisters) - 8} more)" if len(held_back_sisters) > 8 else ""
        _report_result(
            f"⚠ {len(held_back_sisters)} associated domain(s) recorded but held back — not worked on: "
            f"{shown}{tail} (enable work_sisters in config/expansion.yaml to expand them)"
        )
    newly_discovered = [
        n for n in graph.list_nodes(engagement_id=engagement_id, asset_type=AssetType.DOMAIN, limit=5000)
        if n.id not in apex_ids and not n.metadata.get("expanded")
        and _is_expandable_apex(n, target_label=target_label)
    ]
    wordlist_frontier = (domain_frontier + sister_candidates + newly_discovered)[: _batch_cap("domain", 25)]

    if wordlist_frontier:
        _report_result(
            f"▶ stage 2 — subdomain enumeration (seed + high-confidence sisters): {len(wordlist_frontier)} target(s)"
        )
    before_wordlist = _snapshot_finding_ids()

    wordlist_tasks = [
        _dispatch(tool, {param: node.label}, extra=extra, stage="subdomain enumeration", timeout=_DOMAIN_DISCOVERY_TIMEOUT)
        for node in wordlist_frontier
        for tool, param, extra in _installed_steps("wordlist_discovery")
    ]
    if wordlist_tasks:
        await asyncio.gather(*wordlist_tasks)
        _report_stage_findings(before_wordlist, "subdomain enumeration")

    # --- Stage 2b: ACTIVE DNS deepening — gobuster brute force (bounded
    # wordlist, once per apex) plus permutation candidates mutated from
    # already-known subdomain names (prefix/suffix × separator patterns,
    # bulk-resolved via one dnsx call per apex). Both feed the same
    # SUBDOMAIN finding lane as stage 2, so stage 3 resolves and the live
    # pass profiles anything new in the SAME pass. Wildcard domains are
    # canary-guarded before permutations so a wildcard never floods the
    # graph with fake subdomains. Runs only on the same capped frontier as
    # stage 2; bf_done marks apexes so the brute force is not repeated on
    # later passes (its wordlist run is deterministic). ---
    bf_steps = _installed_steps("dns_bruteforce")
    bf_frontier = [n for n in wordlist_frontier if not n.metadata.get("dns_bf_done")]
    if (bf_steps or _permutation_patterns()) and bf_frontier:
        _report_result(f"▶ stage 2b — DNS brute force + permutations: {len(bf_frontier)} apex(es)")
        before_bf = _snapshot_finding_ids()
        bf_tasks = [
            _dispatch(tool, {param: node.label}, extra=extra, stage="dns brute force", timeout=_DNS_BRUTE_TIMEOUT)
            for node in bf_frontier
            for tool, param, extra in bf_steps
        ]
        perm_tasks = [
            _dispatch("dnsx_resolve", {"target": "\n".join(candidates)}, stage="subdomain permutations", timeout=_DNS_RECORD_TIMEOUT + 30)
            for node in bf_frontier
            for candidates in (_generate_permutation_candidates(graph, engagement_id, node.label, _permutation_patterns()),)
            if candidates
        ]
        if bf_tasks or perm_tasks:
            await asyncio.gather(*(bf_tasks + perm_tasks))
            _report_stage_findings(before_bf, "DNS brute force & permutations")
            for node in bf_frontier:
                graph.ensure_node(
                    engagement_id=engagement_id, asset_type=node.asset_type, label=node.label,
                    metadata={"dns_bf_done": True},
                )

    # --- Stage 3: DNS records — resolve A/AAAA/CNAME/NS/MX (dnsx_resolve, which
    # also seeds the IP graph nodes) on every domain + subdomain, and MX/SPF/
    # DKIM/DMARC posture (email_security_probe) once per apex domain. DNS runs on
    # ALL subdomains (they are the discovered assets — resolving them is what
    # feeds the live-host pass), not just the wordlist frontier. ---
    dns_targets = list(wordlist_frontier)
    dns_targets += [
        n for n in graph.list_nodes(engagement_id=engagement_id, asset_type=AssetType.SUBDOMAIN, limit=5000)
        if not n.metadata.get("dns_resolved") and n.label not in {t.label for t in dns_targets}
    ]
    if dns_targets:
        _report_result(f"▶ stage 3 — DNS records (A/AAAA/CNAME/NS/MX, SPF/DKIM/DMARC): {len(dns_targets)} target(s)")
    before_dns = _snapshot_finding_ids()
    dns_tasks = [
        _dispatch("dnsx_resolve", {"target": node.label}, stage="dns records", timeout=_DNS_RECORD_TIMEOUT)
        for node in dns_targets
    ]
    dns_tasks += [
        _dispatch("email_security_probe", {"domain": node.label}, stage="dns records", timeout=_DNS_RECORD_TIMEOUT)
        for node in dns_targets
        if node.asset_type == AssetType.DOMAIN
    ]
    if dns_tasks:
        await asyncio.gather(*dns_tasks)
        _report_stage_findings(before_dns, "DNS records")
        for node in dns_targets:
            graph.ensure_node(
                engagement_id=engagement_id, asset_type=node.asset_type, label=node.label,
                metadata={"dns_resolved": True},
            )

    expanded_this_pass = {n.id: n for n in wordlist_frontier}
    for node in expanded_this_pass.values():
        graph.ensure_node(
            engagement_id=engagement_id, asset_type=node.asset_type, label=node.label,
            metadata={"expanded": True, "depth": node.metadata.get("depth", 0)},
        )

    # --- 3. Live-host pass: port/tech/CDN/origin on subdomains AND on origin-IP
    # candidates surfaced by a prior pass's cdn_origin_probe (they land as HOST
    # nodes, not SUBDOMAIN — an origin IP is exactly the kind of asset this loop
    # exists to chase, not just the initial subdomain list). ---
    subdomain_candidates: list[AssetNode] = []
    external_subdomains: list[AssetNode] = []
    owned_apexes = _owned_apexes(graph, engagement_id, target_label)
    for n in graph.list_nodes(engagement_id=engagement_id, asset_type=AssetType.SUBDOMAIN, limit=5000):
        if n.metadata.get("host_expanded"):
            continue
        if _apex_is_owned(n.label, owned_apexes):
            subdomain_candidates.append(n)
        else:
            external_subdomains.append(n)
    if external_subdomains:
        shown = ", ".join(n.label for n in external_subdomains[:8])
        tail = f" (+{len(external_subdomains) - 8} more)" if len(external_subdomains) > 8 else ""
        _report_result(
            f"ⓘ {len(external_subdomains)} third-party subdomain(s) recorded, not live-scanned "
            f"(apex outside the engagement's owned domains): {shown}{tail}"
        )
        for node in external_subdomains:
            graph.ensure_node(
                engagement_id=engagement_id, asset_type=node.asset_type, label=node.label,
                metadata={"host_expanded": True, "external_infra": True},
            )
    all_origin_nodes = [
        n for n in graph.list_nodes(engagement_id=engagement_id, asset_type=AssetType.HOST, limit=5000)
        if n.metadata.get("role") == "origin_candidate" and not n.metadata.get("host_expanded")
    ]
    origin_candidates = [n for n in all_origin_nodes if _origin_confidence(n) >= min_origin_confidence]
    held_back_origin = [n for n in all_origin_nodes if _origin_confidence(n) < min_origin_confidence]
    if held_back_origin:
        shown = ", ".join(f"{n.label} (conf {_origin_confidence(n):.1f})" for n in held_back_origin[:5])
        tail = f" (+{len(held_back_origin) - 5} more)" if len(held_back_origin) > 5 else ""
        _report_result(
            f"⚠ held back {len(held_back_origin)} low-confidence origin candidate(s), not scanned — "
            f"{shown}{tail}"
        )
        for n in held_back_origin:
            graph.ensure_node(
                engagement_id=engagement_id, asset_type=n.asset_type, label=n.label,
                metadata={"held_back_low_confidence": True},
            )
    # Subnet-sibling IPs (from the pivot step below, or a prior pass) are exactly
    # the kind of asset this loop exists to chase — same live-host treatment as
    # any subdomain: probe, port-scan, fingerprint, vuln-scan.
    subnet_sibling_candidates = [
        n for n in graph.list_nodes(engagement_id=engagement_id, asset_type=AssetType.IP, limit=5000)
        if n.metadata.get("role") == "subnet_sibling" and not n.metadata.get("host_expanded")
    ]
    # High-confidence sisters are apex domains of the same org — their live hosts
    # deserve the same ports/services/tech profiling as subdomains. Low-confidence
    # sisters stay unprobed (they were never enumerated above, and probing a
    # look-alike domain is an operator call).
    sister_live_candidates = [
        n for n in graph.list_nodes(engagement_id=engagement_id, asset_type=AssetType.HOST, limit=5000)
        if n.metadata.get("role") == "sister_domain"
        and not n.metadata.get("host_expanded")
        and _sister_expandable(n)
    ]
    # The seed apex itself is a live web property — but it's a DOMAIN node, so
    # it never appears in the subdomain list and would otherwise never get the
    # ports/services/tech battery. Same for any apex DOMAIN node (the seed
    # created on bind, and DOMAIN nodes a discovery tool recorded). Include
    # them in the live-host pool; the resolution filter below keeps dead ones
    # out for free.
    apex_candidates = [
        n for n in graph.list_nodes(engagement_id=engagement_id, asset_type=AssetType.DOMAIN, limit=5000)
        if not n.metadata.get("host_expanded")
        and _is_expandable_apex(n, target_label=target_label)
    ]
    live_pool = (
        apex_candidates + subdomain_candidates + sister_live_candidates
        + origin_candidates + subnet_sibling_candidates
    )
    # Subdomain discovery (subfinder/crt/wayback) routinely surfaces names that
    # no longer resolve — dead certs, decommissioned hosts, cPanel auto-names
    # (autodiscover.*, cpanel.*, cpcalendars.*, webmail.*) and literal
    # wildcards. The live-host battery is expensive (port scan + tech + WAF +
    # CDN probe + origin attribution per host) and useless against a name DNS
    # can't find, so resolve the whole pool up front, cheaply and in parallel,
    # and spend the batch cap ONLY on names that actually answer. Dead names
    # are marked host_expanded so they never consume a batch slot again.
    resolved_pairs: list[tuple[AssetNode, str]] = []
    dead_candidates: list[AssetNode] = []
    pool_ips = await asyncio.gather(
        *(asyncio.to_thread(resolve_host_ip, n.label) for n in live_pool)
    )
    for node, ip in zip(live_pool, pool_ips):
        if ip:
            resolved_pairs.append((node, ip))
        else:
            dead_candidates.append(node)

    # A single failed lookup proves nothing — the resolver, the Docker network,
    # or the upstream DNS can blip for a few seconds (a real outage that once
    # permanently marked a LIVE apex "does_not_resolve", skipping the entire
    # ports/services battery on it). Retry once after a beat, in parallel.
    if dead_candidates:
        await asyncio.sleep(2.0)
        retry_ips = await asyncio.gather(
            *(asyncio.to_thread(resolve_host_ip, n.label) for n in dead_candidates)
        )
        still_dead: list[tuple[AssetNode, str | None]] = []
        for node, ip in zip(dead_candidates, retry_ips):
            if ip:
                resolved_pairs.append((node, ip))
            else:
                still_dead.append((node, ip))
        dead_candidates = [node for node, _ in still_dead]

    if dead_candidates:
        # Only commit to "never re-probe" for hosts with NO live evidence. A
        # host that already has URLs/ports/HTTP findings (or is the seed apex,
        # which always does once wayback/gau ran) is only *temporarily*
        # unresolvable — defer it to a later pass instead of killing it, so a
        # DNS hiccup costs one pass, not the whole engagement.
        no_evidence = [n for n in dead_candidates if not _has_live_evidence(engagement_id, n.label)]
        deferred = [n for n in dead_candidates if n not in no_evidence]
        if no_evidence:
            # Two-source death check: a public resolver answering nothing is
            # not proof a name is dead (caches, DNSSEC validation, transient
            # upstream blips all return the same nothing). Ask the zone's own
            # authoritative nameservers directly — an answer there means the
            # record exists and public DNS is just having a moment; defer.
            # Names the authority also cannot answer are still only killed
            # after _DEAD_KILL_PASSES consecutive failed passes, so a flaky
            # window costs passes, never the whole engagement.
            kill_now: list[AssetNode] = []
            deferred_dead: list[AssetNode] = []
            auth_budget = _AUTH_CHECK_PASS_CAP
            for node in no_evidence:
                if not node.metadata.get("dead_auth_checked") and auth_budget > 0:
                    auth_budget -= 1
                    if await asyncio.to_thread(_authoritative_host_ip, node.label):
                        deferred_dead.append(node)
                        continue
                    graph.ensure_node(
                        engagement_id=engagement_id, asset_type=node.asset_type, label=node.label,
                        metadata={"dead_auth_checked": True},
                    )
                fails = int(node.metadata.get("dead_fails") or 0) + 1
                if fails >= _DEAD_KILL_PASSES:
                    kill_now.append(node)
                else:
                    graph.ensure_node(
                        engagement_id=engagement_id, asset_type=node.asset_type, label=node.label,
                        metadata={"dead_fails": fails},
                    )
                    deferred_dead.append(node)
            if kill_now:
                shown = ", ".join(n.label for n in kill_now[:8])
                tail = f" (+{len(kill_now) - 8} more)" if len(kill_now) > 8 else ""
                _report_result(
                    f"⚠ {len(kill_now)} candidate host(s) unresolvable across {_DEAD_KILL_PASSES} passes "
                    f"(public + authoritative) — skipped, never re-probed: {shown}{tail}"
                )
                for node in kill_now:
                    graph.ensure_node(
                        engagement_id=engagement_id, asset_type=node.asset_type, label=node.label,
                        metadata={"host_expanded": True, "does_not_resolve": True},
                    )
            if deferred_dead:
                shown = ", ".join(n.label for n in deferred_dead[:8])
                tail = f" (+{len(deferred_dead) - 8} more)" if len(deferred_dead) > 8 else ""
                _report_result(
                    f"⚠ {len(deferred_dead)} candidate host(s) not resolving this pass — deferred, "
                    f"re-checked next pass: {shown}{tail}"
                )
        if deferred:
            shown = ", ".join(n.label for n in deferred[:8])
            tail = f" (+{len(deferred) - 8} more)" if len(deferred) > 8 else ""
            _report_result(
                f"⚠ {len(deferred)} host(s) with live evidence temporarily unresolvable — deferred to a later pass: {shown}{tail}"
            )
    live_candidates = [pair[0] for pair in resolved_pairs[: _batch_cap("live_host", 15)]]
    if live_candidates:
        _report_result(f"▶ stage 4 — live hosts (ports, services, tech, CDN/origin, vuln scan): {len(live_candidates)} host(s)")
    before_livehost = _snapshot_finding_ids()

    host_tasks = [
        _expand_host(node, engagement_id=engagement_id, run_id=run_id, dispatch=_dispatch, on_progress=on_progress)
        for node in live_candidates
    ]
    if host_tasks:
        await asyncio.gather(*host_tasks)
        _report_stage_findings(before_livehost, "live hosts")
    for node in live_candidates:
        graph.ensure_node(
            engagement_id=engagement_id, asset_type=node.asset_type, label=node.label,
            metadata={"host_expanded": True},
        )

    # --- 4. Reverse-DNS + ASN/netblock lookup on IPs not yet PTR-checked, then
    # subnet pivot on whatever netblocks that surfaces. Every confirmed real IP
    # that reaches this point (resolved subdomain, origin candidate, subnet
    # sibling — all funnel through here) gets its netblock looked up once. ---
    ip_candidates = [
        n for n in graph.list_nodes(engagement_id=engagement_id, asset_type=AssetType.IP, limit=5000)
        if not n.metadata.get("ptr_checked")
    ]
    if ip_candidates:
        _report_result(f"▶ stage 5 — reverse DNS/PTR, netblock lookup & subnet pivot: {len(ip_candidates)} IP(s)")

    ptr_steps = _installed_steps("ptr_expansion")
    ptr_tasks = [
        _dispatch(tool, {param: n.label}, extra=extra, stage="netblock lookup", timeout=_PTR_TIMEOUT)
        for n in ip_candidates
        for tool, param, extra in ptr_steps
    ]
    if ptr_tasks:
        await asyncio.gather(*ptr_tasks)
    for n in ip_candidates:
        graph.ensure_node(
            engagement_id=engagement_id, asset_type=AssetType.IP, label=n.label,
            metadata={"ptr_checked": True},
        )

    # Subnet pivot: expand small netblocks (<=256 addresses) asn_enum just
    # surfaced into individual IP frontier nodes — "if a real IP is found,
    # look into its subnet." Bounded deliberately (see _MAX_AUTO_SWEEP_ADDRESSES)
    # — a /16 or larger is recorded as an observation (asn_enum already does
    # that) but never auto-swept; that's an operator call, not a mechanical one.
    netblock_findings = store.list(
        engagement_id=engagement_id, tag="asn_prefix", limit=200,
    )
    already_swept_cidrs = {
        n.metadata.get("cidr")
        for n in graph.list_nodes(engagement_id=engagement_id, asset_type=AssetType.IP, limit=20_000)
        if n.metadata.get("role") == "subnet_sibling"
    }
    swept_this_pass: list[str] = []
    for finding in netblock_findings:
        cidr = str(finding.metadata.get("cidr") or "").strip()
        if not cidr or cidr in already_swept_cidrs:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if network.num_addresses > _MAX_AUTO_SWEEP_ADDRESSES:
            continue
        already_swept_cidrs.add(cidr)
        swept_this_pass.append(cidr)
        for host_ip in network.hosts():
            # ptr_checked=True at creation: siblings still get the full
            # live-host treatment (step 2, keyed on host_expanded) — this only
            # skips re-running PTR+asn_enum per sibling, which would otherwise
            # recursively discover more netblocks from every single IP in an
            # already-discovered one and never terminate.
            graph.ensure_node(
                engagement_id=engagement_id, asset_type=AssetType.IP, label=str(host_ip),
                metadata={"role": "subnet_sibling", "cidr": cidr, "ptr_checked": True},
            )
    if swept_this_pass:
        _report_result(f"✓ subnet pivot: expanded {', '.join(swept_this_pass)} into live-host candidates")

    # --- Stage 6: OSINT contacts — harvest emails/phones/people/socials per apex
    # domain, then enrich the concrete contacts that surfaces (account existence
    # for emails, carrier/OSINT for phones, likely-address permutation for
    # people). Enrichment is keyed on discovered contacts, not the domain, and
    # both discovery and enrichment are idempotent across passes via the exec
    # cache (same email/phone/name -> cache hit, not a re-run). ---
    await _expand_contacts(
        engagement_id=engagement_id, run_id=run_id, graph=graph, dispatch=_dispatch,
        store=store, report_result=_report_result, snapshot=_snapshot_finding_ids,
        report_stage_findings=_report_stage_findings,
    )

    after_node_ids = {n.id for n in graph.list_nodes(engagement_id=engagement_id, limit=20_000)}
    after_edge_keys = {
        (e.source_id, e.target_id, e.relationship)
        for e in graph.list_edges(engagement_id=engagement_id, limit=50_000)
    }
    new_nodes = len(after_node_ids - before_node_ids)
    new_edges = len(after_edge_keys - before_edge_keys)

    health_line = _tool_health_summary(tool_health, new_nodes)
    if health_line:
        _report_result(health_line)

    state = get_surface_expansion_store().record_pass(
        engagement_id=engagement_id, new_nodes=new_nodes, new_edges=new_edges,
    )
    return ExpansionDelta(
        engagement_id=engagement_id,
        frontier_processed=len(expanded_this_pass) + len(live_candidates),
        new_nodes=new_nodes,
        new_edges=new_edges,
        exhausted=state.exhausted,
        total_passes=state.total_passes,
    )


async def _expand_host(
    node: AssetNode, *, engagement_id: str, run_id: str, dispatch,
    on_progress: Callable[[str], None] | None = None,
) -> None:
    host = node.label
    # Wordlist/passive subdomain discovery (subfinder/amass brute force,
    # crt.sh cert history) routinely surfaces names that no longer resolve —
    # dead certs, decommissioned hosts, and literal wildcard entries like
    # "*.example.com" misread as a real hostname (a wildcard can never
    # resolve as a literal DNS query). Running the full battery — port scan,
    # tech analysis, WAF check, CDN probe, vuln scan — against something DNS
    # already can't find wastes real time and produces nothing but noise
    # every one of those tools then has to individually report as empty.
    # One cheap resolution check replaces N expensive ones with the same
    # answer. IPv6-aware: CDN-fronted apexes often answer only with AAAA.
    resolved_ip = await asyncio.to_thread(resolve_host_ip, host)
    if not resolved_ip:
        if on_progress is not None:
            on_progress(f"live-host: {host} does not resolve — skipping (no live host)")
        logger.debug("Surface expansion: %s does not resolve, skipping live-host battery", host)
        return

    # Config-driven host probes (host_expansion in expansion.yaml), each run only
    # if installed. cdn_origin_probe self-gates on CDN detection and only yields
    # origin-IP candidates when it finds a CDN, so it needs no separate gate.
    for tool, param, extra in _installed_steps("host_expansion"):
        await dispatch(tool, {param: host}, extra=extra, stage="live-host", timeout=_LIVE_HOST_TIMEOUT)

    # --- Web depth (web_depth in expansion.yaml): only for hosts that are
    # actually serving HTTP. robots/.well-known, JS endpoints/secrets, content
    # discovery, and host-scoped historical URLs — the surface every live web
    # app exposes beyond its homepage. Skipped when no URL finding exists for
    # this host yet (pure port-service host, e.g. SSH-only), and gated by
    # `phases.web_depth` the same way `vuln_scan` is: content discovery is a
    # deliberate later choice, not something a plain "enumerate subs/IPs/
    # ports" ask should trigger as a breadth-pass side effect. ---
    if _phase_enabled("web_depth") and _host_is_live_web(engagement_id, host=host):
        if on_progress is not None:
            on_progress(f"live-host: web-depth probing {host}…")
        for tool, param, extra in _installed_steps("web_depth"):
            await dispatch(tool, {param: host}, extra=extra, stage="web depth", timeout=_WEB_DEPTH_TIMEOUT)

    # A second, independent origin-attribution technique (favicon/cert/SAN/
    # historical-DNS correlation) so a Cloudflare-fronted host has more than one
    # shot at surfacing its real origin, not just cdn_origin_probe's heuristics.
    await dispatch("origin_ip_attribution", {"domain": host}, stage="live-host", timeout=_LIVE_HOST_TIMEOUT)
    # Passive Shodan host intel on the resolved IP — banners/ports/history that
    # can reveal an origin behind a CDN — but only when a key is configured, so
    # an unkeyed run doesn't burn a call on a guaranteed empty result. Shodan
    # is IPv4-indexed; an IPv6-only answer (AAAA-only CDN edge) has no Shodan
    # record to look up.
    if os.getenv("SHODAN_API_KEY", "").strip() and is_ipv4(resolved_ip):
        await dispatch("shodan_host_info", {"ip": resolved_ip}, stage="live-host", timeout=_LIVE_HOST_TIMEOUT)

    # Service/version detection on exactly the ports naabu just found open —
    # nmap -sV -sC scoped to those ports (not a blind full-range scan). Port
    # discovery without versions is an incomplete profile; this closes it.
    open_ports = _host_open_ports(engagement_id, host=host, ip=resolved_ip)
    if open_ports:
        await dispatch(
            "nmap_service_scan", {"target": host, "additional_args": f"-p {','.join(open_ports)}"},
            stage="service scan", timeout=_SERVICE_SCAN_TIMEOUT,
        )

    # If no service/version profile exists for this host yet, the SYN-based
    # discovery (naabu) and its -sV follow-up either never ran (no port
    # evidence) or came back empty on every probe — both signatures of a
    # per-host firewall that drops raw SYN probes while permitting established
    # connections. One bounded TCP-connect retry closes the gap: the known
    # ports when we have them, the common-service port set otherwise.
    # --host-timeout caps a filtered host at ~90s, once.
    if not _host_has_services(engagement_id, host=host, ip=resolved_ip):
        if open_ports:
            connect_flags = f"-Pn -sT -sV -p {','.join(open_ports)} --max-retries 1 --host-timeout 90s"
        else:
            connect_flags = _CONNECT_FALLBACK_FLAGS
        if on_progress is not None:
            on_progress(f"live-host: no services yet on {host} — connect-scan retry…")
        await dispatch(
            "nmap_custom_scan",
            {"target": host, "flags": connect_flags},
            stage="service scan", timeout=_SERVICE_SCAN_TIMEOUT,
        )

    # Whatever ports this host just got, let the existing comprehensive
    # vuln/vulners scan run against them — reuse, don't duplicate its logic.
    # Bounded the same way as everything else here: this can legitimately run
    # long (full port range + vulners correlation), but it must still be able
    # to give up rather than hang the pass forever. Gated by the `phases.
    # vuln_scan` config flag: the breadth pass is recon by default, vuln
    # analysis is a deliberate later phase (config/expansion.yaml).
    if _phase_enabled("vuln_scan"):
        # Lives in phase_supervisor (the vuln-phase owner), not orchestrator —
        # the old import path silently raised ImportError every call and was
        # swallowed below, so this whole block was dead. It is engagement-scoped
        # and self-dedupes via tool_coverage.has_run (keyed on the seed target),
        # so invoking it per-host runs the scan at most once per engagement.
        from osprey.services.phase_supervisor import _maybe_auto_scan_network_vulns

        if on_progress is not None:
            on_progress(f"live-host: vuln-scanning {host}…")
        try:
            await asyncio.wait_for(
                _maybe_auto_scan_network_vulns(
                    engagement_id=engagement_id, run_id=run_id,
                ),
                timeout=_VULN_SCAN_TIMEOUT,
            )
        except TimeoutError:
            logger.debug(
                "Surface expansion: vuln scan timed out after %ss for %s (non-fatal, pass continues)",
                _VULN_SCAN_TIMEOUT, host,
            )
        except Exception:
            logger.debug("Surface expansion: vuln scan failed for %s (non-fatal, pass continues)", host, exc_info=True)

    # --- Tech-conditional dispatch: the general vuln scan above is signature-
    # based; platform-specific scanners go deeper than any template set. When a
    # fingerprint says the host runs a known CMS/platform, run its dedicated
    # scanner instead of pretending the generic pass was enough. Config-free
    # (a small, fixed table) because the mapping is stable: each fingerprint
    # maps to exactly one dedicated scanner. Same vuln_scan phase gate. ---
    tech = _host_technology(engagement_id, host=host)
    if _phase_enabled("vuln_scan") and tech == "wordpress":
        if on_progress is not None:
            on_progress(f"live-host: WordPress detected on {host} — running wpscan…")
        await dispatch(
            "wpscan_analyze", {"url": host}, stage="platform scan", timeout=_WPSCAN_TIMEOUT,
        )


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


def _host_technology(engagement_id: str, *, host: str) -> str:
    """Best-known CMS/platform for this host from TECHNOLOGY findings, or ''.

    Matches by hostname metadata first, then falls back to any technology
    finding whose target equals the host (httpx/tech_stack findings carry
    either)."""
    from osprey.schemas.finding import FindingType
    from osprey.services.findings_store import get_findings_store

    store = get_findings_store()
    host_l = (host or "").lower()
    best: dict[str, int] = {}
    for f in store.list(engagement_id=engagement_id, finding_type=FindingType.TECHNOLOGY, limit=500):
        meta = f.metadata or {}
        hit = (
            str(meta.get("hostname") or "").lower() == host_l
            or str(f.target or "").lower() == host_l
        )
        if not hit:
            continue
        name = str(f.title or "").lower()
        if "wordpress" in name:
            best["wordpress"] = best.get("wordpress", 0) + 1
    if not best:
        return ""
    return max(best, key=best.get)


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


async def _expand_contacts(
    *, engagement_id: str, run_id: str, graph, dispatch, store,
    report_result: Callable[[str], None], snapshot: Callable[[], set[str]],
    report_stage_findings: Callable[[set[str], str], None],
) -> None:
    """Stage 6 — OSINT contact discovery + enrichment.

    Discovery (per apex domain, once): theharvester + web_contact_harvest surface
    emails / phones / people / socials. Enrichment (per discovered contact):
    holehe on emails, phoneinfoga on phones, email_permute on people — these need
    a concrete contact as input, so they run on what discovery found, not on the
    domain. Idempotent across passes: discovery is gated by a graph flag, and
    enrichment repeats hit the exec cache instead of re-running.
    """
    from osprey.schemas.finding import FindingType

    # Only apex domains this engagement actually owns get contact harvesting —
    # OSINT tools like theharvester return canned test data (e.g. the author's
    # own email cmartorella@edge-security.com) that would otherwise make a
    # third-party domain look like an owned sister apex.
    apex_nodes = graph.list_nodes(engagement_id=engagement_id, asset_type=AssetType.DOMAIN, limit=1)
    apex_label = apex_nodes[0].label if apex_nodes else ""

    domain_nodes = [
        n for n in graph.list_nodes(engagement_id=engagement_id, asset_type=AssetType.DOMAIN, limit=5000)
        if not n.metadata.get("contacts_harvested")
        and _is_expandable_apex(n, target_label=apex_label)
    ][:_DOMAIN_BATCH_CAP]

    if domain_nodes:
        report_result(f"▶ stage 6 — OSINT contacts (emails, phones, people): {len(domain_nodes)} domain(s)")
        before = snapshot()
        tasks = [
            dispatch(tool, {param: node.label}, stage="osint contacts", timeout=_CONTACT_TIMEOUT)
            for node in domain_nodes
            for tool, param in _CONTACT_DISCOVERY_TOOLS
        ]
        await asyncio.gather(*tasks)
        report_stage_findings(before, "OSINT contacts")
        for node in domain_nodes:
            graph.ensure_node(
                engagement_id=engagement_id, asset_type=AssetType.DOMAIN, label=node.label,
                metadata={"contacts_harvested": True},
            )

    # Enrichment of the concrete contacts discovered so far (this pass or a prior
    # one). Capped per pass; exec cache makes re-processing an already-enriched
    # contact a no-op instead of a real re-run.
    emails = [f.title for f in store.list(engagement_id=engagement_id, finding_type=FindingType.EMAIL, limit=500) if f.title]
    phones = [f.title for f in store.list(engagement_id=engagement_id, finding_type=FindingType.PHONE, limit=500) if f.title]
    people = [f for f in store.list(engagement_id=engagement_id, finding_type=FindingType.PERSON, limit=500) if f.title]

    apex = ""
    apex_nodes = graph.list_nodes(engagement_id=engagement_id, asset_type=AssetType.DOMAIN, limit=1)
    if apex_nodes:
        apex = apex_nodes[0].label

    enrich_specs: list[tuple[str, dict]] = []
    for email in dict.fromkeys(emails):  # dedupe, preserve order
        enrich_specs.append(("holehe", {"email": email}))
    for phone in dict.fromkeys(phones):
        enrich_specs.append(("phoneinfoga", {"phone": phone}))
    seen_person: set[str] = set()
    for person in people:
        domain = str((person.metadata or {}).get("domain") or "").strip() or apex
        key = f"{person.title}|{domain}"
        if domain and key not in seen_person:
            seen_person.add(key)
            enrich_specs.append(("email_permute", {"name": person.title, "domain": domain}))

    # Cap the specs BEFORE turning them into coroutines — building then slicing
    # coroutines would leave the dropped ones un-awaited.
    enrich_specs = enrich_specs[:_CONTACT_ENRICH_BATCH_CAP]
    if enrich_specs:
        report_result(f"▶ stage 6b — contact enrichment: {len(enrich_specs)} lookup(s)")
        before_enrich = snapshot()
        await asyncio.gather(*[
            dispatch(tool, params, stage="contact enrich", timeout=_CONTACT_ENRICH_TIMEOUT)
            for tool, params in enrich_specs
        ])
        report_stage_findings(before_enrich, "contact enrichment")


def get_expansion_state(engagement_id: str) -> ExpansionState | None:
    return get_surface_expansion_store().get(engagement_id)


class PassReport(BaseModel):
    pass_number: int
    delta: ExpansionDelta
    new_finding_titles: list[str] = []


class ExpansionReport(BaseModel):
    engagement_id: str
    passes: list[PassReport] = []
    exhausted: bool
    stopped_reason: str  # "exhausted" | "max_passes"
    new_candidate_count: int = 0
    new_candidate_samples: list[str] = []
    # Low-confidence origin candidates the engine deliberately did NOT scan —
    # surfaced here, at the end, once all the confident data work is done, so
    # an operator (or the LLM) can decide whether to expand them too instead
    # of the engine silently either scanning or dropping a guess.
    held_back_low_confidence: list[str] = []
    # Associated domains discovered but never worked on (work_sisters off) —
    # same end-of-run surfacing: the operator decides whether any of them
    # deserve a full expansion, the engine never assumes.
    held_back_sisters: list[str] = []

    @property
    def total_new_nodes(self) -> int:
        return sum(p.delta.new_nodes for p in self.passes)

    @property
    def total_new_edges(self) -> int:
        return sum(p.delta.new_edges for p in self.passes)


_TITLE_SAMPLE_CAP = 20


async def run_expansion_to_fixpoint(
    *,
    engagement_id: str,
    run_id: str,
    max_passes: int = 5,
    on_pass: Callable[[PassReport], None] | None = None,
    on_progress: Callable[[str], None] | None = None,
    min_origin_confidence: float = _MIN_ORIGIN_CONFIDENCE,
) -> ExpansionReport:
    """Loop run_expansion_pass to fixpoint (2 consecutive zero-delta passes) or
    max_passes, whichever comes first — bounded so one call can't run forever
    on a large domain. Unlike a bare delta count, every pass's actual new
    finding titles are captured so the caller sees concrete new assets, not
    just numbers — this is the MCP-facing entry point, and "the LLM must see
    what ran and what changed" only holds if the response says what, not how
    many.
    """
    from osprey.services.exploit_candidate_store import get_exploit_candidate_store
    from osprey.services.exploit_pipeline import scan_for_candidates
    from osprey.services.findings_store import get_findings_store

    if not engagement_id:
        return ExpansionReport(
            engagement_id=engagement_id, passes=[], exhausted=False, stopped_reason="max_passes",
        )

    store = get_findings_store()
    passes: list[PassReport] = []
    exhausted = False

    for i in range(1, max_passes + 1):
        before_ids = {f.id for f in store.list(engagement_id=engagement_id, limit=5000)}
        delta = await run_expansion_pass(
            engagement_id=engagement_id, run_id=run_id, on_progress=on_progress,
            min_origin_confidence=min_origin_confidence,
        )
        after = store.list(engagement_id=engagement_id, limit=5000)
        new_titles = [f.title for f in after if f.id not in before_ids][:_TITLE_SAMPLE_CAP]
        pass_report = PassReport(pass_number=i, delta=delta, new_finding_titles=new_titles)
        passes.append(pass_report)
        if on_pass is not None:
            try:
                on_pass(pass_report)
            except Exception:
                logger.debug("on_pass callback failed (non-fatal)", exc_info=True)
        if delta.exhausted:
            exhausted = True
            break
        if delta.frontier_processed == 0:
            # Nothing to do this pass and the store hasn't flagged exhaustion
            # yet (first empty pass) — one more won't help either; stop early
            # rather than burning through max_passes on no-ops.
            break

    candidates_before = {
        c.id for c in get_exploit_candidate_store().list_for_engagement(engagement_id)
    }
    candidates = scan_for_candidates(engagement_id=engagement_id, run_id=run_id)
    new_candidates = [c for c in candidates if c.id not in candidates_before]

    from osprey.services.engagement_graph import get_engagement_graph

    held_back = [
        f"{n.label} (confidence {_origin_confidence(n):.1f})"
        for n in get_engagement_graph().list_nodes(
            engagement_id=engagement_id, asset_type=AssetType.HOST, limit=5000,
        )
        if n.metadata.get("held_back_low_confidence") and not n.metadata.get("host_expanded")
    ]
    held_back_sisters = [
        f"{n.label} ({n.metadata.get('hunter_confidence', '?')})"
        for n in get_engagement_graph().list_nodes(
            engagement_id=engagement_id, asset_type=AssetType.HOST, limit=5000,
        )
        if n.metadata.get("role") == "sister_domain"
    ]
    # de-dupe in case a sister was also minted as a DOMAIN node
    seen_sisters: set[str] = set()
    deduped_sisters: list[str] = []
    for entry in held_back_sisters:
        label = entry.split(" ", 1)[0]
        if label not in seen_sisters:
            seen_sisters.add(label)
            deduped_sisters.append(entry)

    on_progress_final = on_progress
    if held_back and on_progress_final is not None:
        shown = ", ".join(held_back[:8])
        tail = f" (+{len(held_back) - 8} more)" if len(held_back) > 8 else ""
        on_progress_final(
            f"RESULT::⚠ {len(held_back)} low-confidence candidate(s) held back, not scanned — "
            f"{shown}{tail}. Re-run with --include-low-confidence to expand them too."
        )
    if deduped_sisters and on_progress_final is not None:
        shown = ", ".join(deduped_sisters[:8])
        tail = f" (+{len(deduped_sisters) - 8} more)" if len(deduped_sisters) > 8 else ""
        on_progress_final(
            f"RESULT::ⓘ {len(deduped_sisters)} associated domain(s) discovered but not worked on — "
            f"{shown}{tail}. Only the seed domain + its subdomains were scanned. "
            f"Say the word to expand any of them (set work_sisters: true in config/expansion.yaml)."
        )

    return ExpansionReport(
        engagement_id=engagement_id,
        passes=passes,
        exhausted=exhausted,
        stopped_reason="exhausted" if exhausted else "max_passes",
        new_candidate_count=len(new_candidates),
        new_candidate_samples=[
            f"{c.promotion_trigger}: {c.evidence_summary[:80]}" for c in new_candidates[:10]
        ],
        held_back_low_confidence=held_back,
        held_back_sisters=deduped_sisters,
    )
