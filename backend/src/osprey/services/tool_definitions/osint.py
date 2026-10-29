"""OSINT_TOOLS — tool catalog definitions."""

from __future__ import annotations

from osprey.schemas.tools import ToolCategory, ToolDefinition, ToolSafetyLevel
from osprey.services.tool_definitions._builders import _COMMON_PARAMS, _p, _t


# ---- OSINT (10 tools) — passive people/identity recon --------------------
# Keyless. Seed from the website (web_contact_harvest), then pivot each
# name/email/username/phone it yields. All PASSIVE — public sources only.

OSINT_TOOLS: list[ToolDefinition] = [
    _t("web_contact_harvest", ToolCategory.OSINT, "python3", ToolSafetyLevel.PASSIVE,
       "Passive-OSINT seed: crawl the target site and extract emails, phones, "
       "social profile links (+handles) and person names.",
       ["osint", "passive", "emails", "social", "seed"],
       {"url": _p("", "Target website URL or bare domain"),
        "target": _p("", "Alias for url"),
        "depth": _p("1", "Crawl depth (0=landing only)"),
        "max_pages": _p("25", "Page cap"),
        **_COMMON_PARAMS}),
    _t("theharvester", ToolCategory.OSINT, "theHarvester", ToolSafetyLevel.PASSIVE,
       "Harvest emails, names, subdomains, hosts and IPs for a domain from public "
       "search engines / OSINT sources (keyless sources by default).",
       ["osint", "passive", "emails", "search-engines", "company"],
       {"domain": _p("", "Target domain"),
        "sources": _p("", "Comma-separated sources (default keyless set; 'all' adds keyed)"),
        "limit": _p("200", "Max results per source"),
        **_COMMON_PARAMS}),
    _t("metagoofil", ToolCategory.OSINT, "metagoofil", ToolSafetyLevel.PASSIVE,
       "Discover public documents (pdf/doc/xls/ppt) for a domain; pair with "
       "exiftool_extract for author/software/GPS metadata.",
       ["osint", "passive", "documents", "metadata"],
       {"domain": _p("", "Target domain"),
        "file_types": _p("pdf,doc,docx,xls,xlsx,ppt,pptx", "Extensions"),
        "limit": _p("50", "Max documents"),
        **_COMMON_PARAMS}),
    _t("dnstwist", ToolCategory.OSINT, "dnstwist", ToolSafetyLevel.PASSIVE,
       "Generate and resolve typosquat / look-alike domains (phishing, brand abuse).",
       ["osint", "passive", "typosquat", "brand", "phishing"],
       {"domain": _p("", "Seed domain"),
        "registered_only": _p("true", "Only resolving permutations"),
        **_COMMON_PARAMS}),
    _t("sherlock", ToolCategory.OSINT, "sherlock", ToolSafetyLevel.PASSIVE,
       "Hunt a username across 400+ sites (fast).",
       ["osint", "passive", "username", "social"],
       {"username": _p("", "Username / handle"),
        "timeout": _p("10", "Per-site timeout"),
        **_COMMON_PARAMS}),
    _t("maigret", ToolCategory.OSINT, "maigret", ToolSafetyLevel.PASSIVE,
       "Deep username search across 3000+ sites, extracting profile data.",
       ["osint", "passive", "username", "social", "profile"],
       {"username": _p("", "Username / handle"),
        "timeout": _p("10", "Per-site timeout"),
        "top_sites": _p("500", "Limit to N popular sites"),
        **_COMMON_PARAMS}),
    _t("social_analyzer", ToolCategory.OSINT, "social-analyzer", ToolSafetyLevel.PASSIVE,
       "Discover and confidence-rate a username's social presence across 1000+ sites.",
       ["osint", "passive", "username", "social"],
       {"username": _p("", "Username / handle"),
        "filter_level": _p("good", "good|best|all"),
        **_COMMON_PARAMS}),
    _t("holehe", ToolCategory.OSINT, "holehe", ToolSafetyLevel.PASSIVE,
       "Check which sites have an account registered to an email (existence, not breach).",
       ["osint", "passive", "email", "accounts"],
       {"email": _p("", "Email address"),
        "only_used": _p("true", "Only sites where the email is registered"),
        **_COMMON_PARAMS}),
    _t("phoneinfoga", ToolCategory.OSINT, "phoneinfoga", ToolSafetyLevel.PASSIVE,
       "Passive OSINT on a phone number: country, carrier, line type, footprint.",
       ["osint", "passive", "phone"],
       {"phone": _p("", "Phone number (E.164, e.g. +14155552671)"),
        **_COMMON_PARAMS}),
    _t("email_permute", ToolCategory.OSINT, "python3", ToolSafetyLevel.PASSIVE,
       "Turn a discovered name + domain into likely corporate email candidates (+MX check).",
       ["osint", "passive", "email", "pivot"],
       {"name": _p("", "Full person name"),
        "domain": _p("", "Corporate domain"),
        **_COMMON_PARAMS}),
    _t("intelx_scan", ToolCategory.OSINT, "python3", ToolSafetyLevel.PASSIVE,
       "Intelligence X breach-intel: phonebook harvest (emails / subdomains / URLs for "
       "a domain) plus leaked account records (user+password) via the Identity API. "
       "Mints EMAIL / SUBDOMAIN / CREDENTIAL findings; leaked creds are INFERRED leads "
       "(breach data, verify against the live target). Needs INTELX_API_KEY "
       "(+ INTELX_IDENTITY_API_KEY for leaked credentials).",
       ["osint", "passive", "credentials", "breach", "emails", "intelx"],
       {"target": _p("", "Domain / email / selector to look up"),
        "mode": _p("all", "phonebook | leaks | all"),
        "limit": _p("200", "Max results"),
        **_COMMON_PARAMS}),
    _t("resecurity_scan", ToolCategory.OSINT, "python3", ToolSafetyLevel.PASSIVE,
       "Resecurity credential-intel lookup — leaked credentials + emails for a domain / "
       "email / selector. Mints CREDENTIAL / EMAIL findings (breach leads, INFERRED). "
       "Configurable connector: needs RESECURITY_API_KEY (+ optional RESECURITY_API_BASE / "
       "RESECURITY_ENDPOINT for your account).",
       ["osint", "passive", "credentials", "breach", "resecurity"],
       {"target": _p("", "Domain / email / selector to look up"),
        "limit": _p("100", "Max results"),
        **_COMMON_PARAMS}),
]
