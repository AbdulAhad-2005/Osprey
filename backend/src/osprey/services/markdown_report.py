"""Human-readable Markdown recon report.

Two layers, not one: a short structural overview (seed -> sister domains ->
subdomains -> IPs, built on attack_surface_tree.py's existing tree assembly,
reused not re-derived) for orientation, followed by the actual substance —
every tool's output, grouped by tool then by target, evidence included even
when unparsed.

Plan 19: the substance comes from OBSERVATIONS (what each tool actually
produced), not findings. Findings now hold only brain-authored CONCLUSIONS, so
reading tool output from them left a no-LLM recon report blank. Scanner matches
are shown as unverified CLAIMS (SCANNER_SIGNAL observations), kept distinct from
any brain-authored vulnerability conclusion — a scanner match is never dressed
up as a confirmed vulnerability here.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from osprey.schemas.attack_surface import DomainBranch, HostSurface
from osprey.schemas.finding import Finding, FindingType
from osprey.schemas.observation import Observation, ObservationType
from osprey.services.attack_surface_tree import build_attack_surface_tree
from osprey.services.findings_store import get_findings_store
from osprey.services.observation_store import get_observation_store

# Uncapped relative to attack_surface_tree's interactive-view defaults (25-80
# hosts) — a saved report is read later, not rendered live in a chat turn, so
# it can afford to be complete rather than trimmed for context budget.
_REPORT_HOST_CAP = 2000
_REPORT_SISTER_CAP = 500
_MAX_SCANNED = 20_000
_EVIDENCE_SNIPPET_CHARS = 1500


def build_recon_markdown(engagement_id: str) -> str | None:
    tree = build_attack_surface_tree(
        engagement_id, max_hosts_per_domain=_REPORT_HOST_CAP, max_sisters=_REPORT_SISTER_CAP,
    )
    if tree is None:
        return None

    observations = get_observation_store().list_for_engagement(engagement_id, limit=_MAX_SCANNED)
    # Conclusions (brain-authored) — shown alongside unverified scanner claims
    # in the Vulnerabilities section, clearly distinguished.
    conclusions = [
        f for f in get_findings_store().list(engagement_id=engagement_id, limit=_MAX_SCANNED, exclude_noise=False)
        if f.finding_type == FindingType.VULNERABILITY
    ]

    lines: list[str] = [
        f"# Recon Report — {tree.seed}",
        f"_Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_",
        "",
    ]
    lines.extend(_summary_section(tree, observations))
    lines.extend(_tools_executed_section(observations))
    lines.extend(_asset_overview_section(tree))
    lines.extend(_contact_osint_section(observations))
    lines.extend(_vulnerabilities_section(observations, conclusions))
    lines.extend(_detailed_by_tool_section(observations))

    return "\n".join(lines)


def _obs_label(o: Observation) -> str:
    d = o.details or {}
    return str(d.get("title") or d.get("url") or d.get("hostname") or o.target or o.type.value)


def _obs_content(o: Observation) -> str:
    d = o.details or {}
    return str(d.get("raw") or d.get("snippet") or d.get("evidence") or d.get("response") or "")


def _summary_section(tree, observations: list[Observation]) -> list[str]:
    lines = [
        "## Summary",
        f"- Sister/associated domains: {tree.stats.sisters}",
        f"- Subdomains discovered: {tree.stats.subdomains}",
        f"- Unique IPs: {tree.stats.unique_ips}",
        f"- Open ports: {tree.stats.open_ports}",
        f"- Services identified: {tree.stats.services}",
        f"- Orphan hosts (not clearly under seed/sisters): {tree.stats.orphan_hosts}",
        f"- Total tool observations recorded: {len(observations)}",
    ]
    if tree.truncated:
        lines.append("- Some sections were capped even at report-generation size — surface is unusually large.")
    lines.append("")
    return lines


def _tools_executed_section(observations: list[Observation]) -> list[str]:
    """What actually ran, and how much each one produced — answers "did
    anything even run" before the reader infers it from scattered mentions.
    Rate-limiting/ban signals never reach observations at all (execution
    telemetry on the audit log, not a claim about the target), so no exclusion
    is needed here."""
    counts = Counter(o.source_tool or "(unknown)" for o in observations)
    lines = ["## Tools Executed", "| Tool | Observations |", "|---|---|"]
    for tool, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"| {tool} | {count} |")
    lines.append("")
    return lines


def _asset_overview_section(tree) -> list[str]:
    lines: list[str] = []

    def render_host(hs: HostSurface, heading_level: int) -> None:
        h = "#" * heading_level
        cdn = " `behind CDN/WAF`" if hs.cf else ""
        lines.append(f"{h} {hs.host}{cdn}")
        if hs.ips:
            lines.append(f"- **IPs:** {', '.join(hs.ips)}")
        if hs.ports:
            lines.append(f"- **Ports:** {', '.join(hs.ports)}")
        if hs.services:
            lines.append(f"- **Services:** {', '.join(hs.services)}")
        if hs.technologies:
            lines.append(f"- **Technologies:** {', '.join(hs.technologies)}")
        if hs.tags:
            lines.append(f"- **Tags:** {', '.join(hs.tags)}")
        lines.append("")

    def render_branch(br: DomainBranch, heading_level: int) -> None:
        h = "#" * heading_level
        lines.append(f"{h} {br.domain} _{br.role}_")
        if br.incomplete:
            lines.append("_No structured host data for this domain yet — see Detailed Findings below for raw tool output._")
            lines.append("")
            return
        if br.direct:
            render_host(br.direct, heading_level + 1)
        for hs in br.subdomains:
            render_host(hs, heading_level + 1)

    lines.append("## Asset Overview")
    lines.append(
        "_Structural skeleton only — ports/services/tech shown here are what made it into "
        "structured fields. See **Detailed Findings by Tool** below for everything each tool "
        "actually returned, including unparsed output._"
    )
    lines.append("")
    lines.append("### Seed Domain")
    if tree.seed_branch:
        render_branch(tree.seed_branch, 4)
    else:
        lines.append("_No data yet._")
        lines.append("")

    if tree.sisters:
        lines.append("### Sister / Associated Domains")
        for br in tree.sisters:
            render_branch(br, 4)

    if tree.orphans:
        lines.append("### Other Discovered Hosts")
        lines.append("_Hosts found but not clearly linked to the seed or a sister domain._")
        lines.append("")
        for hs in tree.orphans:
            render_host(hs, 4)

    return lines


def _contact_osint_section(observations: list[Observation]) -> list[str]:
    """Emails/phones/orgs/whois pulled out and surfaced up front — high value,
    easy to miss buried in a per-tool dump further down. All sourced from
    observations by type."""
    def _of_type(t: ObservationType) -> list[Observation]:
        return [o for o in observations if o.type == t]

    whois = [o for o in observations if o.source_tool == "whois_lookup"]
    emails = _of_type(ObservationType.EMAIL)
    phones = _of_type(ObservationType.PHONE)
    orgs = _of_type(ObservationType.ORGANIZATION)
    persons = _of_type(ObservationType.PERSON)
    usernames = _of_type(ObservationType.USERNAME)
    other_subs = [
        o for o in observations
        if o.type == ObservationType.SUBDOMAIN and (o.source_tool or "") == "theharvester"
    ]

    if not any([whois, emails, phones, orgs, persons, usernames]):
        return []

    lines = ["## Contact Info / WHOIS / OSINT"]
    if whois:
        lines.append("### WHOIS")
        for o in whois[:50]:
            lines.append(f"- {_obs_label(o)}")
        lines.append("")
    if emails:
        lines.append("### Emails")
        for o in emails[:100]:
            lines.append(f"- {_obs_label(o)}" + (f" (via {o.source_tool})" if o.source_tool else ""))
        lines.append("")
    if phones:
        lines.append("### Phone Numbers")
        for o in phones[:100]:
            lines.append(f"- {_obs_label(o)}" + (f" (via {o.source_tool})" if o.source_tool else ""))
        lines.append("")
    if orgs or persons or usernames:
        lines.append("### Organizations / People / Usernames")
        for o in orgs[:50]:
            lines.append(f"- [org] {_obs_label(o)}")
        for o in persons[:50]:
            lines.append(f"- [person] {_obs_label(o)}")
        for o in usernames[:50]:
            lines.append(f"- [username] {_obs_label(o)}")
        lines.append("")
    if other_subs:
        lines.append("### Subdomains via theHarvester")
        for o in other_subs[:100]:
            lines.append(f"- {_obs_label(o)}")
        lines.append("")
    return lines


def _vulnerabilities_section(observations: list[Observation], conclusions: list[Finding]) -> list[str]:
    """Two clearly-separated classes: unverified scanner CLAIMS (SCANNER_SIGNAL
    observations) and brain-authored CONCLUSIONS (VULNERABILITY findings). A
    scanner match is never printed as a confirmed vulnerability."""
    claims = [o for o in observations if o.type == ObservationType.SCANNER_SIGNAL]
    lines = ["## Vulnerabilities"]

    lines.append("### Confirmed / Reported (analyst conclusions)")
    if conclusions:
        seen: set[str] = set()
        for f in conclusions:
            key = f.title.split(" (")[0]
            if key in seen:
                continue
            seen.add(key)
            sev = str(getattr(f.claim_severity, "value", f.claim_severity) or "none")
            affected = sorted({v.target for v in conclusions if v.title.split(" (")[0] == key and v.target})
            affected_str = f" — {', '.join(affected)}" if affected else ""
            lines.append(f"- **[{sev}]** {key}{affected_str}")
    else:
        lines.append("_None — no analyst/LLM has filed a vulnerability conclusion for this engagement._")
    lines.append("")

    lines.append("### Scanner Claims (UNVERIFIED — require analyst confirmation)")
    if claims:
        for o in claims[:300]:
            d = o.details or {}
            sev = str(d.get("claimed_severity") or "unknown")
            via = f" (via {o.source_tool})" if o.source_tool else ""
            tgt = f" — {o.target}" if o.target else ""
            lines.append(f"- _[scanner-claimed {sev}]_ {_obs_label(o)}{tgt}{via}")
    else:
        lines.append("_No scanner claims recorded this run._")
    lines.append("")
    return lines


def _detailed_by_tool_section(observations: list[Observation]) -> list[str]:
    """The actual substance: every tool's output, grouped by tool then by
    target, evidence included verbatim — even when no parser structured it.
    Scanner claims have their own section above; excluded here to avoid
    duplication. URL-history rows (gau/waybackurls/hakrawler) are collapsed per
    target — hundreds of same-shape URL rows are noise, not a technical record."""
    _URL_HISTORY_CAP_PER_TARGET = 40
    by_tool: dict[str, dict[str, list[Observation]]] = {}
    for o in observations:
        if o.type == ObservationType.SCANNER_SIGNAL:
            continue
        tool = o.source_tool or "(unknown tool)"
        tgt = o.target or "(engagement-wide)"
        by_tool.setdefault(tool, {}).setdefault(tgt, []).append(o)

    if not by_tool:
        return []

    lines = [
        "## Detailed Findings by Tool",
        "_Everything each tool returned, grouped by target — including raw/unparsed output. "
        "This is the full technical record; the sections above are curated summaries of it._",
        "",
    ]
    for tool in sorted(by_tool):
        targets = by_tool[tool]
        total = sum(len(items) for items in targets.values())
        lines.append(f"### {tool} ({total} observation(s) across {len(targets)} target(s))")
        for tgt in sorted(targets):
            items = targets[tgt]
            lines.append(f"**{tgt}**")
            url_items = [
                o for o in items
                if o.type == ObservationType.URL or "url_history" in (o.tags or [])
            ]
            structured_items = [o for o in items if o not in url_items]
            for o in structured_items:
                title = _obs_label(o).strip()
                content = _obs_content(o).strip()
                if content and content != title:
                    lines.append(f"- {title}")
                    lines.append("  ```")
                    lines.append("  " + content[:_EVIDENCE_SNIPPET_CHARS].replace("\n", "\n  "))
                    lines.append("  ```")
                else:
                    lines.append(f"- {title}")
            if url_items:
                shown = url_items[:_URL_HISTORY_CAP_PER_TARGET]
                for o in shown:
                    lines.append(f"- {_obs_label(o).strip()}")
                if len(url_items) > len(shown):
                    lines.append(f"- _(+{len(url_items) - len(shown)} more URLs — see raw tool output)_")
            lines.append("")
    return lines
