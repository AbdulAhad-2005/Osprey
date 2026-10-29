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

from osprey.schemas.observation import Observation, ObservationType

from osprey.services.parsers.web_recon._shared import _host_of, _is_interesting



# ---------------------------------------------------------------------------
# email_security_probe — sectioned text (=== MX/SPF/DMARC/DKIM ===)
# ---------------------------------------------------------------------------
def parse_email_security(stdout, *, engagement_id="", run_id="", target=""):
    section = ""
    mx: list[str] = []
    spf = ""
    dmarc = ""
    dkim: list[str] = []
    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if line.startswith("=== ") and line.endswith(" ==="):
            section = line.strip("= ").lower()
            continue
        if not line:
            continue
        if section == "mx" and line != "NONE":
            mx.append(line)
        elif section == "spf":
            spf = "" if line == "NONE" else line
        elif section == "dmarc":
            dmarc = "" if line == "NONE" else line
        elif section == "dkim" and line.startswith("DKIM_SELECTOR:"):
            dkim.append(line.split(":", 1)[1].strip())

    out: list[Observation] = []
    dom = (target or "").strip().lower()
    details = {
        "domain": dom, "mx_count": len(mx),
        "has_spf": bool(spf), "has_dmarc": bool(dmarc), "dkim_selectors": dkim,
        "spf": spf[:200], "dmarc": dmarc[:200],
    }
    out.append(Observation(
        engagement_id=engagement_id, run_id=run_id,
        type=ObservationType.DNS_RECORD,
        target=dom, source_tool="email_security_probe",
        details=details,
        tags=["email-security", "dns"],
    ))
    # Spoofing-exposure facts: missing OR weak SPF/DMARC policy is structural,
    # reportable data — the earned-finding pipeline decides if it's worth a
    # finding, this parser only states what it observed.
    weaknesses: list[str] = []
    if not spf:
        weaknesses.append("no SPF record")
    elif re.search(r"[~?]all", spf):
        qual = "~all (softfail)" if "~all" in spf else "?all (neutral)"
        weaknesses.append(f"SPF {qual} — does not hard-fail spoofed senders")
    if not dmarc:
        weaknesses.append("no DMARC record")
    else:
        pol = re.search(r"(?i)\bp\s*=\s*(none|quarantine|reject)", dmarc)
        policy = (pol.group(1).lower() if pol else "none")
        details["dmarc_policy"] = policy
        if policy == "none":
            weaknesses.append("DMARC p=none — monitoring only, does not block spoofed mail")
    if weaknesses:
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.DNS_RECORD,
            target=dom, source_tool="email_security_probe",
            details={**details, "weaknesses": weaknesses},
            tags=["email-security", "spoofing", "misconfig"],
        ))
    return out


# ---------------------------------------------------------------------------
# well_known_probe — sectioned text (=== PATH /x === / STATUS: nnn / body)
# ---------------------------------------------------------------------------
def parse_well_known(stdout, *, engagement_id="", run_id="", target=""):
    out: list[Observation] = []
    base = (target or "").strip()
    cur_path = ""
    cur_status = ""
    body_lines: list[str] = []

    def _flush():
        if not cur_path or cur_status != "200":
            return
        url = cur_path if cur_path.startswith("http") else f"{base.rstrip('/')}{cur_path}"
        body = "\n".join(body_lines)
        tags = ["well-known", "policy-file"]
        details = {
            "path": cur_path, "url": url, "status": cur_status,
            "hostname": _host_of(url), "body_snippet": body[:300],
        }
        # robots.txt Disallow entries are attack-surface leads.
        disallow = re.findall(r"(?im)^\s*Disallow:\s*(\S+)", body)
        if disallow:
            details["disallow"] = disallow[:40]
            tags.append("robots_disallow")
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.URL,
            target=url, source_tool="well_known_probe",
            details=details, tags=tags,
        ))
        # Emit the disallowed paths themselves as URL leads.
        for d in disallow[:30]:
            if not d or d == "/":
                continue
            durl = f"{base.rstrip('/')}{d}" if d.startswith("/") else d
            out.append(Observation(
                engagement_id=engagement_id, run_id=run_id,
                type=ObservationType.URL,
                target=durl, source_tool="well_known_probe",
                details={"url": durl, "from": "robots_disallow"},
                tags=["robots_disallow"] + (["interesting_path"] if _is_interesting(durl) else []),
            ))

    for raw in (stdout or "").splitlines():
        line = raw.rstrip()
        pm = re.match(r"^=== PATH (\S+) ===$", line.strip())
        if pm:
            _flush()
            cur_path, cur_status, body_lines = pm.group(1), "", []
            continue
        if line.strip().startswith("STATUS:"):
            cur_status = line.split(":", 1)[1].strip()
            continue
        if line.strip() == "=== DONE ===":
            _flush()
            cur_path = ""
            continue
        if cur_path:
            body_lines.append(line)
    _flush()
    return out


# ---------------------------------------------------------------------------
# Tech-stack fingerprinting (tech_stack_analyze) and WAF identification
# (wafw00f_scan) — both print human-readable text; neither had a backend
# parser, so their observations always fell through to the raw "Output from …"
# placeholder. TECHNOLOGY observations here feed the tree's tech_by_host and
# the engine's tech-conditional dispatch (e.g. WordPress -> wpscan).
# ---------------------------------------------------------------------------
def parse_tech_stack(stdout, *, engagement_id="", run_id="", target=""):
    """tech_stack_analyze prints one JSON line per probe and a final line
    carrying unified_stack (the merged, deduped technology list). The last
    valid line wins — earlier probe lines are per-method detail."""
    out: list[Observation] = []
    data = None
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            cand = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(cand, dict) and cand.get("unified_stack"):
            data = cand
    if not data:
        return out

    stack = data.get("unified_stack") or []
    seen: set[str] = set()
    for tech in stack:
        if not isinstance(tech, dict):
            continue
        name = str(tech.get("name") or "").strip()
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        version = str(tech.get("version") or "").strip()
        tool_confidence = str(tech.get("confidence") or "low")
        tech_target = target or str(tech.get("target") or "").strip()
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.TECHNOLOGY,
                target=tech_target,
                source_tool="tech_stack_analyze",
                details={
                    "hostname": tech_target,
                    "name": name,
                    "version": version,
                    "categories": tech.get("categories", []),
                    "detected_by": tech.get("detected_by"),
                    "tool_reported_confidence": tool_confidence,
                },
                tags=["technology", "fingerprint"],
            )
        )
    return out


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Note the \s+ before WAF, not \b: WAF names can end in ')' ('Cloudfront
# (Amazon)') and \b does not bind after a non-word char. The generic
# suspicion line ('behind a WAF or some kind of proxy') is filtered by the
# placeholder-name guard in the parser.
_WAF_BEHIND_RE = re.compile(
    r"\b(is|may be|seems to be)\s+(?:behind|protected by)\s+"
    r"([A-Za-z0-9][A-Za-z0-9 /_\-()]{1,80}?)\s+WAF\b",
    re.IGNORECASE,
)

_WAF_PLACEHOLDER_NAMES = frozenset({"a", "an", "some", "any", "the"})


def parse_wafw00f(stdout, *, engagement_id="", run_id="", target=""):
    """wafw00f verdicts: 'The site <url> is behind <Name> WAF.' / '…may be
    behind…' / '…protected by…'. Real output carries ANSI color codes on the
    same line and WAF names can contain parentheses ('Cloudfront (Amazon)'),
    so strip escapes first and allow those characters. A run that detected
    nothing prints no WAF line — legitimately empty, not a raw placeholder
    (parse_tool_output suppresses the fallback for verdict tools)."""
    out: list[Observation] = []
    seen: set[str] = set()
    for raw_line in (stdout or "").splitlines():
        line = _ANSI_RE.sub("", raw_line)
        m = _WAF_BEHIND_RE.search(line)
        if not m:
            continue
        name = " ".join(m.group(2).split())
        if not name or name.lower() in _WAF_PLACEHOLDER_NAMES or name.lower() in seen:
            continue
        seen.add(name.lower())
        verdict = m.group(1).lower()
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.WAF,
                target=target,
                source_tool="wafw00f_scan",
                details={
                    "hostname": target,
                    "waf": name,
                    "verdict": verdict,
                    "raw_line": line.strip()[:500],
                },
                tags=["waf", "technology"],
            )
        )
    return out


def _tech_stack_digest(stdout: str) -> str:
    latest = None
    for line in (stdout or "").splitlines():
        try:
            data = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(data, dict) and "unified_stack" in data:
            latest = data
    if latest is None:
        return ""
    stack = latest.get("unified_stack") or []
    names = [f"{tech.get('name', '?')} {tech.get('version', '')}".strip() for tech in stack if isinstance(tech, dict)]
    failures = [f"{name}: {str(method['error'])[:160]}" for name, method in (latest.get("methods") or {}).items()
                if isinstance(method, dict) and method.get("error")]
    return (f"tech_stack_analyze: {len(stack)} technologies — " + ", ".join(names[:12])
            + (f" (+{len(names) - 12} more)" if len(names) > 12 else "")
            + (". Partial coverage: " + "; ".join(failures) if failures else ""))
