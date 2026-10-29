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

from osprey.services.parsers.web_recon._shared import _content_hit



# ---------------------------------------------------------------------------
# feroxbuster --json (NDJSON: {"type":"response","url":..,"status":..,"content_length":..})
# ---------------------------------------------------------------------------
def parse_feroxbuster(stdout, *, engagement_id="", run_id="", target=""):
    out: list[Observation] = []
    seen: set[str] = set()
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("type") != "response":
            continue
        url = str(rec.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        out.append(_content_hit(
            url, str(rec.get("status") or ""), str(rec.get("content_length") or ""),
            source_tool="feroxbuster_scan", engagement_id=engagement_id, run_id=run_id, target=target,
        ))
    return out or _dir_text_fallback(stdout, "feroxbuster_scan", engagement_id, run_id, target)


# ---------------------------------------------------------------------------
# ffuf -json (NDJSON: {"url":..,"status":..,"length":..,"input":{"FUZZ":..}})
# ---------------------------------------------------------------------------
def parse_ffuf(stdout, *, engagement_id="", run_id="", target=""):
    out: list[Observation] = []
    seen: set[str] = set()
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        # ffuf NDJSON per-result records carry url+status; skip the config header.
        if "status" not in rec:
            continue
        url = str(rec.get("url") or "").strip()
        fuzz = ""
        if isinstance(rec.get("input"), dict):
            fuzz = str(rec["input"].get("FUZZ") or "")
        if not url and fuzz and target:
            url = f"{target.rstrip('/')}/{fuzz}"
        if not url or url in seen:
            continue
        seen.add(url)
        obs = _content_hit(
            url, str(rec.get("status") or ""), str(rec.get("length") or ""),
            source_tool="ffuf_scan", engagement_id=engagement_id, run_id=run_id, target=target,
        )
        if fuzz:
            obs.details["fuzz"] = fuzz
        out.append(obs)
    return out or _dir_text_fallback(stdout, "ffuf_scan", engagement_id, run_id, target)


# ---------------------------------------------------------------------------
# gobuster dir text: "/admin (Status: 200) [Size: 1234]"
# gobuster dns text (v3.8): "host.example.com 1.2.3.4,2600:9000:..."
# (older builds print "Found: host.example.com" — both accepted)
# ---------------------------------------------------------------------------
_GOBUSTER_RE = re.compile(r"^(\S+)\s+\(Status:\s*(\d{3})\)(?:\s*\[Size:\s*(\d+)\])?")
_GOBUSTER_DNS_RE = re.compile(r"^Found:\s*\[?([^\s\]]+)\]?$", re.IGNORECASE)
_GOBUSTER_DNS_IP_RE = re.compile(
    r"^([a-z0-9](?:[a-z0-9._-]*[a-z0-9])?)\s+([0-9a-fA-F.:,]+)$"
)


def parse_gobuster(stdout, *, engagement_id="", run_id="", target=""):
    base = (target or "").rstrip("/")
    out: list[Observation] = []
    seen: set[str] = set()
    for line in (stdout or "").splitlines():
        line = line.strip()
        m_dns = _GOBUSTER_DNS_RE.match(line)
        m_dns_ip = _GOBUSTER_DNS_IP_RE.match(line) if not m_dns else None
        if m_dns or m_dns_ip:
            host = (m_dns.group(1) if m_dns else m_dns_ip.group(1)).strip().lower().rstrip(".")
            ips = [ip for ip in (m_dns_ip.group(2).split(",") if m_dns_ip else []) if ip]
            if not host or "." not in host or host in seen:
                continue
            seen.add(host)
            out.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id,
                    type=ObservationType.SUBDOMAIN,
                    target=target or host,
                    source_tool="gobuster_scan",
                    details={"hostname": host, "source": "dns-bruteforce", "ips": ips},
                    tags=["dns", "active", "subdomain-enum"],
                )
            )
            continue
        m = _GOBUSTER_RE.match(line)
        if not m:
            continue
        path, status, size = m.group(1), m.group(2), m.group(3) or ""
        url = path if path.startswith("http") else f"{base}{path if path.startswith('/') else '/' + path}"
        if url in seen:
            continue
        seen.add(url)
        out.append(_content_hit(
            url, status, size, source_tool="gobuster_scan",
            engagement_id=engagement_id, run_id=run_id, target=target,
        ))
    return out


def _dir_text_fallback(stdout, source_tool, engagement_id, run_id, target):
    """Fallback for feroxbuster/ffuf default (non-JSON) text output."""
    base = (target or "").rstrip("/")
    out: list[Observation] = []
    seen: set[str] = set()
    for line in (stdout or "").splitlines():
        line = line.strip()
        # feroxbuster text: "200      GET  ...  http://t/x" ; ffuf text: "x  [Status: 200, Size: 5]"
        m_ferox = re.match(r"^(\d{3})\s+\w+\s+.*?(https?://\S+)", line)
        m_ffuf = re.match(r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)", line)
        if m_ferox:
            status, url = m_ferox.group(1), m_ferox.group(2)
            size = ""
        elif m_ffuf and base:
            url = f"{base}/{m_ffuf.group(1)}"
            status, size = m_ffuf.group(2), m_ffuf.group(3)
        else:
            continue
        if url in seen:
            continue
        seen.add(url)
        out.append(_content_hit(url, status, size, source_tool=source_tool,
                                engagement_id=engagement_id, run_id=run_id, target=target))
    return out


# ---------------------------------------------------------------------------
# Digests
# ---------------------------------------------------------------------------
def _content_digest(tool):
    def _d(stdout: str) -> str:
        n = sum(1 for ln in (stdout or "").splitlines()
                if ln.strip().startswith("{") or re.search(r"\(Status:|\[Status:", ln))
        return f"{tool}: ~{n} hit(s)" if n else ""
    return _d
