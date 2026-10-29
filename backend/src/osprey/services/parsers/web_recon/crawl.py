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

from osprey.schemas.observation import Observation, ObservationType
from osprey.services.parsers._capping import cap_with_accounting

from osprey.services.parsers.web_recon._shared import _host_of, _is_interesting
from osprey.services.parsers.web_recon.params import extract_parameters_from_urls



# ---------------------------------------------------------------------------
# katana -jsonl : {"timestamp":..,"request":{"endpoint":"http://.."},"response":{"status_code":..}}
# ---------------------------------------------------------------------------
def parse_katana(stdout, *, engagement_id="", run_id="", target=""):
    out: list[Observation] = []
    seen: set[str] = set()
    urls: list[str] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            req = rec.get("request") or {}
            url = str(req.get("endpoint") or rec.get("endpoint") or "").strip()
        elif line.startswith("http"):
            url = line.split()[0]
        else:
            continue
        if not url or url in seen:
            continue
        seen.add(url)
        urls.append(url)
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.URL,
            target=url, source_tool="katana_crawl",
            details={"hostname": _host_of(url), "url": url},
            tags=["crawl", "katana"] + (["interesting_path"] if _is_interesting(url) else []),
        ))
    # Attack-surface handoff: also mine parameters from the crawled URLs.
    out.extend(extract_parameters_from_urls(
        urls, source_tool="katana_crawl", engagement_id=engagement_id, run_id=run_id, target=target))
    return out


# ---------------------------------------------------------------------------
# js_recon JSON — endpoints, secrets, cloud assets
# ---------------------------------------------------------------------------
def parse_js_recon(stdout, *, engagement_id="", run_id="", target=""):
    try:
        data = json.loads((stdout or "").strip())
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    out: list[Observation] = []
    tgt = data.get("target") or target

    all_endpoints = [str(ep) for ep in (data.get("endpoints") or [])]
    out.extend(cap_with_accounting(
        all_endpoints,
        max_items=400,
        render=lambda ep: Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.JS_ENDPOINT,
            target=tgt, source_tool="js_recon",
            details={"endpoint": ep, "hostname": _host_of(ep) or _host_of(tgt)},
            tags=["js-endpoint"] + (["interesting_path", "injection_point_candidate"]
                                    if _is_interesting(ep) else []),
        ),
        tool_name="js_recon",
        item_label="JS endpoint",
        engagement_id=engagement_id, run_id=run_id, target=tgt,
    ))

    for sec in (data.get("secrets") or []):
        stype = str(sec.get("type") or "secret")
        high = bool(sec.get("high_signal"))
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.SECRET,
            target=tgt, source_tool="js_recon",
            details={
                "secret_type": stype,
                "match": sec.get("match"),
                "source": sec.get("source"),
                "high_signal": high,
            },
            tags=["secret", "js-secret", stype] + (["verify_validity"] if high else []),
        ))

    for c in (data.get("cloud_assets") or []):
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.ENDPOINT,
            target=tgt, source_tool="js_recon",
            details={
                "kind": "cloud_storage_reference",
                "cloud_type": c.get("type"),
                "bucket": c.get("bucket"),
                "match": c.get("match"),
            },
            tags=["cloud-asset", str(c.get("type"))],
        ))
    return out


# ---------------------------------------------------------------------------
# app_recon JSON — endpoints, backend hosts, secrets, cloud assets + platform
# metadata (Android permissions/components, iOS schemes/ATS, cleartext).
# ---------------------------------------------------------------------------
def parse_app_recon(stdout, *, engagement_id="", run_id="", target=""):
    try:
        data = json.loads((stdout or "").strip())
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict) or data.get("error"):
        return []
    out: list[Observation] = []
    app_type = str(data.get("app_type") or "app")
    app_id = str(data.get("package") or data.get("bundle_id") or data.get("target") or target or "")

    # Backend hostnames mined from the app become recon seeds — same shape as
    # subfinder's SUBDOMAIN observations (hostname in details) so the graph
    # ingests and the engagement resolves/probes them like any other name.
    hosts = [str(h).lower() for h in (data.get("hosts") or []) if str(h).strip()]
    out.extend(cap_with_accounting(
        hosts,
        max_items=300,
        render=lambda h: Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.SUBDOMAIN,
            target=target, source_tool="app_recon",
            details={"hostname": h, "discovered_via": f"app:{app_type}"},
            tags=["app-backend", "from-app-recon"],
        ),
        tool_name="app_recon", item_label="app backend host",
        engagement_id=engagement_id, run_id=run_id, target=target,
    ))

    endpoints = [str(ep) for ep in (data.get("endpoints") or [])]
    out.extend(cap_with_accounting(
        endpoints,
        max_items=500,
        render=lambda ep: Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.ENDPOINT,
            target=ep, source_tool="app_recon",
            details={"endpoint": ep, "hostname": _host_of(ep), "app_type": app_type},
            tags=["app-endpoint", app_type] + (["interesting_path", "injection_point_candidate"]
                                               if _is_interesting(ep) else []),
        ),
        tool_name="app_recon", item_label="app endpoint",
        engagement_id=engagement_id, run_id=run_id, target=target,
    ))

    for sec in (data.get("secrets") or []):
        stype = str(sec.get("type") or "secret")
        high = bool(sec.get("high_signal"))
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.SECRET,
            target=app_id or target, source_tool="app_recon",
            details={
                "secret_type": stype,
                "match": sec.get("match"),
                "source": sec.get("source"),
                "high_signal": high,
                "app_type": app_type,
            },
            tags=["secret", "app-secret", stype] + (["verify_validity"] if high else []),
        ))

    for c in (data.get("cloud_assets") or []):
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.ENDPOINT,
            target=app_id or target, source_tool="app_recon",
            details={
                "kind": "cloud_storage_reference",
                "cloud_type": c.get("type"),
                "bucket": c.get("bucket"),
                "match": c.get("match"),
            },
            tags=["cloud-asset", str(c.get("type"))],
        ))

    # Platform identity as a technology fact.
    platform = str(data.get("platform") or "")
    if platform:
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.TECHNOLOGY,
            target=app_id or target, source_tool="app_recon",
            details={k: data.get(k) for k in ("platform", "package", "bundle_id",
                                              "version", "app_label", "app_type")
                     if data.get(k)},
            tags=["app-platform", platform],
        ))

    # Declared-posture signals — facts the manifest/plist asserts, never a
    # verdict. confidence_for decides whether any becomes a finding.
    def _signal(kind: str, detail: dict, tags: list[str]) -> None:
        out.append(Observation(
            engagement_id=engagement_id, run_id=run_id,
            type=ObservationType.SCANNER_SIGNAL,
            target=app_id or target, source_tool="app_recon",
            details={"signal": kind, "app_type": app_type, **detail},
            tags=["app-posture", kind] + tags,
        ))

    if data.get("cleartext_traffic") is True:
        _signal("cleartext_traffic_permitted",
                {"note": "network_security_config permits cleartext HTTP"}, [])
    if data.get("ats_arbitrary_loads") is True:
        _signal("ios_ats_arbitrary_loads",
                {"note": "NSAllowsArbitraryLoads=true disables App Transport Security"}, [])
    dangerous = [str(p) for p in (data.get("dangerous_permissions") or [])]
    if dangerous:
        _signal("dangerous_permissions", {"permissions": dangerous[:50],
                                          "count": len(dangerous)}, [])
    schemes = [str(s) for s in (data.get("url_schemes") or [])]
    if schemes:
        _signal("custom_url_schemes", {"schemes": schemes[:50]},
                ["deep-link"])
    return out


def _js_digest(stdout: str) -> str:
    try:
        d = json.loads((stdout or "").strip())
    except (json.JSONDecodeError, ValueError):
        return ""
    return (
        f"js_recon: {d.get('js_file_count', 0)} JS file(s), "
        f"{d.get('endpoint_count', 0)} endpoint(s), "
        f"{len(d.get('secrets') or [])} secret(s), "
        f"{len(d.get('cloud_assets') or [])} cloud ref(s)"
    )


def _app_digest(stdout: str) -> str:
    try:
        d = json.loads((stdout or "").strip())
    except (json.JSONDecodeError, ValueError):
        return ""
    if not isinstance(d, dict):
        return ""
    return (
        f"app_recon[{d.get('app_type', '?')}]: {d.get('endpoint_count', 0)} endpoint(s), "
        f"{len(d.get('hosts') or [])} backend host(s), "
        f"{len(d.get('secrets') or [])} secret(s), "
        f"{len(d.get('cloud_assets') or [])} cloud ref(s), "
        f"{len(d.get('permissions') or [])} permission(s)"
    )
