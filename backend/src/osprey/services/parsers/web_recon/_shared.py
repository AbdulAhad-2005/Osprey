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

from urllib.parse import urlparse

from osprey.schemas.observation import Observation, ObservationType


_INTERESTING_PATH = (
    "/api", "/v1", "/v2", "/graphql", "/admin", "/auth", "/login", "/token",
    "/oauth", "/upload", "/internal", "/private", "/debug", "/actuator",
    "/swagger", "/openapi", "/.env", "/.git", "/config", "/backup", "/console",
)


def _host_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split("@")[-1].split(":")[0].lower()
    except ValueError:
        return ""


def _is_interesting(url: str) -> bool:
    low = url.lower()
    return any(m in low for m in _INTERESTING_PATH)


def _content_hit(
    url: str,
    status: str,
    size: str,
    *,
    source_tool: str,
    engagement_id: str,
    run_id: str,
    target: str,
) -> Observation:
    interesting = _is_interesting(url)
    tags = ["content-discovery", source_tool]
    if interesting:
        tags.append("interesting_path")
    if status in ("401", "403"):
        tags.append("access_controlled")
    return Observation(
        engagement_id=engagement_id,
        run_id=run_id,
        type=ObservationType.URL,
        target=url,
        source_tool=source_tool,
        details={
            "hostname": _host_of(url),
            "url": url,
            "status": status,
            "size": size,
            "interesting": interesting,
        },
        tags=tags,
    )
