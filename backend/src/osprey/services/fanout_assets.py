"""Bulk run one catalog tool across an explicit asset list — the one fan-out
primitive (concurrent, allowlist-free). RoE/validation/rate-governing is
already enforced per call by ``tool_execution.execute_tool_request``, so a
second gatekeeping allowlist here would only be redundant — any registered
catalog tool may be fanned out; ``fanout.py`` (sister-domain enum) is a thin
domain-specific caller of this same primitive, not a second engine.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from pydantic import BaseModel, Field

from osprey.schemas.tools import ToolExecutionRequest
from osprey.services.tool_execution import execute_tool_request
from osprey.services.tool_registry import get_tool_definition

logger = logging.getLogger(__name__)

# Resolution order for "which param gets the per-asset value" — checked
# against the tool's own registered parameter names, so any catalog tool
# works without a per-tool table. Falls back to the tool's first declared
# parameter, then "target", if none of these match.
_TARGET_PARAM_PRIORITY = ("target", "domain", "url", "host", "hostname", "ip")

# A very high sanity ceiling only — catches a fat-fingered value, never
# second-guesses a deliberate one (see parallelism_config for the same
# pattern). Exceeding it is logged, not silently substituted without saying so.
_MAX_ASSETS_CEILING = 500


def _primary_param(tool_name: str) -> str:
    tool_def = get_tool_definition(tool_name)
    params = list((tool_def.parameters or {}).keys()) if tool_def else []
    for name in _TARGET_PARAM_PRIORITY:
        if name in params:
            return name
    return params[0] if params else "target"


class FanoutAssetsRequest(BaseModel):
    assets: list[str] = Field(default_factory=list)
    tool_name: str = "httpx_probe"
    dry_run: bool = True
    confirm: bool = False
    max_assets: int = Field(default=25, ge=1)
    timeout_per_tool: int = Field(default=120, ge=30, le=600)
    additional_args: str = ""
    run_id: str = ""
    force_refresh: bool = False


class FanoutAssetResult(BaseModel):
    asset: str
    planned: bool = False
    executed: bool = False
    success: bool = False
    findings_count: int = 0
    finding_titles: list[str] = Field(default_factory=list)
    error: str = ""
    command: str = ""


class FanoutAssetsResponse(BaseModel):
    engagement_id: str
    tool_name: str
    dry_run: bool
    executed: bool
    assets_planned: int = 0
    assets_executed: int = 0
    total_findings: int = 0
    results: list[FanoutAssetResult] = Field(default_factory=list)
    note: str = ""


async def fanout_assets(
    engagement_id: str,
    request: FanoutAssetsRequest | None = None,
) -> FanoutAssetsResponse:
    request = request or FanoutAssetsRequest()
    tool = (request.tool_name or "httpx_probe").strip()
    if get_tool_definition(tool) is None:
        raise ValueError(f"Tool not registered: {tool}")

    max_assets = request.max_assets
    if max_assets > _MAX_ASSETS_CEILING:
        logger.warning(
            "fanout_assets: max_assets=%d exceeds sanity ceiling %d — enforcing %d instead.",
            max_assets, _MAX_ASSETS_CEILING, _MAX_ASSETS_CEILING,
        )
        max_assets = _MAX_ASSETS_CEILING

    will_execute = (not request.dry_run) and request.confirm
    if not request.dry_run and not request.confirm:
        request = request.model_copy(update={"dry_run": True})
        will_execute = False

    raw_assets = [a.strip() for a in (request.assets or []) if (a or "").strip()]
    # de-dupe preserve order
    seen: set[str] = set()
    assets: list[str] = []
    for a in raw_assets:
        key = a.lower()
        if key in seen:
            continue
        seen.add(key)
        assets.append(a)
        if len(assets) >= max_assets:
            break

    primary = _primary_param(tool)

    if not will_execute:
        results = [FanoutAssetResult(asset=asset, planned=True) for asset in assets]
        note = (
            "Explicit asset fan-out — you pick the list (from graph query / findings). "
            "Prefer dry_run first. Does not invent assets."
            " PREVIEW only — set dry_run=false and confirm=true to execute."
        )
        return FanoutAssetsResponse(
            engagement_id=engagement_id,
            tool_name=tool,
            dry_run=True,
            executed=False,
            assets_planned=len(assets),
            assets_executed=0,
            total_findings=0,
            results=results,
            note=note,
        )

    async def _run_one(asset: str) -> FanoutAssetResult:
        item = FanoutAssetResult(asset=asset, planned=True)
        try:
            params: dict[str, Any] = {primary: asset}
            # httpx often wants URL-ish targets
            if tool == "httpx_probe" and "://" not in asset:
                params[primary] = f"https://{asset}"
            response = await execute_tool_request(
                ToolExecutionRequest(
                    tool_name=tool,
                    params=params,
                    engagement_id=engagement_id,
                    run_id=request.run_id or None,
                    timeout=request.timeout_per_tool,
                    additional_args=request.additional_args or "",
                    use_recovery=False,
                    record_findings=True,
                    force_refresh=request.force_refresh,
                    use_cache=not request.force_refresh,
                )
            )
            item.executed = True
            item.success = bool(response.success)
            item.findings_count = len(response.finding_titles or [])
            item.finding_titles = list(response.finding_titles or [])[:15]
            item.command = response.command or ""
            item.error = response.error or ""
        except Exception as exc:  # noqa: BLE001
            logger.exception("fanout_assets failed for %s", asset)
            item.executed = True
            item.success = False
            item.error = str(exc)
        return item

    results = list(await asyncio.gather(*(_run_one(asset) for asset in assets)))
    total_findings = sum(item.findings_count for item in results)
    executed_n = sum(1 for item in results if item.executed)

    note = (
        "Explicit asset fan-out — you pick the list (from graph query / findings). "
        "Prefer dry_run first. Does not invent assets."
    )

    return FanoutAssetsResponse(
        engagement_id=engagement_id,
        tool_name=tool,
        dry_run=False,
        executed=True,
        assets_planned=len(assets),
        assets_executed=executed_n,
        total_findings=total_findings,
        results=results,
        note=note,
    )
