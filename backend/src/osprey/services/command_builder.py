"""Build CLI commands from MCP modules + LLM params/flags."""

from __future__ import annotations

import importlib.util
import logging
import re
import shlex
import sys
from pathlib import Path
from typing import Any

from osprey.schemas.tools import ToolCategory, ToolDefinition
from osprey.services.target_utils import (
    looks_like_domain,
    prefer_ip_for_tool,
    registrable_apex,
)
from osprey.services.tool_registry import get_tool_definition

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[4]
_MCP_SERVERS = _PROJECT_ROOT / "mcp-servers"
# In-Kali path (docker-exec'd, not the backend's own filesystem) — mcp-servers/
# is bind-mounted to /home/mcpuser/mcp-servers inside osprey-kali (docker-compose.yml).
_DOMAIN_HUNTER_CLI = "/home/mcpuser/mcp-servers/recon/tools/_domain_hunter_cli.py"

_INTERNAL_PARAM_KEYS = frozenset({
    "use_recovery",
    "use_cache",
    "exec_timeout",
    # Kernel-only knob: intensity profile is resolved into flags in
    # tool_execution before the command is built; it must never reach build_fn.
    "profile",
})


def _mcp_category(tool_def: ToolDefinition) -> str:
    if tool_def.category == ToolCategory.RECON:
        return "recon"
    if tool_def.category == ToolCategory.NETWORK:
        return "network"
    return tool_def.mcp_server.value


def _load_build_command(tool_name: str, category: str):
    """Import build_command from mcp-servers/<category>/tools/<tool>.py."""
    module_path = _MCP_SERVERS / category / "tools" / f"{tool_name}.py"
    if not module_path.exists():
        return None

    module_name = f"_mcp_tool_{category}_{tool_name}"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        return None

    if str(_MCP_SERVERS) not in sys.path:
        sys.path.insert(0, str(_MCP_SERVERS))

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except ImportError as exc:
        logger.warning("Failed to import tool module %s: %s", module_path, exc)
        return None
    return getattr(module, "build_command", None)


def merge_llm_params(
    params: dict[str, Any],
    additional_args: str = "",
    *,
    freeform_field: str = "additional_args",
) -> dict[str, Any]:
    """Merge typed params with free-form LLM flags. No flag whitelist."""
    merged = {
        k: v
        for k, v in params.items()
        if k not in _INTERNAL_PARAM_KEYS and v is not None and v != ""
    }

    extra_parts: list[str] = []
    if additional_args and str(additional_args).strip():
        extra_parts.append(str(additional_args).strip())

    for alias in ("additional_args", "extra_args", "flags"):
        if alias in merged and merged[alias]:
            val = str(merged.pop(alias)).strip()
            if val and val not in " ".join(extra_parts):
                extra_parts.append(val)

    combined = " ".join(extra_parts).strip()
    if combined:
        if freeform_field == "flags" and "flags" not in merged:
            merged["flags"] = combined
        else:
            existing = str(merged.get(freeform_field, "") or "").strip()
            merged[freeform_field] = f"{existing} {combined}".strip() if existing else combined

    return merged


def _build_domain_hunter_command(params: dict[str, Any]) -> str:
    """Build the domain-hunter invocation.

    Runs ``python3 _domain_hunter_cli.py`` (self-locating module, no cwd) and
    writes the CSV to /tmp so it never pollutes the mounted repo — findings
    are collected from the stdout table/JSON by the parser.
    """
    raw = str(params.get("domain", "")).strip()
    domain = registrable_apex(raw)
    if not domain or not looks_like_domain(domain):
        raise ValueError("domain_hunter requires a registrable seed domain")

    parts = ["python3", shlex.quote(_DOMAIN_HUNTER_CLI), "--domain", shlex.quote(domain)]

    modules = str(params.get("modules", "") or "").strip()
    if modules:
        parts += ["--modules", shlex.quote(modules)]

    confidence_min = str(params.get("confidence_min", "") or "").strip().lower()
    if confidence_min in ("low", "medium", "high"):
        parts += ["--confidence-min", shlex.quote(confidence_min)]

    safe = re.sub(r"[^A-Za-z0-9.]", "_", domain)
    parts += ["--output", shlex.quote(f"/tmp/domain_hunter_{safe}.csv")]

    extra = str(params.get("additional_args", "") or "").strip()
    if extra:
        parts.append(extra)

    return " ".join(parts)


def build_command_for_tool(
    tool_name: str,
    params: dict[str, Any] | None = None,
    *,
    additional_args: str = "",
    tool_def: ToolDefinition | None = None,
    freeform_field: str | None = None,
) -> str:
    """
    Single command builder for all execution paths.

    Uses ``build_command()`` from mcp-servers when available.
    LLM may supply any flags via ``additional_args`` — not restricted to YAML examples.
    """
    params = params or {}
    tool_def = tool_def or get_tool_definition(tool_name)
    if tool_def is None:
        raise ValueError(f"Tool not registered: {tool_name}")

    field = freeform_field or "additional_args"
    merged = merge_llm_params(params, additional_args, freeform_field=field)

    raw_target = str(merged.get("target", merged.get("domain", "")) or "").strip()
    if raw_target:
        resolved_target, _ = prefer_ip_for_tool(tool_name, raw_target)
        if "target" in merged:
            merged["target"] = resolved_target
        if "domain" in merged and tool_name in ("nbtscan_netbios", "arp_scan_discovery"):
            merged["domain"] = resolved_target

    category = _mcp_category(tool_def)
    # Use resolved tool name (not the alias) so _load_build_command finds the correct file.
    resolved_name = tool_def.name
    build_fn = _load_build_command(resolved_name, category)
    if build_fn is None:
        raise ValueError(
            f"No build_command for {tool_name} (resolved={resolved_name}) "
            f"in mcp-servers/{category}/tools/"
        )

    command = build_fn(**merged)
    if not command or not str(command).strip():
        raise ValueError(f"build_command returned empty for {tool_name}")

    logger.debug("Built command for %s: %s", tool_name, command)
    return str(command).strip()


def build_from_proposal(proposal: dict[str, Any] | Any) -> str:
    """Convenience wrapper for ToolCallProposal-shaped dicts."""
    if hasattr(proposal, "model_dump"):
        data = proposal.model_dump()
    else:
        data = dict(proposal)

    tool_name = data["tool_name"]
    params = dict(data.get("params") or {})
    additional_args = str(data.get("additional_args") or "")
    return build_command_for_tool(tool_name, params, additional_args=additional_args)
