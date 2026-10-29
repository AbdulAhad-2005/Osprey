from __future__ import annotations

import shutil
from functools import lru_cache
from typing import Iterable

from osprey.schemas.tools import (
    MCPServerCategory,
    ToolAvailability,
    ToolCatalogResponse,
    ToolCatalogSummary,
    ToolCategory,
    ToolDefinition,
    ToolParameter,
    ToolSafetyLevel,
)

# ---------------------------------------------------------------------------
# Complete tool registry — all 90 tools from mcp-servers
# Each entry maps 1:1 to a tool module in mcp-servers/<category>/tools/
# ---------------------------------------------------------------------------

# Tool-definition data lives in the tool_definitions package (split out for
# readability); logic + public API stay here.
from osprey.services.tool_definitions import (  # noqa: E402
    _t,
    RECON_TOOLS,
    OSINT_TOOLS,
    NETWORK_TOOLS,
    WEB_TOOLS,
    VULN_TOOLS,
    CLOUD_TOOLS,
    CREDS_TOOLS,
    EXPLOIT_TOOLS,
    API_TOOLS,
    BINARY_TOOLS,
    FORENSICS_TOOLS,
)


# ---------------------------------------------------------------------------
# Aggregate all tools
# ---------------------------------------------------------------------------

ALL_TOOL_DEFINITIONS: tuple[ToolDefinition, ...] = tuple(
    RECON_TOOLS
    + OSINT_TOOLS
    + NETWORK_TOOLS
    + WEB_TOOLS
    + VULN_TOOLS
    + CLOUD_TOOLS
    + CREDS_TOOLS
    + EXPLOIT_TOOLS
    + API_TOOLS
    + BINARY_TOOLS
    + FORENSICS_TOOLS
)

# Optional private-overlay tool definitions (for example, a company credential
# manager).
# Absent in public Osprey — a missing module is a no-op, not an error. The
# private module exports ADDITIONAL_TOOL_DEFINITIONS (and optionally
# ADDITIONAL_ALIASES, merged into _TOOL_ALIASES below).
try:  # pragma: no cover - overlay only present in a private superset repo
    from osprey.services import tool_registry_private as _tool_registry_private

    _EXTRA_TOOL_DEFINITIONS = tuple(
        getattr(_tool_registry_private, "ADDITIONAL_TOOL_DEFINITIONS", ()) or ()
    )
    if _EXTRA_TOOL_DEFINITIONS:
        ALL_TOOL_DEFINITIONS = ALL_TOOL_DEFINITIONS + _EXTRA_TOOL_DEFINITIONS
except ImportError:
    _tool_registry_private = None


def _load_custom_tool_definitions() -> tuple[ToolDefinition, ...]:
    """Operator-defined tools from config/custom_tools.yaml (+ its .local.yaml
    overlay) — plans/harness/13-systematic-vuln-dispatch-and-extensibility.md
    Step 2. This registers the CATALOG entry (name/category/params/safety) —
    the same metadata ``_t(...)`` builds for every other tool. The execution
    side is unchanged and not special-cased here: ``command_builder.py``
    still resolves a tool by name to ``mcp-servers/<category>/tools/<name>
    .py`` (``_load_build_command``), so an operator adding a real, runnable
    tool also drops a ``build_command(**params)`` module at that exact path
    — the same shape every built-in tool already has (see canary_confirm.py
    for a minimal example). A YAML entry with no matching file still
    registers (visible in the catalog, documented), it just fails at
    execution time with the same "No build_command for X" error any other
    misconfigured tool would. A bad/malformed YAML entry itself is skipped
    with a logged warning, never crashes catalog startup for everyone else's
    tools.
    """
    import logging

    from osprey.services.config_loader import read_config_layered

    logger = logging.getLogger(__name__)
    data = read_config_layered("custom_tools.yaml")
    entries = data.get("tools") or []
    out: list[ToolDefinition] = []
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("disabled"):
            continue
        try:
            name = str(entry["id"]).strip()
            category = ToolCategory(str(entry.get("category", "web")).strip().lower())
            safety = ToolSafetyLevel(str(entry.get("safety_level", "active")).strip().lower())
            executable = str(entry.get("executable") or "python3").strip()
            description = str(entry.get("description") or "").strip()
            if not name or not description:
                raise ValueError("custom tool entries require 'id' and 'description'")
            params = {
                pname: ToolParameter(
                    default=str(p.get("default", "")), description=str(p.get("description", ""))
                )
                for pname, p in (entry.get("params") or {}).items()
            }
            tags = list(entry.get("tags") or []) + ["custom"]
            out.append(_t(name, category, executable, safety, description, tags, params))
        except (KeyError, ValueError) as exc:
            logger.warning("custom_tools.yaml: skipping malformed entry %r: %s", entry, exc)
    return tuple(out)


_CUSTOM_TOOL_DEFINITIONS = _load_custom_tool_definitions()
if _CUSTOM_TOOL_DEFINITIONS:
    ALL_TOOL_DEFINITIONS = ALL_TOOL_DEFINITIONS + _CUSTOM_TOOL_DEFINITIONS

# Build lookup tables
_TOOL_BY_NAME: dict[str, ToolDefinition] = {t.name: t for t in ALL_TOOL_DEFINITIONS}
_TOOLS_BY_CATEGORY: dict[ToolCategory, list[ToolDefinition]] = {}
for _t_def in ALL_TOOL_DEFINITIONS:
    _TOOLS_BY_CATEGORY.setdefault(_t_def.category, []).append(_t_def)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _matches_category(tool: ToolDefinition, category: ToolCategory | None) -> bool:
    return category is None or tool.category == category


def _kali_which(executable: str) -> str | None:
    """Resolve binary inside the Kali tools container (not the backend image)."""
    import os
    import subprocess

    exe = (executable or "").strip()
    if not exe or any(c in exe for c in (" ", "/", "\\", ";", "|", "&", "`", "$")):
        return None
    container = os.getenv("KALI_CONTAINER", "osprey-kali").strip()
    if not container:
        return None
    try:
        # Do NOT use `bash -lc`: login shells reset PATH and drop /opt/go/bin.
        # Prefer image ENV PATH, then fall back to known install locations.
        probe = (
            "export PATH=\"/home/mcpuser/.local/bin:/opt/go/bin:/usr/local/go/bin:"
            "/usr/local/bin:/home/mcpuser/.cargo/bin:/root/.cargo/bin:"
            "${PATH:-/usr/bin:/bin}\"; "
            f"command -v {exe} 2>/dev/null || true"
        )
        proc = subprocess.run(
            ["docker", "exec", container, "sh", "-c", probe],
            capture_output=True,
            text=True,
            timeout=8,
        )
        path = (proc.stdout or "").strip().splitlines()
        return path[0].strip() if path and path[0].strip() else None
    except Exception:
        return None


@lru_cache(maxsize=256)
def _kali_which_cached(executable: str) -> str | None:
    return _kali_which(executable)


def _kali_python_importable(module: str) -> bool | None:
    """Check whether a Python module imports inside the Kali tools container.

    Returns None (not True/False) when Docker isn't reachable at all, so the
    caller can fall through to a host-side check instead of wrongly reporting
    "not installed" for native mode.
    """
    import os
    import subprocess

    mod = (module or "").strip()
    if not mod or not all(part.isidentifier() for part in mod.split(".")):
        return None
    container = os.getenv("KALI_CONTAINER", "osprey-kali").strip()
    if not container:
        return None
    try:
        proc = subprocess.run(
            ["docker", "exec", container, "python3", "-c", f"import {mod}"],
            capture_output=True,
            text=True,
            timeout=8,
        )
        return proc.returncode == 0
    except Exception:
        return None


def _host_python_importable(module: str) -> bool:
    """Check whether a Python module imports on the backend's own host (native mode)."""
    import importlib.util

    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


@lru_cache(maxsize=256)
def _python_module_importable_cached(module: str) -> bool:
    kali_result = _kali_python_importable(module)
    if kali_result is not None:
        return kali_result
    return _host_python_importable(module)


def reload_tool_availability() -> None:
    """Clear the process-lifetime tool-availability cache.

    Unlike every other cached config in this codebase (parallelism, ingest
    rules, escalation matrix, phase-pipeline thresholds — each has a
    `reload_*()`/`cache_clear()` this file's own `@lru_cache` had none), a
    tool's installed/missing status was cached forever once first checked,
    with no way to refresh it short of restarting the whole backend process —
    so starting the Kali container *after* the backend had already cached a
    tool as missing left it reporting "not installed" indefinitely, even
    though the container now has it. Wired into `POST /config/reload` so the
    existing "make the backend look again" action actually covers this too.
    """
    _kali_which_cached.cache_clear()
    _projectdiscovery_httpx_cached.cache_clear()
    _python_module_importable_cached.cache_clear()


def _kali_projectdiscovery_httpx() -> str | None:
    import os
    import subprocess

    container = os.getenv("KALI_CONTAINER", "osprey-kali").strip()
    if not container:
        return None
    probe = """
export PATH="/home/mcpuser/.local/bin:/opt/go/bin:/usr/local/go/bin:/usr/local/bin:${PATH:-/usr/bin:/bin}"
for candidate in httpx-toolkit httpx-pd httpx; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -h 2>&1 | grep -q -- '-tech-detect'; then
    command -v "$candidate"
    exit 0
  fi
done
"""
    try:
        proc = subprocess.run(
            ["docker", "exec", container, "sh", "-c", probe],
            capture_output=True,
            text=True,
            timeout=8,
        )
    except Exception:
        return None
    path = (proc.stdout or "").strip().splitlines()
    return path[0].strip() if path and path[0].strip() else None


def _host_projectdiscovery_httpx() -> str | None:
    import subprocess

    for candidate in ("httpx-toolkit", "httpx-pd", "httpx"):
        path = shutil.which(candidate)
        if not path:
            continue
        try:
            proc = subprocess.run(
                [path, "-h"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except Exception:
            continue
        if "-tech-detect" in f"{proc.stdout}\n{proc.stderr}":
            return path
    return None


@lru_cache(maxsize=1)
def _projectdiscovery_httpx_cached() -> str | None:
    return _kali_projectdiscovery_httpx() or _host_projectdiscovery_httpx()


def _with_availability(tool: ToolDefinition) -> ToolAvailability:
    # Tools run in Kali — never trust backend-local shutil.which alone.
    if tool.name == "httpx_probe":
        executable_path = _projectdiscovery_httpx_cached()
    else:
        executable_path = _kali_which_cached(tool.executable)
        if executable_path is None:
            executable_path = shutil.which(tool.executable)
    installed = executable_path is not None
    # executable='python3' is present on essentially every image — that alone
    # doesn't mean a python3-wrapped tool's REAL dependency (playwright,
    # Wappalyzer, pwn, angr, ...) is there. Only trust the executable check
    # alone when the tool doesn't declare one of these.
    if installed and tool.requires_python_module:
        installed = _python_module_importable_cached(tool.requires_python_module)
    return ToolAvailability(
        **tool.model_dump(),
        installed=installed,
        executable_path=executable_path,
    )


def _build_summary(tools: Iterable[ToolAvailability]) -> ToolCatalogSummary:
    materialized = list(tools)
    by_category = {category: 0 for category in ToolCategory}
    for tool in materialized:
        by_category[tool.category] += 1
    installed = sum(1 for tool in materialized if tool.installed)
    return ToolCatalogSummary(
        total=len(materialized),
        installed=installed,
        missing=len(materialized) - installed,
        by_category=by_category,
    )


@lru_cache(maxsize=1)
def list_registered_tools() -> tuple[ToolDefinition, ...]:
    return ALL_TOOL_DEFINITIONS


def list_tools(category: ToolCategory | None = None) -> list[ToolAvailability]:
    return [
        _with_availability(tool)
        for tool in list_registered_tools()
        if _matches_category(tool, category)
    ]


def get_tool(name: str) -> ToolAvailability | None:
    tool_def = get_tool_definition(name)
    if tool_def is None:
        return None
    return _with_availability(tool_def)


# Common LLM / docs short names → registered tool ids
_TOOL_ALIASES: dict[str, str] = {
    "subfinder": "subfinder_scan",
    "amass": "amass_scan",
    "amass_enum": "amass_scan",
    "dnsenum": "dnsenum_scan",
    "dns_enum": "dnsenum_scan",
    "dns-enum": "dnsenum_scan",
    "fierce": "fierce_scan",
    "httpx": "httpx_probe",
    "httpx_scan": "httpx_probe",
    "nmap": "nmap_syn_scan",
    "nmap_scan": "nmap_syn_scan",
    "nmap_syn": "nmap_syn_scan",
    "nmap_service": "nmap_service_scan",
    "masscan": "masscan_high_speed",
    "rustscan": "rustscan_fast_scan",
    "naabu": "naabu_port_scan",
    "naabu_scan": "naabu_port_scan",
    "whois": "whois_lookup",
    "whois_lookup": "whois_lookup",
    "dnsx": "dnsx_resolve",
    "dnsx_ptr": "dnsx_reverse",
    "reverse_dns": "dnsx_reverse",
    "reverse_dns_lookup": "dnsx_reverse",
    "ptr_lookup": "dnsx_reverse",
    "asn": "asn_enum",
    "asn_lookup": "asn_enum",
    "asn_enumeration": "asn_enum",
    "netblock": "asn_enum",
    "cymru": "asn_enum",
    "tlsx": "tlsx_inspect",
    "crtsh": "crt_sh_query",
    "crt_sh": "crt_sh_query",
    "cdn_origin": "cdn_origin_probe",
    "origin_ip": "cdn_origin_probe",
    # cdn_origin_ip removed as a duplicate — keep the old name resolvable so any
    # historical call degrades gracefully to the lightweight probe.
    "cloudflare_origin_ip": "cdn_origin_probe",
    "cdn_origin_ip": "cdn_origin_probe",
    # autorecon_comprehensive removed as a duplicate — build_command/parse/run
    # were byte-for-byte identical to autorecon_scan (confirmed via diff).
    "autorecon_comprehensive": "autorecon_scan",
    "shodan": "shodan_search",
    "shodan_lookup": "shodan_search",
    "shodan_host": "shodan_host_info",
    "takeover": "subdomain_takeover_check",
    "subdomain_takeover": "subdomain_takeover_check",
    "gau": "gau_discovery",
    "wayback": "waybackurls_discovery",
    "waybackurls": "waybackurls_discovery",
    "dnsrecon": "dnsenum_scan",
    "nslookup": "dnsenum_scan",
    # ── OSINT short names ──
    "theharvester": "theharvester",
    "harvester": "theharvester",
    "the_harvester": "theharvester",
    "sherlock_scan": "sherlock",
    "username_search": "sherlock",
    "maigret_scan": "maigret",
    "holehe_scan": "holehe",
    "email_check": "holehe",
    "phoneinfoga_scan": "phoneinfoga",
    "phone_osint": "phoneinfoga",
    "dnstwist_scan": "dnstwist",
    "typosquat": "dnstwist",
    "metagoofil_scan": "metagoofil",
    "document_harvest": "metagoofil",
    "social_analyzer_scan": "social_analyzer",
    "social-analyzer": "social_analyzer",
    "web_harvest": "web_contact_harvest",
    "contact_harvest": "web_contact_harvest",
    "email_permutation": "email_permute",
    "email_permutator": "email_permute",
    # ── Credential-harvesting short names ──
    "intelx": "intelx_scan",
    "intelligencex": "intelx_scan",
    "intelx_search": "intelx_scan",
    "resecurity": "resecurity_scan",
    "resecurity_lookup": "resecurity_scan",
}

# Merge optional private-overlay aliases. No-op in public Osprey.
if "_tool_registry_private" in dir() and _tool_registry_private is not None:
    _TOOL_ALIASES.update(getattr(_tool_registry_private, "ADDITIONAL_ALIASES", {}) or {})


def resolve_tool_name(name: str) -> str:
    """Normalize aliases to registered tool names."""
    key = (name or "").strip().lower()
    if not key:
        return key
    if key in _TOOL_BY_NAME:
        return key
    aliased = _TOOL_ALIASES.get(key)
    if aliased and aliased in _TOOL_BY_NAME:
        return aliased
    # trailing _scan already tried; try appending _scan / _probe / _discovery
    for suffix in ("_scan", "_probe", "_discovery", "_lookup"):
        cand = key if key.endswith(suffix) else key + suffix
        if cand in _TOOL_BY_NAME:
            return cand
    return key


def suggest_tool_names(name: str, *, limit: int = 8) -> list[str]:
    """Closest registered names for 404 hints."""
    import difflib

    key = (name or "").strip().lower()
    pool = sorted(_TOOL_BY_NAME.keys())
    return difflib.get_close_matches(key, pool, n=limit, cutoff=0.4)


def get_tool_definition(name: str) -> ToolDefinition | None:
    resolved = resolve_tool_name(name)
    return _TOOL_BY_NAME.get(resolved)


def get_tools_by_mcp_server(server: MCPServerCategory) -> list[ToolDefinition]:
    return [t for t in ALL_TOOL_DEFINITIONS if t.mcp_server == server]


def get_tool_catalog(category: ToolCategory | None = None) -> ToolCatalogResponse:
    tools = list_tools(category=category)
    return ToolCatalogResponse(tools=tools, summary=_build_summary(tools))
