"""Builders + common params for tool definitions (see package __init__)."""

from __future__ import annotations

from osprey.schemas.tools import (
    CATEGORY_TO_MCP_SERVER,
    ToolCategory,
    ToolDefinition,
    ToolParameter,
    ToolSafetyLevel,
)


def _t(
    name: str,
    category: ToolCategory,
    executable: str,
    safety: ToolSafetyLevel,
    description: str,
    tags: list[str],
    parameters: dict[str, ToolParameter] | None = None,
    install_hint: str | None = None,
    requires_root: bool = False,
    requires_python_module: str | None = None,
) -> ToolDefinition:
    mcp_server = CATEGORY_TO_MCP_SERVER[category]
    return ToolDefinition(
        name=name,
        category=category,
        executable=executable,
        safety_level=safety,
        description=description,
        tags=tags,
        install_hint=install_hint or f"Install {executable}.",
        mcp_server=mcp_server,
        parameters=parameters or {},
        requires_root=requires_root,
        requires_python_module=requires_python_module,
    )


def _p(default: str = "", desc: str = "") -> ToolParameter:
    return ToolParameter(default=default, description=desc)


# Common parameters shared by most tools
_COMMON_PARAMS = {
    "use_recovery": _p("true", "Enable error recovery with retry/alternative."),
    "use_cache": _p("true", "Cache identical results for TTL."),
    "exec_timeout": _p("300", "Execution timeout in seconds."),
}
