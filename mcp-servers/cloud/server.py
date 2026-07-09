"""
FastMCP server — `cloud` capability domain (HexStrike CLI tools).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

_CATEGORY_DIR = Path(__file__).resolve().parent
_MCP_ROOT = _CATEGORY_DIR.parent
if str(_MCP_ROOT) not in sys.path:
    sys.path.insert(0, str(_MCP_ROOT))

mcp = FastMCP("cloud-mcp")


def _register_harvested_tools() -> None:
    tools_dir = _CATEGORY_DIR / "tools"
    for path in sorted(tools_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(path.stem, path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        run_fn = getattr(module, "run", None)
        if run_fn is None:
            continue
        tool_name = getattr(module, "TOOL_NAME", path.stem)
        registered = mcp.tool(name=tool_name)(run_fn)
        if module.__doc__:
            registered.__doc__ = module.__doc__


_register_harvested_tools()


if __name__ == "__main__":
    mcp.run()
