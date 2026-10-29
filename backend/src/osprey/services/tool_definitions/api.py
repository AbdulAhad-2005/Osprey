"""API_TOOLS — tool catalog definitions."""

from __future__ import annotations

from osprey.schemas.tools import ToolDefinition  # noqa: F401 — used in the annotation below


# ---- API (3 tools) --------------------------------------------------------

# API_TOOLS: removed 2026-08-04. The three legacy stubs
# (api_fuzzer, graphql_scanner, api_schema_analyzer) were crude curl loops,
# unused (never typed/cataloged), and superseded:
#   - graphql_scanner  → graphql_cop_scan (real GraphQL audit tool)
#   - api_fuzzer       → ffuf_scan (proper fuzzer)
#   - api_schema_analyzer → runtime API discovery via browser_scrape (captures
#     live XHR/fetch endpoints), js_recon, and gau/waybackurls; an OpenAPI file,
#     if present, is trivially fetched/parsed via platform_script.
API_TOOLS: list[ToolDefinition] = []
