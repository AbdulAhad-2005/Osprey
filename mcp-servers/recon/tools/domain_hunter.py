"""
Execute sister-domain discovery for affiliated root domains.

Discovers ALL linked/associated domains using 10 signal sources:
  - site_scrape:    Homepage links, robots.txt, sitemap.xml
  - certs:          Certificate transparency (crt.sh)
  - knowledge_recon: Brand-token crt.sh + Wikidata P856 + TLD variants (.pk, .com.pk, etc.)
  - dns:            Seed's NS/MX hosts
  - asn:            Reverse-IP co-location
  - whois:          RDAP registrant org tokens
  - certs:          certspotter + crt.sh CT (token search + brand probe)
  - email_pivot:    Extract emails from site → crt.sh registrant search
  - spf_dmarc:      Parse SPF includes + DMARC rua for related domains
  - reverse_ns:     Find domains sharing the same authoritative NS

Args:
    domain: Seed root domain
    modules: Comma-separated subset of discovery modules (default: all 10)
    confidence_min: Minimum confidence tier to report
    additional_args: Additional CLI arguments

Returns:
    Structured sister-domain discovery results
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
_TOOLS_DIR = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from _core.result import ToolResult
from _core.runner import run_tool

# Same-dir helper module (underscore prefix = skipped by the server harvest
# loop) — the shared implementation, imported for its stdout parser. The CLI
# itself is invoked via a fixed container path like the other _*_cli tools.
from _domain_hunter_cli import hunter_seed_apex, parse_stdout

TOOL_NAME = "domain_hunter"
CATEGORY = "recon"

# Runtime-resolved in the shell (inside the Kali container where the filesystem
# is real): commands are built in the backend but executed via docker exec.
_CLI_CONTAINER = "/home/mcpuser/mcp-servers/recon/tools/_domain_hunter_cli.py"
_CLI_FALLBACK = str(Path(__file__).resolve().with_name("_domain_hunter_cli.py"))

def _cli_expr() -> str:
    return (
        f"$( [ -f {_CLI_CONTAINER} ] && echo {_CLI_CONTAINER} "
        f"|| echo {_CLI_FALLBACK} )"
    )


def build_command(**params: Any) -> str:
    """Build CLI command for local MCP execution."""
    domain = hunter_seed_apex(str(params.get("domain", "")).strip())
    if not domain:
        raise ValueError("domain_hunter requires a registrable seed domain")

    modules = str(params.get("modules", "") or "").strip()
    confidence_min = str(params.get("confidence_min", "low") or "low").strip().lower()
    output = str(params.get("output", "") or "").strip()
    additional_args = str(params.get("additional_args", "") or "").strip()

    if not output:
        safe = domain.replace("/", "_").replace(" ", "_")
        output = f"/tmp/domain_hunter_{safe}.csv"

    parts = [
        "python3",
        _cli_expr(),
        "--domain",
        shlex.quote(domain),
        "--confidence-min",
        shlex.quote(confidence_min),
        "--output",
        shlex.quote(output),
    ]
    if modules:
        parts.extend(["--modules", shlex.quote(modules)])
    if additional_args:
        parts.append(additional_args)

    return " ".join(parts)


def parse(result: ToolResult) -> dict[str, Any]:
    rows = parse_stdout(result.raw_stdout)
    return {"rows": rows, "count": len(rows)}


def run(
    domain: str = "",
    modules: str = "",
    confidence_min: str = "low",
    output: str = "",
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 300,
) -> dict[str, Any]:
    params = {
        "domain": domain,
        "modules": modules,
        "confidence_min": confidence_min,
        "output": output,
        "additional_args": additional_args,
    }
    command = build_command(**params)
    return run_tool(
        TOOL_NAME,
        command,
        params=params,
        timeout=exec_timeout,
        use_cache=use_cache,
        use_recovery=use_recovery,
        parse_fn=parse,
    )
