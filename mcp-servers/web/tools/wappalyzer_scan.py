"""
Execute Wappalyzer technology detection via Python library.

Uses the python-Wappalyzer library to identify web technologies including
CMS, frameworks, JavaScript libraries, web servers, analytics, CDNs,
and more. Provides categorized technology stack information.

Args:
    target: Target URL or domain
    additional_args: Reserved for future use

Returns:
    Categorized technology stack from Wappalyzer fingerprinting

Harvested: HexStrike `wappalyzer_scan` -> `/api/tools/wappalyzer`.
Category: web
"""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import run_tool
from _core.result import ToolResult

TOOL_NAME = "wappalyzer_scan"
CATEGORY = "web"


def build_command(**params: Any) -> str:
    """Build Wappalyzer command — writes inline Python script."""
    target = params.get("target", "")

    target_str = str(target).strip()
    if target_str and not target_str.startswith(("http://", "https://")):
        target_str = f"https://{target_str}"

    # Use python3 -c with a compact single-line script. target_str is embedded
    # via json.dumps (not an f-string quote) — JSON string syntax is a valid
    # Python string literal, so a target containing a stray quote can't break
    # out of the literal and inject arbitrary Python.
    script = (
        "import json,sys,warnings;warnings.filterwarnings('ignore');"
        "from Wappalyzer import Wappalyzer,WebPage;"
        f"t={json.dumps(target_str)};"
        "w=Wappalyzer.latest();"
        "p=WebPage.new_from_url(t,verify=False);"
        "r=w.analyze_with_versions_and_categories(p);"
        "s=sorted(list(w.analyze(p)));"
        "c={};"
        "[c.setdefault(cat,[]).append({'name':tech,'version':r[tech].get('versions',[]),'confidence':r[tech].get('confidence',[])}) for tech,info in r.items() for cat in info.get('categories',[])];"
        "print(json.dumps({'target':t,'technologies':r,'simple_technologies':s,'categories':c}))"
    )
    # shlex.quote (single-quoted), not json.dumps (double-quoted): the actual
    # execution path runs this whole string through a real shell (sh -c), and
    # double quotes still let $(...) / backticks in the script text expand.
    return f"python3 -c {shlex.quote(script)}"


def parse(result: ToolResult) -> dict[str, Any]:
    """Parse Wappalyzer JSON output into structured findings."""
    stdout = result.raw_stdout or ""

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return {
            "findings": [],
            "raw_output": stdout,
            "error": "Failed to parse Wappalyzer output",
        }

    if "error" in data and not data.get("technologies"):
        return {
            "findings": [],
            "raw_output": stdout,
            "error": data["error"],
        }

    findings = []
    categories = data.get("categories", {})
    technologies = data.get("technologies", {})

    for tech_name, tech_info in technologies.items():
        versions = tech_info.get("versions", [])
        version = versions[0] if versions else ""
        cats = tech_info.get("categories", [])
        confidence = tech_info.get("confidence", [])
        conf = confidence[0] if confidence else ""

        findings.append({
            "technology": tech_name,
            "version": str(version),
            "categories": cats,
            "confidence": conf,
            "target": data.get("target", ""),
        })

    return {
        "findings": findings,
        "categories": categories,
        "technologies_detected": data.get("simple_technologies", []),
        "target": data.get("target", ""),
        "total_technologies": len(findings),
    }


def run(
    target: str = "",
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 300,
) -> dict[str, Any]:
    params = {"target": target, "additional_args": additional_args}
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
