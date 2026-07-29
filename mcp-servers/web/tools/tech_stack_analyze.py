"""
Comprehensive technology stack analysis combining multiple fingerprinting methods.

Runs WhatWeb + Wappalyzer + HTTP header analysis + security checks to produce
a unified technology stack report with version detection, security concerns,
and known vulnerability research hints.

Args:
    target: Target URL or domain
    aggression: WhatWeb aggression level (1-4, default 1)
    verbose: Enable verbose WhatWeb output
    additional_args: Reserved for future use

Returns:
    Unified technology stack with categories, versions, security concerns,
    and follow-up recommendations

Harvested: HexStrike `tech_stack_analyze` -> `/api/tools/tech-stack`.
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

TOOL_NAME = "tech_stack_analyze"
CATEGORY = "web"

ANALYSIS_SCRIPT = '''#!/usr/bin/env python3
import json
import shlex
import subprocess
import sys
import warnings
warnings.filterwarnings("ignore")

target = sys.argv[1] if len(sys.argv) > 1 else ""
aggression = sys.argv[2] if len(sys.argv) > 2 else "1"
verbose = sys.argv[3] == "true" if len(sys.argv) > 3 else False

if not target.startswith(("http://", "https://")):
    target = f"https://{target}"

results = {"target": target, "methods": {}}

def emit():
    # Merge whatever methods have completed so far and print ONE JSON line,
    # flushed immediately. Called after every method (not just at the end) so
    # that if the outer exec_timeout kills this process mid-run, stdout still
    # has the last printed line — parse() below reads the LAST JSON line, so
    # a mid-run kill yields a partial-but-usable result instead of nothing.
    all_techs = {}
    for method_name, method_data in results["methods"].items():
        if "error" in method_data:
            continue
        for tech in method_data.get("technologies", []):
            name = tech.get("name", "")
            if not name:
                continue
            key = name.lower()
            if key not in all_techs:
                all_techs[key] = {
                    "name": name,
                    "version": tech.get("version", ""),
                    "categories": tech.get("categories", []),
                    "detected_by": [],
                }
            if method_name not in all_techs[key]["detected_by"]:
                all_techs[key]["detected_by"].append(method_name)
            if tech.get("version") and not all_techs[key]["version"]:
                all_techs[key]["version"] = tech.get("version")
    out = dict(results)
    out["unified_stack"] = list(all_techs.values())
    out["total_technologies"] = len(all_techs)
    print(json.dumps(out))
    sys.stdout.flush()

# Method 1: WhatWeb
try:
    verbose_flag = "-v " if verbose else ""
    cmd = f"whatweb --log-json=- {verbose_flag}-a {aggression} --user-agent=PentestPlatform/1.0 {shlex.quote(target)}"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
    if not proc.stdout.strip() and ("ERROR Opening" in proc.stderr or "execution expired" in proc.stderr):
        results["methods"]["whatweb"] = {"error": proc.stderr.strip().splitlines()[-1][:300]}
    elif proc.stdout.strip():
        # WhatWeb may output multiple JSON objects (one per redirect hop)
        lines = proc.stdout.strip().split("\\n")
        whatweb_techs = []
        all_plugins = []
        for line in lines:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                whatweb_data = json.loads(line)
            except json.JSONDecodeError:
                continue
            plugins = whatweb_data.get("plugins", {})
            all_plugins.extend(list(plugins.keys()))
            for name, data in plugins.items():
                if name in ("IP", "Country", "UncommonHeaders", "Allow"):
                    continue
                versions = data.get("version", [])
                ver = versions[0] if versions else ""
                whatweb_techs.append({"name": name, "version": ver})
        results["methods"]["whatweb"] = {"technologies": whatweb_techs, "raw_plugins": all_plugins}
except Exception as e:
    results["methods"]["whatweb"] = {"error": str(e)}
emit()

# Method 2: Wappalyzer
try:
    from Wappalyzer import Wappalyzer, WebPage
    wappalyzer = Wappalyzer.latest()
    webpage = WebPage.new_from_url(target, verify=False)
    wapp_result = wappalyzer.analyze_with_versions_and_categories(webpage)
    wapp_techs = []
    wapp_categories = {}
    for tech, info in wapp_result.items():
        versions = info.get("versions", [])
        ver = versions[0] if versions else ""
        cats = info.get("categories", [])
        wapp_techs.append({"name": tech, "version": ver, "categories": cats})
        for cat in cats:
            if cat not in wapp_categories:
                wapp_categories[cat] = []
            wapp_categories[cat].append(tech)
    results["methods"]["wappalyzer"] = {"technologies": wapp_techs, "categories": wapp_categories}
except Exception as e:
    results["methods"]["wappalyzer"] = {"error": str(e)}
emit()

# Method 3: HTTP Header Analysis
try:
    import urllib.request
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(target, headers={"User-Agent": "Mozilla/5.0"})
    resp = urllib.request.urlopen(req, context=ctx, timeout=15)
    headers = dict(resp.headers)
    results["methods"]["headers"] = {
        "server": headers.get("Server", ""),
        "x_powered_by": headers.get("X-Powered-By", ""),
        "all_headers": {k: v for k, v in headers.items()}
    }
except Exception as e:
    results["methods"]["headers"] = {"error": str(e)}
emit()
'''


def build_command(**params: Any) -> str:
    """Build comprehensive analysis command — writes script to temp file."""
    target = params.get("target", "")
    aggression = params.get("aggression", "1")
    verbose = params.get("verbose", False)

    target_str = str(target).strip()
    if target_str and not target_str.startswith(("http://", "https://")):
        target_str = f"https://{target_str}"

    verbose_str = "true" if verbose else "false"

    # Write script to temp file and execute. target_str/aggression are
    # user-controlled and land on the "python3 ..." line of a real shell
    # command (this whole string runs via `sh -c`) — shlex.quote so a
    # target containing shell metacharacters can't break out.
    script_path = "/tmp/_tech_stack_analyze.py"
    return (
        f"cat > {script_path} << 'PYEOF'\n{ANALYSIS_SCRIPT}\nPYEOF\n"
        f"python3 {script_path} {shlex.quote(target_str)} {shlex.quote(str(aggression))} {verbose_str}"
    )


def parse(result: ToolResult) -> dict[str, Any]:
    """Parse comprehensive analysis output.

    The script prints one JSON line after EACH method (see emit() in
    ANALYSIS_SCRIPT) so a mid-run timeout still leaves usable output — take
    the LAST valid JSON line, which is always the most complete snapshot
    (full merge if all methods finished, partial merge if killed early).
    """
    stdout = result.raw_stdout or ""

    data: dict[str, Any] | None = None
    partial = True
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and "methods" in parsed:
            data = parsed
    if data is None:
        return {
            "findings": [],
            "raw_output": stdout,
            "error": "Failed to parse analysis output"
            + (" — process likely timed out before any method completed" if result.timed_out else ""),
        }
    partial = result.timed_out and len(data.get("methods", {})) < 3

    unified_stack = data.get("unified_stack", [])
    findings = []
    security_assessment = []
    all_concerns = []
    all_follow_ups = set()

    # Security concern database
    SECURITY_CONCERNS = {
        "wordpress": {"category": "CMS", "concerns": ["Check for outdated plugins/themes", "Test /wp-json/wp/v2/users"], "follow_ups": ["wpscan_analyze"]},
        "joomla": {"category": "CMS", "concerns": ["Check for known Joomla CVEs", "Verify admin panel access"], "follow_ups": []},
        "drupal": {"category": "CMS", "concerns": ["Check Drupalgeddon CVE-2018-7600", "Verify /CHANGELOG.txt not exposed"], "follow_ups": []},
        "apache": {"category": "Web Server", "concerns": ["Check directory listing", "Verify server version disclosure"], "follow_ups": ["nikto_scan"]},
        "nginx": {"category": "Web Server", "concerns": ["Check alias traversal", "Verify server version"], "follow_ups": ["nikto_scan"]},
        "iis": {"category": "Web Server", "concerns": ["Check old IIS versions", "Verify WebDAV restrictions"], "follow_ups": ["nikto_scan"]},
        "php": {"category": "Programming Language", "concerns": ["Check PHP version CVEs", "Verify error reporting disabled"], "follow_ups": []},
        "react": {"category": "JavaScript Framework", "concerns": ["SPA - verify API auth", "Check __NEXT_DATA__"], "follow_ups": []},
        "angular": {"category": "JavaScript Framework", "concerns": ["Check template injection", "Verify production mode"], "follow_ups": []},
        "cloudflare": {"category": "CDN/WAF", "concerns": ["Check origin IP leakage"], "follow_ups": ["cdn_origin_probe"]},
    }

    for tech in unified_stack:
        name = tech.get("name", "")
        version = tech.get("version", "")
        categories = tech.get("categories", [])
        detected_by = tech.get("detected_by", [])

        finding = {
            "technology": name,
            "version": version,
            "categories": categories,
            "detected_by": detected_by,
            "target": data.get("target", ""),
        }
        findings.append(finding)

        # Security assessment
        name_lower = name.lower()
        for pattern, info in SECURITY_CONCERNS.items():
            if pattern in name_lower:
                assessment = dict(info)
                if version:
                    assessment["version_note"] = f"Version {version} - research CVEs"
                assessment["technology"] = name
                assessment["version"] = version
                security_assessment.append(assessment)
                all_concerns.extend(info.get("concerns", []))
                for fu in info.get("follow_ups", []):
                    all_follow_ups.add(fu)
                break

    categories_summary = {}
    for tech in unified_stack:
        for cat in tech.get("categories", []):
            if cat not in categories_summary:
                categories_summary[cat] = []
            categories_summary[cat].append(tech.get("name", ""))

    methods = data.get("methods", {})
    method_errors = {name: info["error"] for name, info in methods.items() if "error" in info}
    methods_succeeded = [name for name in methods if "error" not in methods[name]]

    result: dict[str, Any] = {
        "findings": findings,
        "security_assessment": security_assessment,
        "categories_summary": categories_summary,
        "all_concerns": list(set(all_concerns)),
        "recommended_follow_ups": sorted(all_follow_ups),
        "targets_scanned": [data.get("target", "")],
        "total_technologies": data.get("total_technologies", 0),
        # methods_used previously listed every *attempted* method regardless
        # of outcome, which looked identical whether it found nothing or
        # couldn't connect at all. methods_succeeded/method_errors disambiguate.
        "methods_used": list(methods.keys()),
        "methods_succeeded": methods_succeeded,
    }
    if partial:
        result["partial"] = True
        result["note"] = (
            f"Timed out after {len(methods)}/3 methods completed — "
            "results above are from what finished before the kill, not a full run."
        )
    if method_errors:
        result["method_errors"] = method_errors
    if methods and not methods_succeeded:
        result["error"] = "All detection methods failed (see method_errors) — target likely unreachable from this vantage point."
    return result


def run(
    target: str = "",
    aggression: str = "1",
    verbose: bool = False,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 300,
) -> dict[str, Any]:
    params = {
        "target": target,
        "aggression": aggression,
        "verbose": verbose,
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
