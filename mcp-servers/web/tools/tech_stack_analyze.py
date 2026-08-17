"""
Comprehensive technology stack analysis combining multiple fingerprinting methods.

Runs WhatWeb + Wappalyzer + HTTP header analysis + JS bundle analysis + favicon
hashing + robots/sitemap/404 probing + TLS cert metadata to produce a unified
technology stack report with version detection, security concerns, and known
vulnerability research hints.

Detection methods (merged into `unified_stack`, each attributed via `detected_by`):
  1. whatweb     — WhatWeb plugin fingerprinting (aggression param, default 3)
  2. wappalyzer  — Wappalyzer Python library signatures
  3. headers     — HTTP response headers + header-pattern rules (Server/X-Powered-By/
                   Set-Cookie/AspNet/Drupal/CF-Ray/... -> tech)
  4. bundle      — JS bundle analysis: fetch <script src> files, grep framework
                   markers (Zone.js/Angular, React/Next, Vue/Nuxt, jQuery, Webpack,
                   Vite...) + hashed-bundle heuristic for build-tool SPAs
  5. probes      — robots.txt + sitemap.xml + guaranteed-404 body markers +
                   <meta generator> extraction + favicon hash
  6. tls         — TLS version + certificate issuer metadata

Args:
    target: Target URL or domain
    aggression: WhatWeb aggression level (1-4, default 3)
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
import socket
import ssl
import subprocess
import sys
import warnings
import re
import urllib.request
import urllib.parse
import hashlib
from collections import OrderedDict
warnings.filterwarnings("ignore")

target = sys.argv[1] if len(sys.argv) > 1 else ""
aggression = sys.argv[2] if len(sys.argv) > 2 else "3"
verbose = sys.argv[3] == "true" if len(sys.argv) > 3 else False

if not target.startswith(("http://", "https://")):
    target = f"https://{target}"

results = {"target": target, "methods": {}}

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/125.0 Safari/537.36")

# ---- canonicalisation: names that add no signal -> dropped; aliases -> merged ----
NOISE_NAMES = {
    "html5", "script", "title", "strict-transport-security", "x-frame-options",
    "x-xss-protection", "content-security-policy", "ip", "country",
    "uncommonheaders", "allow", "httpserver", "http server", "cookie",
}
ALIASES = {
    "google-analytics": "Google Analytics",
    "google analytics": "Google Analytics",
    "iis": "Microsoft IIS",
    "microsoft-iis": "Microsoft IIS",
}

def http_get(url, timeout=10, headers=None):
    hdrs = {"User-Agent": UA}
    if headers:
        hdrs.update(headers)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers=hdrs)
    return urllib.request.urlopen(req, context=ctx, timeout=timeout)

def norm_name(name):
    low = name.strip().lower()
    if low in NOISE_NAMES:
        return None
    return ALIASES.get(low, name.strip())

def emit():
    # Merge whatever methods have completed so far and print ONE JSON line,
    # flushed immediately. Called after every method (not just at the end) so
    # that if the outer exec_timeout kills this process mid-run, stdout still
    # has the last printed line — parse() below reads the LAST JSON line, so
    # a mid-run kill yields a partial-but-usable result instead of nothing.
    all_techs = OrderedDict()
    for method_name, method_data in results["methods"].items():
        if "error" in method_data:
            continue
        for tech in method_data.get("technologies", []):
            raw = tech.get("name", "")
            name = norm_name(raw)
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
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=90)
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

# Method 3: HTTP Header Analysis + header-pattern rules
# (header value regex -> canonical tech name + category + version group)
HEADER_PATTERNS = [
    ("Server", r"Apache(?:/([\\d.]+))?", "Apache HTTP Server", ["Web Server"]),
    ("Server", r"nginx(?:/([\\d.]+))?", "Nginx", ["Web Server"]),
    ("Server", r"openresty(?:/([\\d.]+))?", "OpenResty", ["Web Server"]),
    ("Server", r"caddy(?:/([\\d.]+))?", "Caddy", ["Web Server"]),
    ("Server", r"lighttpd(?:/([\\d.]+))?", "Lighttpd", ["Web Server"]),
    ("Server", r"tengine", "Tengine", ["Web Server"]),
    ("Server", r"Microsoft-IIS(?:/([\\d.]+))?", "Microsoft IIS", ["Web Server"]),
    ("Server", r"cloudflare", "Cloudflare", ["CDN/WAF"]),
    ("Server", r"akamaighost|akamai", "Akamai", ["CDN"]),
    ("Server", r"gws", "Google Web Server", ["Web Server"]),
    ("Server", r"Varnish", "Varnish", ["Cache"]),
    ("X-Powered-By", r"PHP(?:/([\\d.]+))?", "PHP", ["Programming Language"]),
    ("X-Powered-By", r"ASP\\.NET(?:/([\\d.]+))?", "ASP.NET", ["Web Framework"]),
    ("X-Powered-By", r"Express", "Express", ["Web Framework"]),
    ("X-Powered-By", r"PleskLin", "Plesk", ["Panel"]),
    ("X-AspNet-Version", r"([\\d.]+)", "ASP.NET", ["Web Framework"]),
    ("X-Generator", r"(\\S+)", "Generator", ["Meta"]),
    ("X-Drupal-Cache", r".+", "Drupal", ["CMS"]),
    ("X-Drupal-Dynamic-Cache", r".+", "Drupal", ["CMS"]),
    ("X-Pingback", r".+", "WordPress", ["CMS"]),
    ("Link", r"wp-json", "WordPress", ["CMS"]),
    ("CF-Ray", r".+", "Cloudflare", ["CDN/WAF"]),
    ("CF-Cache-Status", r".+", "Cloudflare", ["CDN/WAF"]),
    ("Via", r".+", "HTTP Proxy", ["Proxy"]),
    ("X-Cache", r".+", "HTTP Cache", ["Cache"]),
    ("X-Served-By", r".+", "Reverse Proxy", ["Proxy"]),
    ("Set-Cookie", r"PHPSESSID", "PHP", ["Programming Language"]),
    ("Set-Cookie", r"ASP\\.NET_SessionId", "ASP.NET", ["Web Framework"]),
    ("Set-Cookie", r"JSESSIONID", "Java Servlet", ["Web Framework"]),
    ("Set-Cookie", r"csrftoken", "Django", ["Web Framework"]),
    ("Set-Cookie", r"sessionid", "Django", ["Web Framework"]),
    ("Set-Cookie", r"laravel_session", "Laravel", ["Web Framework"]),
    ("Set-Cookie", r"wp-settings|wordpress_logged_in", "WordPress", ["CMS"]),
    ("Set-Cookie", r"viewstate", "ASP.NET", ["Web Framework"]),
    ("Set-Cookie", r"XSRF-TOKEN", "Laravel", ["Web Framework"]),
]

try:
    import urllib.request
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(target, headers={"User-Agent": "Mozilla/5.0"})
    resp = urllib.request.urlopen(req, context=ctx, timeout=15)
    headers = dict(resp.headers)
    body_prefix = resp.read(20000).decode("utf-8", "ignore")
    techs = []
    for hname, pat, tech_name, cats in HEADER_PATTERNS:
        val = headers.get(hname, "")
        if not val:
            continue
        m = re.search(pat, val, re.I)
        if m:
            ver = m.group(1) if m.groups() else ""
            techs.append({"name": tech_name, "version": ver, "categories": cats})
    results["methods"]["headers"] = {
        "server": headers.get("Server", ""),
        "x_powered_by": headers.get("X-Powered-By", ""),
        "all_headers": headers,
        "technologies": techs,
    }
except Exception as e:
    results["methods"]["headers"] = {"error": str(e)}
emit()

# Method 4: JS bundle analysis — framework markers in fetched <script> files
BUNDLE_MARKERS = [
    (r"__NEXT_DATA__", "Next.js", ["JavaScript Framework"]),
    (r"__NUXT__", "Nuxt.js", ["JavaScript Framework"]),
    (r"zone\\.js|@angular/core|ngZone|__Zone_disable|ZoneAwarePromise", "Angular", ["JavaScript Framework"]),
    (r"React\\.createElement|react-dom|react\\.js", "React", ["JavaScript Framework"]),
    (r"Vue\\.js|createApp\\s*\\(|vue\\.runtime", "Vue.js", ["JavaScript Framework"]),
    (r"jQuery\\s*\\(|jquery\\.min|jQuery\\.fn", "jQuery", ["JavaScript Library"]),
    (r"webpackBootstrap|__webpack_require__", "Webpack", ["Build Tool"]),
    (r"@vite/client|createViteRuntime", "Vite", ["Build Tool"]),
    (r"\\bsvelte\\b", "Svelte", ["JavaScript Framework"]),
    (r"lodash", "Lodash", ["JavaScript Library"]),
    (r"axios", "Axios", ["JavaScript Library"]),
    (r"bootstrap\\.min|bootstrap\\s*\\(", "Bootstrap", ["CSS Framework"]),
    (r"\\bd3\\s*\\(", "D3.js", ["JavaScript Library"]),
]
HASHED_BUNDLE_RE = r"(?:main|polyfills|runtime|scripts|vendor|chunk)-[A-Za-z0-9_-]+\\.js"

try:
    html = body_prefix if "body_prefix" in dir() else ""
    try:
        resp2 = http_get(target, timeout=12)
        html = resp2.read(300000).decode("utf-8", "ignore")
    except Exception:
        pass
    scripts = re.findall('<script[^>]+src=["\\']([^"\\']+)["\\']', html)
    css = re.findall('<link[^>]+href=["\\']([^"\\']+[.]css[^"\\']*)["\\']', html)
    dedup = []
    seen = set()
    for s in scripts:
        s = urllib.parse.urljoin(target, s)
        if s not in seen:
            seen.add(s)
            dedup.append(s)
    blob = ""
    fetched = []
    for s in dedup[:6]:
        try:
            data = http_get(s, timeout=8).read(1000000)
            blob += data.decode("utf-8", "ignore")
            fetched.append(s)
        except Exception:
            pass
    techs = []
    blob_low = blob[:2000000].lower()
    for pat, tech_name, cats in BUNDLE_MARKERS:
        if re.search(pat, blob, re.I):
            techs.append({"name": tech_name, "version": "", "categories": cats})
    # hashed-bundle heuristic: build-tool SPA even if no framework marker matched
    any_hashed = any(re.search(HASHED_BUNDLE_RE, s, re.I) for s in scripts)
    has_spa_framework = any(t["name"] in ("Angular", "React", "Vue.js", "Next.js", "Nuxt.js", "Svelte") for t in techs)
    if any_hashed and not has_spa_framework:
        techs.append({"name": "Hashed JS Bundles (build-tool SPA)", "version": "", "categories": ["Build Tool"]})
    if blob and not techs and not any_hashed:
        techs.append({"name": "Custom JavaScript", "version": "", "categories": ["JavaScript"]})
    results["methods"]["bundle"] = {
        "technologies": techs,
        "scripts": scripts,
        "css": css,
        "fetched_scripts": fetched,
        "html_bytes": len(html),
        "bundle_bytes": len(blob),
    }
except Exception as e:
    results["methods"]["bundle"] = {"error": str(e)}
emit()

# Method 5: robots.txt / sitemap.xml / 404 body / <meta generator> / favicon hash
try:
    base = urllib.parse.urljoin(target, "/")
    probes = {}
    robots = ""
    try:
        r = http_get(urllib.parse.urljoin(base, "robots.txt"), timeout=8)
        robots = r.read(50000).decode("utf-8", "ignore")
        probes["robots_status"] = r.status
    except Exception:
        pass
    if robots:
        disallowed = re.findall(r"(?im)^Disallow:\\s*(\\S+)", robots)
        probes["robots_disallowed"] = disallowed
    sitemap = ""
    try:
        s = http_get(urllib.parse.urljoin(base, "sitemap.xml"), timeout=8)
        sitemap = s.read(50000).decode("utf-8", "ignore")
        probes["sitemap_status"] = s.status
        probes["sitemap_urls"] = re.findall(r"<loc>([^<]+)</loc>", sitemap)[:20]
    except Exception:
        pass
    body404 = ""
    try:
        r404 = http_get(urllib.parse.urljoin(base, "_pentest_nonexistent_8f3a2c"), timeout=8)
        body404 = r404.read(50000).decode("utf-8", "ignore")
        probes["error_status"] = r404.status
    except Exception:
        try:
            body404 = http_get(urllib.parse.urljoin(base, "nope"), timeout=8).read(20000).decode("utf-8", "ignore")
            probes["error_status"] = 200
        except Exception:
            pass
    gen = re.search('<meta[^>]+name=["\\']?generator["\\']?[^>]+content=["\\']([^"\\']+)', html or "", re.I)
    if gen:
        probes["generator"] = gen.group(1).strip()
    techs = []
    low_robots = robots.lower()
    low_404 = body404.lower()
    low_all = (robots + " " + body404 + " " + (html or "")).lower()
    if "wp-content" in low_all or "wp-includes" in low_robots or "wp-admin" in low_robots:
        techs.append({"name": "WordPress", "version": "", "categories": ["CMS"]})
    if "drupal" in low_404 or "sites/default" in low_robots or "drupal" in low_robots:
        techs.append({"name": "Drupal", "version": "", "categories": ["CMS"]})
    if "joomla" in low_404 or "/administrator" in low_robots:
        techs.append({"name": "Joomla", "version": "", "categories": ["CMS"]})
    if "nginx" in low_404:
        techs.append({"name": "Nginx", "version": "", "categories": ["Web Server"]})
    if "apache" in low_404:
        techs.append({"name": "Apache HTTP Server", "version": "", "categories": ["Web Server"]})
    if "laravel" in low_404:
        techs.append({"name": "Laravel", "version": "", "categories": ["Web Framework"]})
    if "django" in low_404:
        techs.append({"name": "Django", "version": "", "categories": ["Web Framework"]})
    favicon = ""
    try:
        fdata = http_get(urllib.parse.urljoin(base, "favicon.ico"), timeout=8).read(200000)
        favicon = hashlib.md5(fdata).hexdigest()
        probes["favicon_md5"] = favicon
        probes["favicon_size"] = len(fdata)
    except Exception:
        pass
    if gen and gen.group(1):
        gname = gen.group(1).strip()
        m = re.match(r"^([^\\d]+?)\\s*([\\d.]+)$", gname)
        brand = (m.group(1).strip() if m else gname)
        ver = (m.group(2) if m else "")
        techs.append({"name": brand, "version": ver, "categories": ["Meta Generator"]})
    results["methods"]["probes"] = {
        "technologies": techs,
        "probes": probes,
    }
except Exception as e:
    results["methods"]["probes"] = {"error": str(e)}
emit()

# Method 6: TLS version + certificate issuer
try:
    host = urllib.parse.urlparse(target).netloc
    port = 443
    if ":" in host:
        host, port = host.rsplit(":", 1)
        port = int(port)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tls_ver = ""
    issuer_org = ""
    subject_cn = ""
    not_after = ""
    with socket.create_connection((host, port), timeout=6) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ts:
            tls_ver = ts.version() or ""
            cert = ts.getpeercert()
            if cert:
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer_org = issuer.get("organizationName", "")
                subject_cn = subject.get("commonName", "")
                not_after = cert.get("notAfter", "")
    techs = []
    if tls_ver:
        techs.append({"name": f"TLS {tls_ver}", "version": "", "categories": ["TLS"]})
    if subject_cn:
        techs.append({"name": "TLS Certificate", "version": "", "categories": ["TLS"]})
    results["methods"]["tls"] = {
        "technologies": techs,
        "tls_version": tls_ver,
        "cert_issuer_org": issuer_org,
        "cert_subject_cn": subject_cn,
        "cert_not_after": not_after,
    }
except Exception as e:
    results["methods"]["tls"] = {"error": str(e)}
emit()
'''


def build_command(**params: Any) -> str:
    """Build comprehensive analysis command — writes script to temp file."""
    target = params.get("target", "")
    aggression = params.get("aggression", "3")
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
    partial = result.timed_out and len(data.get("methods", {})) < 6

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
        "react": {"category": "JavaScript Framework", "concerns": ["SPA - verify API auth", "Check __NEXT_DATA__ for data leakage"], "follow_ups": ["js_recon"]},
        "angular": {"category": "JavaScript Framework", "concerns": ["Check template injection", "Verify production mode", "SPA - API surface in JS bundles"], "follow_ups": ["js_recon"]},
        "next.js": {"category": "JavaScript Framework", "concerns": ["__NEXT_DATA__ data leakage", "SSR/RSC security"], "follow_ups": ["js_recon"]},
        "nuxt": {"category": "JavaScript Framework", "concerns": ["__NUXT__ state leakage", "SPA API auth"], "follow_ups": ["js_recon"]},
        "vue": {"category": "JavaScript Framework", "concerns": ["SPA - verify API auth", "Client-side template injection"], "follow_ups": ["js_recon"]},
        "laravel": {"category": "Web Framework", "concerns": ["Check APP_DEBUG exposure", "Verify /storage, /_debugbar not exposed"], "follow_ups": ["feroxbuster_scan"]},
        "django": {"category": "Web Framework", "concerns": ["Check DEBUG mode", "Verify /admin exposure", "SECRET_KEY issues"], "follow_ups": ["feroxbuster_scan"]},
        "asp.net": {"category": "Web Framework", "concerns": ["Check for viewstate tampering", "Verify error details disabled"], "follow_ups": []},
        "tomcat": {"category": "Application Server", "concerns": ["Verify /manager not exposed", "Check default creds"], "follow_ups": ["nuclei_scan"]},
        "weblogic": {"category": "Application Server", "concerns": ["CVE-2020-14882 RCE class", "Verify console exposure"], "follow_ups": ["nuclei_scan"]},
        "jenkins": {"category": "CI/CD", "concerns": ["Unauthenticated /script console", "Check old CVEs"], "follow_ups": ["nuclei_scan"]},
        "gitlab": {"category": "CI/CD", "concerns": ["Public project exposure", "Check CVE-2021-22205"], "follow_ups": ["nuclei_scan"]},
        "grafana": {"category": "Monitoring", "concerns": ["Check unauthenticated dashboards", "CVE-2021-43798 path traversal"], "follow_ups": ["nuclei_scan"]},
        "elasticsearch": {"category": "Data Store", "concerns": ["Unauthenticated cluster exposure (9200)"], "follow_ups": []},
        "kibana": {"category": "Monitoring", "concerns": ["Unauthenticated dashboard exposure"], "follow_ups": []},
        "swagger": {"category": "API", "concerns": ["Public API documentation = attack surface", "Verify auth on documented endpoints"], "follow_ups": []},
        "phpmyadmin": {"category": "Panel", "concerns": ["Verify login brute-force resistance", "Check known CVEs"], "follow_ups": ["nuclei_scan"]},
        "cloudflare": {"category": "CDN/WAF", "concerns": ["Check origin IP leakage"], "follow_ups": ["cdn_origin_probe"]},
        "jquery": {"category": "JavaScript Library", "concerns": ["Outdated jQuery XSS (CVE-2020-11022/23)"], "follow_ups": []},
    }

    # Confidence: methods that read raw bytes/pages we fetched directly are
    # stronger than signature-database matches.
    STRONG_METHODS = {"headers", "bundle", "probes", "tls"}
    MEDIUM_METHODS = {"whatweb", "wappalyzer"}

    for tech in unified_stack:
        name = tech.get("name", "")
        version = tech.get("version", "")
        categories = tech.get("categories", [])
        detected_by = tech.get("detected_by", [])

        if any(m in STRONG_METHODS for m in detected_by):
            confidence = "high"
        elif any(m in MEDIUM_METHODS for m in detected_by):
            confidence = "medium"
        else:
            confidence = "low"

        finding = {
            "technology": name,
            "version": version,
            "categories": categories,
            "detected_by": detected_by,
            "confidence": confidence,
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
                assessment["confidence"] = confidence
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
        "methods_used": list(methods.keys()),
        "methods_succeeded": methods_succeeded,
    }

    # Surface extra per-method detail that isn't a technology but is useful
    # recon data (robots disallows, favicon hash, TLS issuer, JS scripts).
    details: dict[str, Any] = {}
    if "probes" in methods and "error" not in methods["probes"]:
        probes = methods["probes"].get("probes", {})
        d = {}
        if probes.get("robots_disallowed"):
            d["robots_disallowed"] = probes["robots_disallowed"]
        if probes.get("generator"):
            d["generator_meta"] = probes["generator"]
        if probes.get("favicon_md5"):
            d["favicon_md5"] = probes["favicon_md5"]
        if probes.get("favicon_size"):
            d["favicon_size"] = probes["favicon_size"]
        if probes.get("sitemap_urls"):
            d["sitemap_urls"] = probes["sitemap_urls"][:10]
        if probes.get("error_status"):
            d["error_page_status"] = probes["error_status"]
        if d:
            details["probes"] = d
    if "bundle" in methods and "error" not in methods["bundle"]:
        b = methods["bundle"]
        d = {}
        if b.get("scripts"):
            d["js_scripts"] = b["scripts"][:15]
        if b.get("css"):
            d["css_files"] = b["css"][:10]
        if b.get("bundle_bytes"):
            d["bundle_bytes_analyzed"] = b["bundle_bytes"]
        if d:
            details["bundle"] = d
    if "tls" in methods and "error" not in methods["tls"]:
        t = methods["tls"]
        d = {}
        if t.get("tls_version"):
            d["tls_version"] = t["tls_version"]
        if t.get("cert_issuer_org"):
            d["cert_issuer_org"] = t["cert_issuer_org"]
        if t.get("cert_subject_cn"):
            d["cert_subject_cn"] = t["cert_subject_cn"]
        if t.get("cert_not_after"):
            d["cert_not_after"] = t["cert_not_after"]
        if d:
            details["tls"] = d
    if "headers" in methods and "error" not in methods["headers"]:
        h = methods["headers"]
        d = {}
        if h.get("server"):
            d["server"] = h["server"]
        if h.get("x_powered_by"):
            d["x_powered_by"] = h["x_powered_by"]
        if d:
            details["headers"] = d
    if details:
        result["recon_details"] = details

    if partial:
        result["partial"] = True
        result["note"] = (
            f"Timed out after {len(methods)}/6 methods completed — "
            "results above are from what finished before the kill, not a full run."
        )
    if method_errors:
        result["method_errors"] = method_errors
    if methods and not methods_succeeded:
        result["error"] = "All detection methods failed (see method_errors) — target likely unreachable from this vantage point."
    return result


def run(
    target: str = "",
    aggression: str = "3",
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
