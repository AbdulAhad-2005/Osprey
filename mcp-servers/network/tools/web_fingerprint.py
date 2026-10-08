"""Retrieve an HTTP(S) page and fingerprint common network/security appliances.

Returns vendor/product matches with confidence and the matched evidence. This is
passive fingerprinting: it performs a GET request only and does not authenticate
or submit forms.
"""
from __future__ import annotations

import json
import re
import shlex
import ssl
import sys
import urllib.error
import urllib.request
from html import unescape
from pathlib import Path
from typing import Any


_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.result import ToolResult
from _core.runner import default_parse, run_tool

TOOL_NAME = "web_fingerprint"
CATEGORY = "network"

# Signals are intentionally conservative. Strong product-specific paths/assets get
# more weight than generic words such as "login" or "firewall".
SIGNATURES: dict[str, dict[str, Any]] = {
    "Fortinet": {
        "product": "FortiGate",
        "patterns": [
            ("fortigate", 5), ("fortinet", 4), ("fgtauth", 5),
            ("/remote/login", 2), ("/logincheck", 2), ("forticlient", 2),
        ],
    },
    "Palo Alto": {
        "product": "PAN-OS / GlobalProtect",
        "patterns": [
            ("globalprotect", 5), ("pan-os", 5), ("palo alto networks", 5),
            ("/global-protect/", 4), ("/ssl-vpn/", 2), ("prelogin.esp", 5),
        ],
    },
    "SonicWall": {
        "product": "SonicOS",
        "patterns": [
            ("sonicwall", 5), ("sonicos", 5), ("sonicwall netextender", 5),
            ("/cgi-bin/welcome", 3), ("/cgi-bin/sslvpnclient", 4),
        ],
    },
    "Cisco ASA": {
        "product": "Cisco ASA / AnyConnect",
        "patterns": [
            ("cisco adaptive security appliance", 6), ("adaptive security appliance", 5),
            ("anyconnect", 4), ("webvpn", 3), ("cisco asa", 5),
            ("/+csco+", 5), ("/csco/", 3),
            ("/+cscoe+", 6), ("cscoe", 5), ("/+cscot+", 5),
            ("cisco anyconnect", 5),
        ],
    },
    "Ivanti/Pulse": {
        "product": "Ivanti Connect Secure / Pulse Secure",
        "patterns": [
            ("ivanti connect secure", 6), ("ivanti", 4), ("pulse secure", 6),
            ("pulse connect secure", 5), ("/dana-na/", 5), ("/dana/home", 5),
        ],
    },
    "Citrix Gateway": {
        "product": "Citrix Gateway",
        "patterns": [
            ("citrix gateway", 6), ("citrix netscaler gateway", 6),
            ("netscaler gateway", 5), ("citrix adc", 4),
            ("/vpn/index.html", 4), ("/vpn/tmindex.html", 5),
        ],
    },
    "FortiVPN": {
        "product": "FortiGate SSL-VPN",
        "patterns": [
            ("forticlient", 4), ("fortigate ssl vpn", 6), ("ssl-vpn", 2),
            ("/remote/login", 3), ("/remote/fgt_lang", 4),
        ],
    },
    "Cisco IOS": {
        "product": "Cisco IOS HTTP/HTTPS management",
        "patterns": [
            ("cisco ios", 6), ("cisco systems", 4), ("cisco web setup", 5),
            ("cisco configuration professional", 4), ("cisco ios software", 5),
        ],
    },
    "MikroTik": {
        "product": "RouterOS / MikroTik",
        "patterns": [
            ("mikrotik", 6), ("routeros", 6), ("routerboard", 5),
            ("webfig", 5), ("/webfig/", 5), ("mikrotik routeros", 7),
        ],
    },
    "Juniper": {
        "product": "Juniper Junos / SRX",
        "patterns": [
            ("juniper networks", 6), ("junos", 5), ("juniper", 4),
            ("juniper srx", 6), ("jnpr", 3),
        ],
    },
    "F5 BIG-IP": {
        "product": "F5 BIG-IP",
        "patterns": [
            ("f5 big-ip", 7), ("big-ip", 6), ("f5 networks", 5),
            ("tmui", 5), ("/tmui/", 6), ("bigipserver", 4),
        ],
    },
    "Citrix ADC": {
        "product": "Citrix ADC / NetScaler",
        "patterns": [
            ("citrix adc", 6), ("netscaler", 6), ("citrix netscaler", 6),
            ("ns.conf", 3), ("nscache", 3),
        ],
    },
    "Cyberoam": {
        "product": "Cyberoam appliance",
        "patterns": [
            ("cyberoam", 7), ("cyberoam web admin", 7), ("cyberoam corporate", 5),
            ("cyberoam ssl vpn", 6), ("cyberoam login", 5),
        ],
    },
    "Cisco Firepower": {
        "product": "Cisco Secure Firewall / Firepower Device Manager",
        "patterns": [
            ("firepower device manager", 8), ("firepower management center", 7),
            ("cisco secure firewall", 7), ("firepower", 6),
            ("secure firewall device manager", 7), ("fxos", 4),
        ],
    },
    "DD-WRT": {
        "product": "DD-WRT router firmware",
        "patterns": [
            ("dd-wrt", 8), ("ddwrt", 6), ("dd-wrt (build", 7),
            ("router settings", 2),
        ],
    },
    "Cisco TelePresence": {
        "product": "Cisco TelePresence MCU / Conferencing",
        "patterns": [
            ("cisco telepresence mcu", 8), ("telepresence mcu", 8),
            ("telepresence", 6), ("cisco telepresence", 7),
            ("mse 8000", 5),
        ],
    },
    "Cisco SD-WAN": {
        "product": "Cisco SD-WAN (vManage/Viptela)",
        "patterns": [
            ("cisco sd-wan", 8), ("vmanage", 8), ("viptela", 7),
            ("sd-wan", 4), ("/vmanage/", 6), ("cisco catalyst sd-wan", 8),
        ],
    },
    "Juniper Web Device Manager": {
        "product": "Juniper Web Device Manager",
        "patterns": [
            ("juniper web device manager", 9), ("junos web device manager", 8),
            ("web device manager", 4),
        ],
    },
    "HPE": {
        "product": "HPE (Hewlett Packard Enterprise) web management",
        "patterns": [
            ("hewlett packard enterprise", 7), ("hewlett packard company", 6),
            ("hpe imc", 6), ("grommet.css", 3), ("procurve", 4),
        ],
    },
    "Tandberg": {
        "product": "Tandberg / Cisco video endpoint",
        "patterns": [
            ("tandberg", 7), ("tandberg_user", 6), ("tandberg codecs", 6),
            ("cisco codecs", 4), ("cisco endpoint", 3),
        ],
    },
}


def _strip_html(html: str) -> str:
    html = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", html)
    html = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", html)
    html = re.sub(r"(?is)<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", unescape(html)).strip()


def fingerprint(url: str, timeout: int = 10, verify_tls: bool = True, max_bytes: int = 1_000_000) -> dict[str, Any]:
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url

    context = None if verify_tls else ssl._create_unverified_context()
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Osprey-WebFingerprinter/1.0", "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
            raw = response.read(max_bytes)
            headers = {k.lower(): v for k, v in response.headers.items()}
            final_url = response.geturl()
            status = response.status
            content_type = headers.get("content-type", "")
    except urllib.error.HTTPError as exc:
        # A 403/404/500 page still carries fingerprintable headers and body.
        try:
            raw = exc.read(max_bytes)
        except Exception:
            raw = b""
        headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        final_url = exc.geturl() or url
        status = exc.code
        content_type = headers.get("content-type", "")
    except Exception as exc:
        return {"url": url, "error": str(exc), "matches": []}

    body = raw.decode("utf-8", errors="ignore")
    header_text = " ".join(str(v) for v in headers.values())
    text = (body + " " + _strip_html(body) + " " + final_url + " " + content_type
            + " " + header_text).lower()
    title_m = re.search(r"(?is)<title[^>]*>(.*?)</title>", body)
    title = _strip_html(title_m.group(1)) if title_m else ""

    results = []
    for vendor, spec in SIGNATURES.items():
        evidence = []
        score = 0
        for needle, weight in spec["patterns"]:
            if needle.lower() in text:
                score += weight
                evidence.append(needle)
        if score:
            # Confidence is bounded and intentionally not a probability.
            confidence = min(0.99, 0.35 + score / 20.0)
            results.append({
                "vendor": vendor,
                "product": spec["product"],
                "score": score,
                "confidence": round(confidence, 2),
                "evidence": evidence,
            })

    results.sort(key=lambda x: x["score"], reverse=True)
    return {
        "url": url,
        "final_url": final_url,
        "status": status,
        "content_type": content_type,
        "title": title,
        "server": headers.get("server", ""),
        "matches": results,
        "best_match": results[0] if results else None,
    }


def run(url: str = "", timeout: int = 10, verify_tls: bool = True,
        use_recovery: bool = True, use_cache: bool = False,
        exec_timeout: int = 30, **kwargs: Any) -> dict[str, Any]:
    params = {
        "url": url, "timeout": timeout, "verify_tls": verify_tls,
        "target": kwargs.get("target", ""), "additional_args": kwargs.get("additional_args", ""),
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


_CLI_CONTAINER = "/home/mcpuser/mcp-servers/network/tools/web_fingerprint.py"
_CLI_FALLBACK = str(Path(__file__).resolve())


def _cli_expr() -> str:
    return (
        f"$( [ -f {_CLI_CONTAINER} ] && echo {_CLI_CONTAINER} "
        f"|| echo {_CLI_FALLBACK} )"
    )


def build_command(**params: Any) -> str:
    url = str(params.get("url") or params.get("target") or "").strip()
    if not url:
        raise ValueError("web_fingerprint requires url=")

    timeout = str(params.get("timeout") or "10").strip() or "10"
    verify = str(params.get("verify_tls") or "true").strip().lower()
    verify_flag = "true" if verify in ("1", "true", "yes", "y") else "false"

    return (
        f"python3 {_cli_expr()} --cli"
        f" --url {shlex.quote(url)}"
        f" --timeout {shlex.quote(timeout)}"
        f" --verify-tls {verify_flag}"
    )


def parse(result: ToolResult) -> dict[str, Any]:
    raw = (result.raw_stdout or "").strip()
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {"error": "invalid_json", "raw": raw[:500], "matches": []}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Passive HTTP(S) appliance fingerprinting")
    parser.add_argument("--cli", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--url", required=True)
    parser.add_argument("--timeout", default="10")
    parser.add_argument("--verify-tls", dest="verify_tls", default="true")
    args = parser.parse_args()

    out = fingerprint(
        args.url.strip(),
        timeout=max(1, min(int(args.timeout), 60)),
        verify_tls=args.verify_tls.lower() in ("1", "true", "yes", "y"),
    )
    print(json.dumps(out))
