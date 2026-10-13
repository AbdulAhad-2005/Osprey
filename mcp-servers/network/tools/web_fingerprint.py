"""Fingerprint common network/security appliances over HTTP(S).

GETs the target's web UI and matches vendor/product signatures, returning
matches with confidence and evidence. Passive — GET only, no auth or form
submission. When the root page is inconclusive it also GETs the known vendor
login paths (same origin) and re-scores, since an appliance is often
identifiable only on its login endpoint.
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
from _core.runner import run_tool

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
    # SOHO / consumer routers (the ticket covers routers broadly). The web UI
    # often reveals little on the root, so vendor-specific UI paths carry weight.
    "TP-Link": {
        "product": "TP-Link router / Archer",
        "patterns": [
            ("tp-link", 6), ("tplink", 5), ("archer", 5), ("/webpages/", 6),
            ("tp link", 5), ("tether", 3),
        ],
    },
    "Huawei": {
        "product": "Huawei router / gateway",
        "patterns": [
            ("huawei", 6), ("huaweihomegateway", 7), ("echolife", 6),
            ("/html/index.html", 2),
        ],
    },
    "ZTE": {
        "product": "ZTE router / gateway",
        "patterns": [("zte corporation", 7), ("zxhn", 6), ("zte", 4)],
    },
    "Netgear": {
        "product": "Netgear router",
        "patterns": [("netgear", 6), ("genie", 4), ("/cgi-bin/", 1), ("orbi", 5)],
    },
    "ASUS": {
        "product": "ASUS router / ASUSWRT",
        "patterns": [("asuswrt", 7), ("asus wireless router", 7), ("rt-ac", 4), ("merlin", 3)],
    },
    "OpenWrt": {
        "product": "OpenWrt / LuCI",
        "patterns": [("openwrt", 7), ("luci", 6), ("/cgi-bin/luci", 7), ("powered by luci", 7)],
    },
}


# Vendor login paths to probe when the root page is inconclusive — harvested
# from the signatures themselves so the two never drift (an appliance is often
# identifiable only on its login endpoint, not its bare root).
_LOGIN_PATHS = list(dict.fromkeys(
    needle for spec in SIGNATURES.values() for needle, _w in spec["patterns"] if needle.startswith("/")
))
_MAX_PROBE_PATHS = 14
_STRONG_SCORE = 7  # a confident single-vendor hit — stop probing further paths


def _strip_html(html: str) -> str:
    html = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", html)
    html = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", html)
    html = re.sub(r"(?is)<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", unescape(html)).strip()


def _fetch(url: str, timeout: int, verify_tls: bool, max_bytes: int) -> dict[str, Any]:
    """GET one URL → {text, title, headers, final_url, status, tls_failed}.
    An HTTP error status still yields its body/headers. Appliances routinely
    serve self-signed certs, so a verified request that fails on a cert error
    retries once unverified and flags it. Raises on a connection failure."""
    def _do_get(ctx):
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Osprey-WebFingerprinter/1.0", "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                return (response.read(max_bytes),
                        {k.lower(): v for k, v in response.headers.items()},
                        response.geturl(), response.status)
        except urllib.error.HTTPError as exc:
            try:
                raw_ = exc.read(max_bytes)
            except Exception:
                raw_ = b""
            return (raw_, {k.lower(): v for k, v in (exc.headers or {}).items()},
                    exc.geturl() or url, exc.code)

    tls_failed = False
    try:
        raw, headers, final_url, status = _do_get(None if verify_tls else ssl._create_unverified_context())
    except (urllib.error.URLError, ssl.SSLError) as exc:
        reason = getattr(exc, "reason", exc)
        if verify_tls and isinstance(reason, ssl.SSLError):
            raw, headers, final_url, status = _do_get(ssl._create_unverified_context())
            tls_failed = True
        else:
            raise

    body = raw.decode("utf-8", errors="ignore")
    title_m = re.search(r"(?is)<title[^>]*>(.*?)</title>", body)
    # Match on RESPONSE content only — never the request URL. Folding the path we
    # chose to GET into the text would self-match that path's vendor signature
    # (probing /cgi-bin/sslvpnclient must not "prove" SonicWall).
    text = " ".join((body, _strip_html(body), headers.get("content-type", ""),
                     " ".join(str(v) for v in headers.values()))).lower()
    meta = re.search(r'(?is)<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*content=["\']?[^;"\']*;\s*url=([^"\'>\s]+)', body)
    return {
        "text": text, "title": _strip_html(title_m.group(1)) if title_m else "",
        "meta_refresh": meta.group(1).strip() if meta else "",
        "headers": headers, "final_url": final_url, "status": status, "tls_failed": tls_failed,
    }


def _score(text: str) -> list[dict[str, Any]]:
    results = []
    for vendor, spec in SIGNATURES.items():
        evidence = [needle for needle, _w in spec["patterns"] if needle.lower() in text]
        score = sum(weight for needle, weight in spec["patterns"] if needle.lower() in text)
        if score:
            results.append({
                "vendor": vendor, "product": spec["product"], "score": score,
                "confidence": round(min(0.99, 0.35 + score / 20.0), 2),  # bounded, not a probability
                "evidence": evidence,
            })
    results.sort(key=lambda x: x["score"], reverse=True)
    return results


def fingerprint(url: str, timeout: int = 10, verify_tls: bool = True,
                probe_paths: bool = True, max_bytes: int = 1_000_000) -> dict[str, Any]:
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    try:
        base = _fetch(url, timeout, verify_tls, max_bytes)
    except Exception as exc:
        return {"url": url, "error": str(exc), "matches": []}

    from urllib.parse import urljoin, urlsplit, urlunsplit

    # The base includes its server-chosen final_url (a redirect to e.g.
    # /remote/login is a legit signal); probed pages contribute content only.
    texts = [base["text"], (base["final_url"] or "").lower()]
    tls_failed = base["tls_failed"]
    title = base["title"]
    probed: list[str] = []
    followed: list[str] = []

    # Follow one meta-refresh hop — many device UIs redirect to their real page
    # via <meta refresh>, not an HTTP 3xx, so urllib would otherwise stop at the
    # stub (e.g. a TP-Link root that meta-refreshes to /webpages/index.html).
    if base.get("meta_refresh"):
        try:
            hop = _fetch(urljoin(base["final_url"] or url, base["meta_refresh"]),
                         timeout, verify_tls and not tls_failed, max_bytes)
            # The refresh TARGET path is server-chosen (in the root HTML), so it is
            # a legit signal like a redirect Location — e.g. /webpages/ => TP-Link.
            texts.append(hop["text"])
            texts.append(base["meta_refresh"].lower())
            tls_failed = tls_failed or hop["tls_failed"]
            title = title or hop["title"]
            followed.append(base["meta_refresh"])
        except Exception:
            pass

    results = _score(" ".join(texts))

    # If still no confident vendor, probe the known appliance login paths (same
    # origin) and re-score — bounded, GET-only, stops once one vendor is confident.
    if probe_paths and (not results or results[0]["score"] < _STRONG_SCORE):
        parts = urlsplit(base["final_url"] or url)
        origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
        probe_verify = verify_tls and not tls_failed  # skip the known-failing verify pass
        for path in _LOGIN_PATHS[:_MAX_PROBE_PATHS]:
            try:
                page = _fetch(origin + path, min(timeout, 6), probe_verify, max_bytes)
            except Exception:
                continue
            probed.append(path)
            texts.append(page["text"])
            tls_failed = tls_failed or page["tls_failed"]
            results = _score(" ".join(texts))
            if results and results[0]["score"] >= _STRONG_SCORE:
                break

    return {
        "url": url,
        "final_url": base["final_url"],
        "status": base["status"],
        "content_type": base["headers"].get("content-type", ""),
        "title": title,
        "server": base["headers"].get("server", ""),
        "tls_verification_failed": tls_failed,
        "followed": followed,
        "probed_paths": probed,
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
