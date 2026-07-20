#!/usr/bin/env python3
"""Smoke-test recon/network: alias remap + Kali binaries + playbooks file.

Run from repo root (or anywhere) with backend up:
  python scripts/smoke_recon_network.py
  python scripts/smoke_recon_network.py --api http://127.0.0.1:9000
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Wrong-key → expected substring in built command
ALIAS_CASES = [
    ("subfinder_scan", {"target": "example.com"}, "subfinder -d example.com"),
    ("dnsenum_scan", {"target": "example.com"}, "dnsenum --enum example.com"),
    ("nmap_syn_scan", {"domain": "vpn.example.com"}, "vpn.example.com"),
    ("httpx_probe", {"domain": "https://www.example.com"}, "https://www.example.com"),
    ("rustscan_fast_scan", {"host": "203.0.113.10"}, "203.0.113.10"),
    ("whois_lookup", {"target": "example.com"}, "example.com"),
]

BINARIES = ("subfinder", "nmap", "rustscan", "whois", "amass", "httpx")


def _post(api: str, path: str, body: dict) -> dict:
    req = urllib.request.Request(
        api.rstrip("/") + path,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get(api: str, path: str) -> dict:
    with urllib.request.urlopen(api.rstrip("/") + path, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def check_playbooks() -> list[str]:
    path = ROOT / "config" / "playbooks.yaml"
    if not path.exists():
        return [f"MISSING playbooks.yaml at {path}"]
    text = path.read_text(encoding="utf-8")
    errs = []
    for name in ("web_recon_light", "network_crown_jewels", "dns_deep", "smb_followup"):
        if name not in text:
            errs.append(f"playbook missing key: {name}")
    return errs


def check_aliases_local() -> list[str]:
    """Import backend validators if PYTHONPATH includes backend/src."""
    errs: list[str] = []
    sys.path.insert(0, str(ROOT / "backend" / "src"))
    try:
        from pentest_platform.services.command_builder import build_command_for_tool
        from pentest_platform.services.param_validator import validate_raw
    except Exception as exc:  # noqa: BLE001
        return [f"local import failed (will rely on API): {exc}"]

    for tool, params, needle in ALIAS_CASES:
        v = validate_raw(tool, params)
        if not v.approved:
            errs.append(f"{tool} {params} REJECTED: {v.reason}")
            continue
        try:
            cmd = build_command_for_tool(tool, v.normalized_params)
        except Exception as exc:  # noqa: BLE001
            errs.append(f"{tool} build failed: {exc}")
            continue
        if needle not in cmd:
            errs.append(f"{tool} cmd missing {needle!r}: got {cmd!r}")
        # Primary must not be empty flag
        if " -d  " in cmd or cmd.rstrip().endswith(" -d") or "--enum  " in cmd:
            errs.append(f"{tool} looks like empty primary: {cmd!r}")
    return errs


def check_catalog_api(api: str) -> list[str]:
    errs: list[str] = []
    try:
        data = _get(api, "/api/v1/tools/catalog?category=recon")
    except Exception as exc:  # noqa: BLE001
        return [f"catalog API failed: {exc}"]
    tools = data.get("tools") or []
    by_name = {t.get("name"): t for t in tools if isinstance(t, dict)}
    for name in ("subfinder_scan", "whois_lookup", "httpx_probe"):
        t = by_name.get(name)
        if not t:
            errs.append(f"catalog missing {name}")
        elif t.get("installed") is False:
            errs.append(f"{name} installed=false in catalog")
    try:
        net = _get(api, "/api/v1/tools/catalog?category=network")
    except Exception as exc:  # noqa: BLE001
        errs.append(f"network catalog failed: {exc}")
        return errs
    net_by = {t.get("name"): t for t in (net.get("tools") or []) if isinstance(t, dict)}
    rs = net_by.get("rustscan_fast_scan")
    if not rs:
        errs.append("catalog missing rustscan_fast_scan")
    elif rs.get("installed") is False:
        errs.append("rustscan_fast_scan installed=false")
    return errs


def check_binaries_docker() -> list[str]:
    import subprocess

    errs: list[str] = []
    cmd = [
        "docker",
        "exec",
        "ai-pentest-kali",
        "sh",
        "-c",
        "export PATH=/opt/go/bin:/usr/local/bin:$PATH; "
        + "; ".join(f"command -v {b} >/dev/null || echo MISSING:{b}" for b in BINARIES),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception as exc:  # noqa: BLE001
        return [f"docker exec failed: {exc}"]
    out = (proc.stdout or "") + (proc.stderr or "")
    for line in out.splitlines():
        if line.startswith("MISSING:"):
            errs.append(line.strip())
    return errs


def check_elite_surface(api: str) -> list[str]:
    errs: list[str] = []
    # skills + config browse
    try:
        idx = _get(api, "/api/v1/capabilities/skills-index")
        if int(idx.get("count") or 0) < 3:
            errs.append(f"skills-index too thin: {idx.get('count')}")
    except Exception as exc:  # noqa: BLE001
        errs.append(f"skills-index failed: {exc}")
    try:
        skill = _get(api, "/api/v1/capabilities/skills-file?path=shared/evidence-to-hypothesis.md")
        if "SIGNAL" not in (skill.get("content") or ""):
            errs.append("evidence-to-hypothesis skill missing SIGNAL loop")
    except Exception as exc:  # noqa: BLE001
        errs.append(f"skills-file evidence-to-hypothesis failed: {exc}")
    try:
        cfg = _get(api, "/api/v1/capabilities/config-file?name=thinking_model")
        if "universal_loop" not in (cfg.get("content") or ""):
            errs.append("thinking_model missing universal_loop")
    except Exception as exc:  # noqa: BLE001
        errs.append(f"config-file thinking_model failed: {exc}")
    try:
        cfg = _get(api, "/api/v1/capabilities/config-file?name=ingest_rules")
        if "spa_catchall" not in (cfg.get("content") or ""):
            errs.append("ingest_rules missing spa_catchall")
    except Exception as exc:  # noqa: BLE001
        errs.append(f"config-file ingest_rules failed: {exc}")

    # ingest promoter local
    sys.path.insert(0, str(ROOT / "backend" / "src"))
    try:
        from pentest_platform.services.hypothesis_engine import build_hypotheses_from_text
        from pentest_platform.services.ingest_promoter import apply_ingest_rules, looks_like_spa_html

        html = "<!DOCTYPE html><div id=\"root\"></div>"
        if not looks_like_spa_html(html):
            errs.append("SPA detector failed")
        sample = "Server: nginx\nX-CUSTOM-VENDOR-ID: abc123\n" + html
        found = apply_ingest_rules(
            sample,
            engagement_id="smoke-test-eid",
            source_tool="smoke",
            target="https://x.example/api/v1",
            persist=False,
        )
        titles = " ".join(f.title for f in found).lower()
        if "spa" not in titles and "html" not in titles:
            errs.append(f"ingest missed spa signal: {[f.title for f in found]}")
        cards = build_hypotheses_from_text(
            "X-ORACLE-DMS-ECID: deadbeef\nServer: WebLogic",
            asset="app.example",
        )
        if not cards:
            errs.append("hypothesis_engine produced no cards for vendor header sample")
        elif cards[0].get("signal_class") != "vendor_http_header":
            errs.append(f"expected vendor_http_header card, got {cards[0].get('signal_class')}")
    except Exception as exc:  # noqa: BLE001
        errs.append(f"ingest/hypothesis local failed: {exc}")

    # nmap_custom flags optional
    try:
        from pentest_platform.services.param_validator import validate_raw

        v = validate_raw("nmap_custom_scan", {"target": "203.0.113.10"})
        if not v.approved:
            errs.append(f"nmap_custom_scan without flags rejected: {v.reason}")
    except Exception as exc:  # noqa: BLE001
        errs.append(f"nmap_custom validate failed: {exc}")

    return errs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://127.0.0.1:9000")
    parser.add_argument("--skip-docker", action="store_true")
    args = parser.parse_args()

    failures: list[str] = []
    failures.extend(check_playbooks())
    failures.extend(check_aliases_local())
    failures.extend(check_catalog_api(args.api))
    failures.extend(check_elite_surface(args.api))
    if not args.skip_docker:
        failures.extend(check_binaries_docker())

    if failures:
        print("SMOKE FAIL")
        for f in failures:
            print(" -", f)
        return 1
    print("SMOKE OK — recon/network + elite skills/ingest/graph surface")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
