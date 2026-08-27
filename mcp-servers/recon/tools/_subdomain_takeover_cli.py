#!/usr/bin/env python3
"""CNAME + HTTP fingerprint subdomain takeover checker."""

from __future__ import annotations

import json
import sys
from typing import Any

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Fingerprints are signals for the operator — not a closed universe.
TAKEOVER_FINGERPRINTS = [
    {
        "service": "GitHub Pages",
        "cname_patterns": ["github.io", "github.com"],
        "error_strings": ["There isn't a GitHub Pages site here"],
    },
    {
        "service": "Heroku",
        "cname_patterns": ["herokuapp.com", "heroku.com"],
        "error_strings": ["No such app", "herokucdn.com/error-pages/no-such-app"],
    },
    {
        "service": "AWS S3",
        "cname_patterns": ["s3.amazonaws.com", "s3-website"],
        "error_strings": ["NoSuchBucket", "The specified bucket does not exist"],
    },
    {
        "service": "AWS CloudFront",
        "cname_patterns": ["cloudfront.net"],
        "error_strings": [
            "Bad request. We cannot connect to the server for this app or website at this time.",
            "ERROR: The request could not be satisfied",
        ],
    },
    {
        "service": "Azure",
        "cname_patterns": ["azurewebsites.net", "azure.com", "cloudapp.net"],
        "error_strings": ["404 Web Site not found", "does not exist in Azure"],
    },
    {
        "service": "Netlify",
        "cname_patterns": ["netlify.com", "netlify.app"],
        "error_strings": ["Not Found - Request ID", "netlify.com/error-page"],
    },
    {
        "service": "Vercel",
        "cname_patterns": ["vercel.app", "now.sh"],
        "error_strings": ["The deployment could not be found", "This page could not be found"],
    },
    {
        "service": "Fastly",
        "cname_patterns": ["fastly.net"],
        "error_strings": [
            "Fastly error: unknown domain",
            "Please check that this domain has been added to a service",
        ],
    },
    {
        "service": "Shopify",
        "cname_patterns": ["myshopify.com"],
        "error_strings": ["Sorry, this shop is currently unavailable", "Only one step away"],
    },
    {
        "service": "Tumblr",
        "cname_patterns": ["tumblr.com"],
        "error_strings": ["Whatever you were looking for doesn't currently exist"],
    },
    {
        "service": "WordPress.com",
        "cname_patterns": ["wordpress.com"],
        "error_strings": ["Do you want to register"],
    },
    {
        "service": "Ghost",
        "cname_patterns": ["ghost.io"],
        "error_strings": ["The thing you were looking for is no longer here"],
    },
    {
        "service": "Surge.sh",
        "cname_patterns": ["surge.sh"],
        "error_strings": ["project not found"],
    },
    {
        "service": "Pantheon",
        "cname_patterns": ["pantheon.io", "pantheonsite.io"],
        "error_strings": ["The gods are wise, but do not know of the site which you seek."],
    },
    {
        "service": "Sendgrid",
        "cname_patterns": ["sendgrid.net"],
        "error_strings": ["The provided host name is not valid for this server."],
    },
    {
        "service": "Cargo",
        "cname_patterns": ["cargocollective.com"],
        "error_strings": ["404 Not Found"],
    },
    {
        "service": "HubSpot",
        "cname_patterns": ["hubspot.com", "hubspotpagebuilder.com"],
        "error_strings": ["Domain not found"],
    },
    {
        "service": "Zendesk",
        "cname_patterns": ["zendesk.com"],
        "error_strings": ["Help Center Closed"],
    },
    {
        "service": "Readme.io",
        "cname_patterns": ["readme.io"],
        "error_strings": ["Project doesnt exist... yet"],
    },
    {
        "service": "Intercom",
        "cname_patterns": ["intercom.io"],
        "error_strings": ["This page is reserved for artistic dogs."],
    },
]


def get_cname(subdomain: str) -> str | None:
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(subdomain, "CNAME")
        return str(answers[0].target).rstrip(".")
    except Exception:
        return None


def check_http_response(subdomain: str) -> tuple[int, str]:
    try:
        import requests
    except ImportError:
        return 0, ""

    for scheme in ("https", "http"):
        try:
            response = requests.get(
                f"{scheme}://{subdomain}",
                timeout=8,
                verify=False,
                allow_redirects=True,
            )
            return response.status_code, response.text or ""
        except Exception:
            continue
    return 0, ""


def check_takeover(subdomain: str) -> dict[str, Any]:
    cname = get_cname(subdomain)
    if not cname:
        return {
            "subdomain": subdomain,
            "status": "safe",
            "reason": "No CNAME record found",
        }

    status_code, body = check_http_response(subdomain)
    body_l = body.lower()
    cname_l = cname.lower()

    for fingerprint in TAKEOVER_FINGERPRINTS:
        cname_match = any(p.lower() in cname_l for p in fingerprint["cname_patterns"])
        if not cname_match:
            continue
        error_match = any(e.lower() in body_l for e in fingerprint["error_strings"])
        if error_match:
            return {
                "subdomain": subdomain,
                "service": fingerprint["service"],
                "cname": cname,
                "http_status": status_code,
                "status": "vulnerable",
                "reason": (
                    f"CNAME points to {fingerprint['service']} ({cname}) "
                    "and body matches unclaimed-service fingerprint"
                ),
            }
        if status_code in (404, 0):
            return {
                "subdomain": subdomain,
                "service": fingerprint["service"],
                "cname": cname,
                "http_status": status_code,
                "status": "potential",
                "reason": (
                    f"CNAME points to {fingerprint['service']} ({cname}) "
                    f"and HTTP {status_code} — verify manually"
                ),
            }

    return {
        "subdomain": subdomain,
        "cname": cname,
        "http_status": status_code,
        "status": "safe",
        "reason": f"CNAME to {cname} — no takeover fingerprint matched",
    }


def main() -> None:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: _subdomain_takeover_cli.py '<json_params>'"}))
        raise SystemExit(1)

    params = json.loads(sys.argv[1])
    target = str(params.get("target") or params.get("domain") or "").strip()
    mode = str(params.get("mode") or "single").strip().lower()
    raw_list = params.get("subdomains") or params.get("hosts") or []

    if isinstance(raw_list, str):
        subdomains = [s.strip() for s in raw_list.replace(",", "\n").splitlines() if s.strip()]
    else:
        subdomains = [str(s).strip() for s in raw_list if str(s).strip()]

    if mode == "list":
        hosts = subdomains or ([target] if target else [])
    elif mode == "single":
        hosts = [target] if target else subdomains[:1]
    else:
        # "list" of known hosts preferred; discover is operator-driven via subfinder first
        hosts = subdomains or ([target] if target else [])

    if not hosts:
        print(json.dumps({"error": "No hosts to check — pass target= or subdomains="}))
        raise SystemExit(1)

    # Soft cap keeps OpenCode-friendly runtime; operator can chunk via jobs/fanout.
    max_hosts = int(params.get("max_hosts") or 50)
    hosts = hosts[: max(1, max_hosts)]

    results = [check_takeover(host) for host in hosts]
    vulnerable = [r for r in results if r.get("status") == "vulnerable"]
    potential = [r for r in results if r.get("status") == "potential"]
    safe = [r["subdomain"] for r in results if r.get("status") == "safe"]

    print(
        json.dumps(
            {
                "vulnerable": vulnerable,
                "potential": potential,
                "safe": safe,
                "summary": {
                    "tested": len(results),
                    "vulnerable": len(vulnerable),
                    "potential": len(potential),
                    "safe": len(safe),
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
