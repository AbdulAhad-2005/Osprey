#!/usr/bin/env python3
"""
Email permutation generator — turn a person's name + a domain into the likely
corporate email formats, and note whether the domain even accepts mail (MX).

Keyless. Pairs with the pivot flow: web_contact_harvest / theHarvester find a
NAME, this proposes the addresses, holehe then tests which exist.

Output: single JSON object on stdout.

Usage:
    python3 _email_permute_cli.py "First Last" example.com
"""

from __future__ import annotations

import json
import re
import sys


def _mx_exists(domain: str) -> bool:
    try:
        import dns.resolver

        answers = dns.resolver.resolve(domain, "MX", lifetime=8)
        return len(list(answers)) > 0
    except Exception:
        return False


def permutations(name: str, domain: str) -> list[str]:
    parts = [p for p in re.split(r"[\s.]+", name.strip().lower()) if p.isalpha()]
    if not parts:
        return []
    first = parts[0]
    last = parts[-1]
    fi = first[0]
    li = last[0]
    d = domain.strip().lower().lstrip("@")

    locals_ = {
        first,
        last,
        f"{first}.{last}",
        f"{first}{last}",
        f"{first}_{last}",
        f"{first}-{last}",
        f"{fi}{last}",
        f"{fi}.{last}",
        f"{first}{li}",
        f"{first}.{li}",
        f"{last}.{first}",
        f"{last}{first}",
        f"{fi}{li}",
    }
    if len(parts) >= 3:  # include middle initial
        mi = parts[1][0]
        locals_.add(f"{fi}{mi}{last}")
        locals_.add(f"{first}.{parts[1]}.{last}")

    return sorted(f"{loc}@{d}" for loc in locals_ if loc)


def main() -> None:
    if len(sys.argv) < 3:
        print(json.dumps({"error": "usage: _email_permute_cli.py <name> <domain>"}))
        return
    name = sys.argv[1]
    domain = sys.argv[2]
    cands = permutations(name, domain)
    print(
        json.dumps(
            {
                "name": name,
                "domain": domain.lstrip("@").lower(),
                "mx": _mx_exists(domain.lstrip("@").lower()),
                "candidates": cands,
            }
        )
    )


if __name__ == "__main__":
    main()
