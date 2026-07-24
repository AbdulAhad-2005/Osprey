"""WHOIS lookup via system whois binary.

Automatically strips subdomains to the registrable domain (e.g.
``sub.example.com`` -> ``example.com``) so the LLM does not need
to know this quirk of the ``whois`` binary.  A clear error is returned
when the input is not a valid domain.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import default_parse, run_tool
from _core.result import ToolResult

TOOL_NAME = "whois_lookup"
CATEGORY = "recon"

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

# Known multi-part TLDs where the registrable domain has 3+ labels.
_MULTI_PART_TLDS = {"co.uk", "com.au", "co.nz", "co.za", "com.br", "co.in",
                    "co.jp", "ne.jp", "or.jp", "co.kr", "com.sg", "co.nz"}


def _strip_to_apex(target: str) -> str:
    """Return the registrable (apex) domain from a FQDN.

    ``sub.scanme.nmap.org``  -> ``nmap.org``
    ``foo.example.co.uk``    -> ``example.co.uk``
    ``example.com``          -> ``example.com``
    """
    target = target.strip().rstrip(".")
    if not target or not _DOMAIN_RE.match(target):
        return target

    parts = target.split(".")
    if len(parts) <= 2:
        return target

    # Check for multi-part TLD (e.g. co.uk).
    tld_2 = ".".join(parts[-2:])
    if tld_2 in _MULTI_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])

    # Standard case: last two labels = apex domain.
    return ".".join(parts[-2:])


def build_command(**params: Any) -> str:
    raw = params.get("target") or params.get("domain") or ""
    additional_args = params.get("additional_args", "")

    target = _strip_to_apex(raw)
    if not target or not _DOMAIN_RE.match(target):
        raise ValueError(
            f"whois_lookup requires a valid domain or IP. Got: {raw!r}. "
            "Pass a root domain (e.g. example.com) or an IP address."
        )

    command = f"whois {target}"
    if additional_args:
        command += f" {additional_args}"
    return command


def parse_output(raw: ToolResult) -> dict[str, Any]:
    return default_parse(raw)


if __name__ == "__main__":
    run_tool(TOOL_NAME, CATEGORY, build_command, parse_output)
