"""Email-security posture probe — SPF / DKIM / DMARC / MX via dig.

Passive DNS lookups only. Surfaces spoofing/phishing exposure (missing or weak
SPF/DMARC) as structured findings — the sample engagement flagged "no MX = no
email security" by hand; this makes SPF/DKIM/DMARC posture a first-class,
reportable recon fact. No host is touched beyond authoritative DNS.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import run_tool
from _core.result import ToolResult

TOOL_NAME = "email_security_probe"
CATEGORY = "recon"

# Common DKIM selectors to probe (best-effort; DKIM has no discovery mechanism).
_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2"]


def build_command(**params: Any) -> str:
    domain = str(params.get("domain") or params.get("target") or "").strip()
    if not domain:
        raise ValueError("email_security_probe requires domain=")
    selectors = " ".join(_DKIM_SELECTORS)
    script = """set +e
DOM='""" + domain + """'
echo "=== MX ==="
dig +short MX "$DOM" 2>/dev/null
echo "=== SPF ==="
dig +short TXT "$DOM" 2>/dev/null | grep -i 'v=spf1' || echo "NONE"
echo "=== DMARC ==="
dig +short TXT "_dmarc.$DOM" 2>/dev/null | grep -i 'v=DMARC1' || echo "NONE"
echo "=== DKIM ==="
for sel in """ + selectors + """; do
  REC=$(dig +short TXT "${sel}._domainkey.$DOM" 2>/dev/null | grep -i 'v=DKIM1\\|k=rsa\\|p=')
  if [ -n "$REC" ]; then
    echo "DKIM_SELECTOR: $sel"
  fi
done
echo "=== DONE ==="
"""
    return script.strip()


def parse(result: ToolResult) -> dict[str, Any]:
    from _core.runner import default_parse
    return default_parse(result)


def run(
    domain: str = "",
    target: str = "",
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 60,
) -> dict[str, Any]:
    params = {"domain": domain or target}
    return run_tool(
        TOOL_NAME,
        build_command(**params),
        params=params,
        timeout=exec_timeout,
        use_cache=use_cache,
        use_recovery=use_recovery,
        parse_fn=parse,
    )
