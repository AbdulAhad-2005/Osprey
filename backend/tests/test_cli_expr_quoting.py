"""The native-host $(...) fallback-path pattern (_CLI_CONTAINER / _CLI_FALLBACK
/ _cli_expr) is duplicated across 21 mcp-server tool wrappers. Unquoted, it
breaks whenever the checkout path contains a space (common on Windows/Mac) in
two ways: the inner echo arg isn't shlex-quoted, AND bash word-splits a
command substitution's *output* at its point of use even when the inner
command WAS quoted — so the outer $(...) itself must be quoted too. One test
per file, run against a real bash, so this can't regress silently per-file."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MCP_SERVERS = ROOT / "mcp-servers"

# (category, tool_name) for every wrapper sharing the _cli_expr pattern.
_TOOLS = [
    ("network", "web_fingerprint"),
    ("osint", "email_permute"),
    ("osint", "intelx_scan"),
    ("osint", "web_contact_harvest"),
    ("osint", "resecurity_scan"),
    ("recon", "app_recon"),
    ("recon", "domain_hunter"),
    ("recon", "js_recon"),
    ("recon", "shodan_host_info"),
    ("recon", "shodan_search"),
    ("recon", "subdomain_takeover_check"),
    ("recon", "web_search"),
    ("web", "browser_flow"),
    ("web", "browser_scrape"),
    ("web", "canary_confirm"),
    ("web", "proxy_flows"),
    ("web", "proxy_flow_detail"),
    ("web", "proxy_replay"),
    ("web", "proxy_start"),
    ("web", "proxy_stop"),
    ("web", "response_diff_confirm"),
]


def _load(category: str, name: str):
    if str(MCP_SERVERS) not in sys.path:
        sys.path.insert(0, str(MCP_SERVERS))
    path = MCP_SERVERS / category / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"_test_cli_expr_{category}_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("category,name", _TOOLS, ids=[f"{c}/{n}" for c, n in _TOOLS])
def test_fallback_path_with_spaces_survives_as_one_shell_word(category, name, monkeypatch):
    module = _load(category, name)
    monkeypatch.setattr(module, "_CLI_FALLBACK", "/home/some user/with spaces/_tool.py")
    expr = module._cli_expr()
    assert expr.startswith('"$(') and expr.endswith(')"'), f"{name}: outer $(...) not quoted"

    script = f'for w in {expr}; do printf "%s\\n" "$w"; done\n'
    out = subprocess.run(["bash", "-s"], input=script.encode(), capture_output=True, timeout=5)
    assert out.stdout.decode().splitlines() == ["/home/some user/with spaces/_tool.py"], (
        f"{name}: {out.stderr.decode()}"
    )
