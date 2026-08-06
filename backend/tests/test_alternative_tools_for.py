"""Component 3 — consolidated fallback-tool suggestion (execution_recovery.alternative_tools_for).

Replaces tool_execution.py's _STATIC_FALLBACKS dict. Two-tier: the curated
_core.recovery.alternatives_for_tool() map first, tool_registry category/tag
overlap second, platform_script as a universal last resort.
"""

from __future__ import annotations

from pentest_platform.services.execution_recovery import alternative_tools_for
from pentest_platform.services.tool_registry import get_tool_definition


def test_curated_alternative_is_used_when_available():
    # nmap_syn_scan -> "nmap" in the curated map -> alternatives include real,
    # registered platform port-scan tools.
    alts = alternative_tools_for("nmap_syn_scan")
    assert alts, "expected at least one alternative"
    assert "nmap_syn_scan" not in alts  # never suggest itself
    for name in alts:
        assert get_tool_definition(name) is not None, f"{name} must be a real registered tool"


def test_never_suggests_the_tool_itself():
    for tool_name in ("subfinder_scan", "amass_scan", "gau_discovery", "nmap_service_scan"):
        assert tool_name not in alternative_tools_for(tool_name)


def test_unregistered_tool_still_gets_a_graceful_fallback():
    # No crash, no empty list for a made-up/misspelled name — platform_script
    # is always a legitimate answer to "what else can I try."
    alts = alternative_tools_for("this_tool_does_not_exist_at_all")
    assert alts == ["platform_script"]


def test_result_is_capped_at_limit():
    alts = alternative_tools_for("subfinder_scan", limit=2)
    assert len(alts) <= 2


def test_category_tag_fallback_only_suggests_same_category():
    # whois_lookup has no curated _core.recovery entry — whatever fills in
    # must come from the same ToolCategory (recon), never a network/vuln tool.
    this_def = get_tool_definition("whois_lookup")
    alts = alternative_tools_for("whois_lookup")
    for name in alts:
        if name == "platform_script":
            continue
        other_def = get_tool_definition(name)
        assert other_def is not None
        assert other_def.category == this_def.category
