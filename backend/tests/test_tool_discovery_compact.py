"""compact=True previously dropped llm_hints/tags entirely (recon/network phases,
the two with the most tools — 51/18) before the fix in tool_discovery.py.
Truncation for token economy is fine; deleting the field built for tool
disambiguation is not. These pin the fix and the "never filters what's
callable" guarantee for phase-scoped tool arrays.
"""

from __future__ import annotations

from osprey.schemas.tool_capability import ToolCapability
from osprey.schemas.tools import ToolSafetyLevel
from osprey.services.tool_discovery import capability_to_openai, get_tools_for_llm_phase


def _sample_capability(**overrides) -> ToolCapability:
    base = dict(
        tool_name="subfinder_scan",
        task="subdomain_enumeration",
        phase="recon",
        safety_level=ToolSafetyLevel.PASSIVE,
        executable="subfinder",
        description="Passive subdomain enumeration across public data sources.",
        llm_hints="Default passive subdomain enum. If few results, try amass.",
        tags=["subdomains", "osint", "asset-discovery"],
    )
    base.update(overrides)
    return ToolCapability(**base)


def test_compact_mode_keeps_llm_hints():
    cap = _sample_capability()
    schema = capability_to_openai(cap, compact=True)
    desc = schema["function"]["description"]
    assert "Default passive subdomain enum" in desc


def test_compact_mode_keeps_tags():
    cap = _sample_capability()
    schema = capability_to_openai(cap, compact=True)
    desc = schema["function"]["description"]
    assert "subdomains" in desc and "osint" in desc


def test_compact_mode_drops_redundant_task_phase_fields():
    cap = _sample_capability()
    schema = capability_to_openai(cap, compact=True)
    desc = schema["function"]["description"]
    assert "Task:" not in desc
    assert "Phase:" not in desc


def test_non_compact_still_has_everything():
    cap = _sample_capability()
    schema = capability_to_openai(cap, compact=False)
    desc = schema["function"]["description"]
    assert "Default passive subdomain enum" in desc
    assert "subdomains" in desc
    assert "Task: subdomain_enumeration" in desc
    assert "Phase: recon" in desc


def test_recon_and_network_tools_all_have_llm_hints_now():
    from osprey.services.task_registry import list_tool_capabilities

    for phase in ("recon", "network"):
        caps = list_tool_capabilities(phase=phase)
        missing = [c.tool_name for c in caps if not c.llm_hints or c.llm_hints == c.description]
        assert not missing, f"{phase} tools with no real llm_hints signal: {missing}"


def test_full_tool_array_unfiltered_regardless_of_queue_content():
    """Dispatch tags / exploit-candidate queues (Round 2/3) are additive context,
    never a filter on what's callable — this is the structural guarantee."""
    recon_tools = get_tools_for_llm_phase("recon", compact=True)
    assert len(recon_tools) >= 20  # full catalog, not a curated shortlist
