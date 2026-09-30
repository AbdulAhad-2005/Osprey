"""Deterministic identity laws for investigation opportunities — every
opportunity is exactly one real action (one tool call, or for the three
analytical kinds, one store operation), so identity is keyed on
(capability, tool, subject, params, evidence), never a batch of subjects."""

from osprey.schemas.engagement_graph import AssetNode, AssetType
from osprey.schemas.investigation import CapabilityKind
from osprey.services.investigation_capabilities import _opportunity, _tool_opportunity


def _node(index: int) -> AssetNode:
    return AssetNode(
        id=f"subdomain:{index}",
        asset_type=AssetType.SUBDOMAIN,
        label=f"host-{index}.example.test",
        observation_ids=[f"obs-{index}"],
    )


def test_tool_opportunity_is_exactly_one_tool_on_one_subject() -> None:
    """The atomic unit: one opportunity always carries exactly one tool name
    and one subject — never a batch of subjects or more than one tool."""
    from osprey.services import priority

    node = _node(1)
    ctx = priority.build_context("")
    opp = _tool_opportunity(
        "subfinder_scan", node, param="domain", capability=CapabilityKind.ENUMERATE_SUBDOMAINS,
        reason="test", base=95, priority_ctx=ctx,
    )
    assert opp.tool == "subfinder_scan"
    assert opp.params == {"domain": node.label}
    assert len(opp.subjects) == 1
    assert opp.subjects[0].asset_id == node.id


def test_tool_opportunity_identity_changes_with_tool_or_params() -> None:
    from osprey.services import priority

    node = _node(1)
    ctx = priority.build_context("")
    first = _tool_opportunity(
        "subfinder_scan", node, param="domain", capability=CapabilityKind.ENUMERATE_SUBDOMAINS,
        reason="a", base=95, priority_ctx=ctx,
    )
    different_tool = _tool_opportunity(
        "amass_scan", node, param="domain", capability=CapabilityKind.ENUMERATE_SUBDOMAINS,
        reason="a", base=95, priority_ctx=ctx,
    )
    different_params = _tool_opportunity(
        "subfinder_scan", node, param="domain", capability=CapabilityKind.ENUMERATE_SUBDOMAINS,
        reason="a", base=95, priority_ctx=ctx, additional_args="-silent",
    )
    assert first.id != different_tool.id
    assert first.id != different_params.id


def test_fixed_capability_identity_is_stable_for_same_subject_set() -> None:
    nodes = [_node(2), _node(1)]
    first = _opportunity(
        CapabilityKind.RESOLVE_ASSETS, nodes, reason="first wording", priority=10
    )
    second = _opportunity(
        CapabilityKind.RESOLVE_ASSETS,
        list(reversed(nodes)),
        reason="changed wording",
        priority=99,
    )

    assert first.id == second.id


def test_evidence_revision_reopens_only_evidence_sensitive_action() -> None:
    nodes = [_node(1)]
    before = _opportunity(
        CapabilityKind.DETECT_ANOMALIES,
        nodes,
        reason="refresh",
        priority=10,
        evidence={"observation_ids": ["obs-1"]},
    )
    after = _opportunity(
        CapabilityKind.DETECT_ANOMALIES,
        nodes,
        reason="refresh",
        priority=10,
        evidence={"observation_ids": ["obs-1", "obs-2"]},
    )

    assert before.id != after.id
