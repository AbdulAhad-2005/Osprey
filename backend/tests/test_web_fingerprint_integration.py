"""web_fingerprint is a FIRST-CLASS, auto-used capability — not just a
registered name reachable via platform_exec. Guards the integration that was
missing when the tool first merged: a typed MCP wrapper, and a dispatch rule so
the deterministic engine fingerprints every live host."""

from __future__ import annotations

import tempfile

from osprey.schemas.engagement import EngagementCreateRequest
from osprey.schemas.observation import Observation, ObservationType
from osprey.services.engagement_store import get_engagement_store
from osprey.services.observation_store import get_observation_store
from osprey.services.tech_dispatch import suggest_dispatch


def test_registered_network_passive_and_engine_eligible():
    from osprey.services.tool_registry import get_tool_definition

    td = get_tool_definition("web_fingerprint")
    assert td is not None
    assert td.category.value == "network"
    assert td.safety_level.value == "passive"  # read-only → engine may auto-run


def test_exposed_as_a_typed_mcp_tool():
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_pm_typed_rn", root / "platform-mcp" / "typed_recon_network.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert "web_fingerprint" in mod.TYPED_RECON_NETWORK_TOOLS
    assert "web_fingerprint" in mod._TOOL_BLURBS


def test_engine_auto_fingerprints_a_live_host():
    import os

    os.environ.setdefault("DATABASE_URL", "sqlite:///" + tempfile.mktemp(suffix=".db"))
    eid = get_engagement_store().create(EngagementCreateRequest(target="fw.example.com")).id
    get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.URL, target="https://fw.example.com",
        source_tool="httpx_probe", details={"url": "https://fw.example.com"},
    ))
    suggestions = suggest_dispatch(engagement_id=eid)
    hits = [s for s in suggestions if s.default_tool == "web_fingerprint"]
    assert hits, "live host did not produce a web_fingerprint opportunity"
    assert hits[0].subject_id == "https://fw.example.com"
