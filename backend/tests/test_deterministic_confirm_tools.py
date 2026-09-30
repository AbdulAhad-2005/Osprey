"""canary_confirm / response_diff_confirm — plans/harness/12-deterministic-
evidence-verification.md Step 2: registration + parser correctness. The
tools' own CLI logic runs inside Kali (mcp-servers/), untested here by
convention (matches proxy_replay/browser_scrape — no precedent test exists
for those either); what belongs in the backend suite is that the catalog
resolves them and their stdout becomes real, groundable evidence.
"""

from __future__ import annotations

import json

from osprey.services.parsers.deterministic_confirm import (
    parse_canary_confirm,
    parse_response_diff_confirm,
)
from osprey.services.tool_registry import get_tool_definition


def test_canary_confirm_and_response_diff_confirm_are_registered():
    for name in ("canary_confirm", "response_diff_confirm"):
        tool_def = get_tool_definition(name)
        assert tool_def is not None, f"{name} not registered in the tool catalog"
        assert tool_def.executable == "python3"


def test_parse_canary_confirm_found_becomes_scanner_signal_with_real_snippet():
    stdout = json.dumps({
        "canary": "xyz123nonce",
        "url": "https://x.test/search?q=xyz123nonce",
        "status_code": 200,
        "found": True,
        "occurrences": 1,
        "context": "<div>results for xyz123nonce</div>",
    })
    obs = parse_canary_confirm(stdout, engagement_id="e1", run_id="r1", target="x.test")
    assert len(obs) == 1
    assert obs[0].type.value == "scanner_signal"
    assert obs[0].details["found"] is True
    # The raw stdout is preserved verbatim as the groundable snippet.
    assert "xyz123nonce" in obs[0].details["snippet"]


def test_parse_canary_confirm_not_found_becomes_raw_not_scanner_signal():
    stdout = json.dumps({
        "canary": "xyz123nonce", "url": "https://x.test/", "status_code": 200,
        "found": False, "occurrences": 0, "context": "",
    })
    obs = parse_canary_confirm(stdout, engagement_id="e1", run_id="r1", target="x.test")
    assert len(obs) == 1
    assert obs[0].type.value == "raw"


def test_parse_response_diff_confirm_differing_becomes_scanner_signal():
    stdout = json.dumps({
        "url_a": "https://x.test/?id=1' AND SLEEP(0)--",
        "url_b": "https://x.test/?id=1' AND SLEEP(5)--",
        "status_code_a": 200, "status_code_b": 200,
        "body_length_a": 120, "body_length_b": 4,
        "length_delta": -116,
        "identical": False,
        "diff": ["-full page", "+error"],
    })
    obs = parse_response_diff_confirm(stdout, engagement_id="e1", run_id="r1", target="x.test")
    assert len(obs) == 1
    assert obs[0].type.value == "scanner_signal"
    assert obs[0].details["identical"] is False
    assert "SLEEP" in obs[0].details["snippet"]


def test_parse_response_diff_confirm_identical_becomes_raw():
    stdout = json.dumps({
        "url_a": "https://x.test/a", "url_b": "https://x.test/b",
        "status_code_a": 200, "status_code_b": 200,
        "body_length_a": 50, "body_length_b": 50,
        "length_delta": 0, "identical": True, "diff": [],
    })
    obs = parse_response_diff_confirm(stdout, engagement_id="e1", run_id="r1", target="x.test")
    assert len(obs) == 1
    assert obs[0].type.value == "raw"


def test_reproduction_claim_grounded_via_canary_confirm_observation():
    """End-to-end proof this closes the loop Step 1 opened: a real
    canary_confirm run produces evidence a reproduction claim can actually
    be grounded against, with no manual wiring."""
    from osprey.services.evidence_grounding import ground_claim

    stdout = json.dumps({
        "canary": "osprey-canary-9f3a", "url": "https://x.test/search?q=osprey-canary-9f3a",
        "status_code": 200, "found": True, "occurrences": 1,
        "context": "<script>var q = 'osprey-canary-9f3a';</script>",
    })
    obs = parse_canary_confirm(stdout, engagement_id="e1", run_id="r1", target="x.test")[0]
    claim = "Reflected in a script context: <script>var q = 'osprey-canary-9f3a';</script>"
    ok, reason = ground_claim(claim, obs)
    assert ok, reason
