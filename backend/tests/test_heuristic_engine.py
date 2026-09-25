"""Tests for the no-LLM heuristic dispatch engine's pure decision logic.

The selector is a pure function (no DB, no live tools), so the rule-decision
behaviour — priority order, exploit-category blocking, fixpoint, and the
additional_args-aware de-dup key — is testable in isolation.
"""

from __future__ import annotations

from osprey.schemas.hybrid import DispatchSuggestion
from osprey.services import heuristic_engine as he


def _d(tool: str, priority: int = 0, additional_args: str = "") -> DispatchSuggestion:
    return DispatchSuggestion(
        signal="s", task_id="t", default_tool=tool, priority=priority, additional_args=additional_args
    )


_CATS = {
    "nuclei_scan": "vuln",
    "wpscan_analyze": "vuln",
    "httpx_probe": "recon",
    "metasploit_run": "exploit",
    "hydra_attack": "creds",
}


def _cat(tool: str) -> str:
    return _CATS.get(tool, "")


def test_selector_blocks_exploit_and_creds_categories():
    # Highest priority is an exploit tool, but it must never be chosen.
    sugg = [_d("metasploit_run", 9), _d("hydra_attack", 8), _d("wpscan_analyze", 7)]
    pick = he.select_next_dispatch(sugg, executed_keys=set(), category_of=_cat)
    assert pick is not None and pick.default_tool == "wpscan_analyze"


def test_selector_respects_priority_then_advances():
    sugg = [_d("nuclei_scan", 5), _d("wpscan_analyze", 7)]
    first = he.select_next_dispatch(sugg, executed_keys=set(), category_of=_cat)
    assert first.default_tool == "wpscan_analyze"
    second = he.select_next_dispatch(
        sugg, executed_keys={he.dispatch_key(first)}, category_of=_cat
    )
    assert second.default_tool == "nuclei_scan"


def test_selector_reaches_fixpoint():
    sugg = [_d("nuclei_scan", 5), _d("metasploit_run", 9)]
    executed = {he.dispatch_key(_d("nuclei_scan", 5))}
    # Only the (blocked) exploit tool remains → fixpoint.
    assert he.select_next_dispatch(sugg, executed_keys=executed, category_of=_cat) is None


def test_dispatch_key_distinguishes_additional_args():
    a = he.dispatch_key(_d("httpx_probe"))
    b = he.dispatch_key(_d("httpx_probe", additional_args="-path /.env"))
    assert a != b


def test_unknown_category_is_never_blocked():
    # A tool we can't classify must still be runnable (blocklist excludes only
    # positively-classified exploit/creds/postex tools).
    pick = he.select_next_dispatch([_d("some_new_tool", 3)], executed_keys=set(), category_of=_cat)
    assert pick is not None and pick.default_tool == "some_new_tool"


def test_non_autonomous_categories_are_the_downstream_ones():
    assert he.NON_AUTONOMOUS_CATEGORIES == frozenset({"exploit", "creds", "postex"})
