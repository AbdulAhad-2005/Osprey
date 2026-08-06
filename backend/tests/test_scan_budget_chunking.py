"""Component 2 — pre-flight port-range chunking (scan_budget.chunk_port_range).

Reuses scan_budget's existing cost estimator/cap by construction — these tests
exist to prove that reuse holds and that no chunk can ever itself trip the
same budget it was split to avoid.
"""

from __future__ import annotations

from pentest_platform.services.scan_budget import (
    _MAX_PORTS_WITHOUT_CONFIRM,
    chunk_port_range,
    detect_expensive_port_scope,
    enforce_scan_budget,
)


def test_narrow_range_is_not_chunked():
    # Well within budget — nothing to do, caller proceeds normally.
    assert chunk_port_range(tool_name="nmap_service_scan", params={"ports": "1-1000"}) is None


def test_non_chunkable_tool_returns_none():
    # naabu is a fast scanner — not in the chunkable set; it keeps its own
    # existing higher cap and refusal path untouched.
    assert (
        chunk_port_range(tool_name="naabu_port_scan", params={"ports": "1-65535"}) is None
    )


def test_moderately_wide_range_chunks_into_a_few_pieces():
    # 6000 ports > the 2000 cap, but well within what 8 chunks of 1000 can
    # cover (needs 6 chunks) — this is exactly the "routine wide-range"
    # case chunking exists to dissolve without asking a human.
    chunks = chunk_port_range(tool_name="nmap_service_scan", params={"ports": "1-6000"})
    assert chunks is not None
    assert len(chunks) == 6
    assert chunks[0]["ports"] == "1-1000"
    assert chunks[-1]["ports"] == "5001-6000"


def test_every_chunk_independently_passes_its_own_budget_check():
    # The correctness property that matters most: no chunk this function
    # produces may itself trip enforce_scan_budget when it re-enters the
    # execution path as its own request (each chunk goes through
    # execute_tool_request again, independently).
    chunks = chunk_port_range(tool_name="nmap_service_scan", params={"ports": "1-6000"})
    for c in chunks:
        # Must not raise.
        enforce_scan_budget(tool_name="nmap_service_scan", params=c)
        reason = detect_expensive_port_scope(tool_name="nmap_service_scan", params=c)
        assert reason is None


def test_full_range_that_would_need_too_many_chunks_declines_to_chunk():
    # A genuine 1-65535 sweep needs 66 chunks of 1000 — far beyond the
    # _MAX_CHUNKS safety ceiling. This must NOT be auto-chunked; it must fall
    # through to the existing refusal + confirm_expensive path, same as
    # before this feature existed. Auto-chunking only dissolves the routine
    # case, never becomes an unlimited-scope bypass.
    assert chunk_port_range(tool_name="nmap_service_scan", params={"ports": "1-65535"}) is None
    # The existing refusal for that same request is untouched — see
    # test_full_range_still_raises_without_confirm_expensive below.


def test_full_range_still_raises_without_confirm_expensive():
    import pytest

    with pytest.raises(ValueError):
        enforce_scan_budget(tool_name="nmap_service_scan", params={"ports": "1-65535"})


def test_dash_p_full_range_flag_treated_same_as_explicit_range():
    chunks = chunk_port_range(
        tool_name="nmap_custom_scan", params={}, additional_args="-p-"
    )
    # -p- means the full 65535 — same "too many chunks needed" decline.
    assert chunks is None


def test_top_ports_is_never_chunked_even_if_large():
    # --top-ports is nmap's own fast path — never route it through chunking.
    assert (
        chunk_port_range(
            tool_name="nmap_service_scan", params={}, additional_args="--top-ports 3000"
        )
        is None
    )


def test_chunk_strips_conflicting_ports_flags_from_additional_args():
    chunks = chunk_port_range(
        tool_name="nmap_service_scan",
        params={},
        additional_args="-sV -p 1-6000 -T4",
    )
    assert chunks is not None
    for c in chunks:
        override = c["_additional_args_override"]
        assert "-p " not in override
        assert "-sV" in override and "-T4" in override


def test_chunk_span_never_exceeds_the_tool_cap():
    chunks = chunk_port_range(tool_name="nmap_syn_scan", params={"ports": "1-8000"})
    assert chunks is not None
    for c in chunks:
        start, end = (int(x) for x in c["ports"].split("-"))
        assert (end - start + 1) <= _MAX_PORTS_WITHOUT_CONFIRM
