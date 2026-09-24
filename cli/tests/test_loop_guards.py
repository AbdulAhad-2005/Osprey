"""Unit tests for the CLI loop's cross-call failure/repeat guards.

Covers the pure helpers behind the doom-loop guard and repeated-failure
escalation. Importing cli.agent.loop must not require a running backend
(tools.load_server is lazy), which this suite also implicitly checks.
"""

from __future__ import annotations

from cli.agent import loop as L


def test_call_signature_is_order_independent():
    a = L._call_signature("nmap_syn_scan", {"target": "x", "flags": "-p1"})
    b = L._call_signature("nmap_syn_scan", {"flags": "-p1", "target": "x"})
    assert a == b
    assert a != L._call_signature("nmap_syn_scan", {"target": "y", "flags": "-p1"})


def test_call_signature_handles_unserializable_args():
    # Must not raise even if an arg isn't JSON-serializable.
    sig = L._call_signature("t", {"x": object()})
    assert sig.startswith("t:")


def test_tool_result_failed_detects_error_and_success_false():
    assert L.tool_result_failed("ERROR executing nmap: boom")
    assert L.tool_result_failed("tool: nmap\nsuccess: False\n...")
    # A guard-block string is not itself an exec failure (the tool never ran).
    assert L.tool_result_failed("BLOCKED (no-progress guard): ...") is False
    assert not L.tool_result_failed("success: True\nfound 3 hosts")
    # A benign 'connection refused' inside a successful run is NOT a failure.
    assert not L.tool_result_failed("success: True\nport 80 connection refused")


def _simulate_stall(results: list[str]) -> list[bool]:
    """Reproduce _run_one's outcome-based guard: returns, per call, whether it
    would be BLOCKED (not executed) because the same call has stalled."""
    outcomes: dict[str, tuple[str, int]] = {}
    sig = "job_poll:{'id':1}"
    blocked: list[bool] = []
    for res in results:
        seen = outcomes.get(sig)
        if seen and seen[1] >= L._STALL_THRESHOLD:
            blocked.append(True)
            continue
        blocked.append(False)
        fp = L._result_fingerprint(res)
        if seen and seen[0] == fp:
            outcomes[sig] = (fp, seen[1] + 1)
        else:
            outcomes[sig] = (fp, 1)
    return blocked


def test_stall_guard_blocks_only_non_progressing_repeats():
    # Same result every time → blocked once the stall threshold is reached.
    same = ["identical output"] * 6
    assert _simulate_stall(same) == [False, False, False, True, True, True]


def test_stall_guard_never_blocks_a_progressing_poll():
    # A poll whose result changes each time (status advancing) is NEVER blocked,
    # even called many times with identical arguments — the real fix.
    progressing = [f"status: running {pct}%" for pct in (10, 25, 40, 60, 80, 100)]
    assert _simulate_stall(progressing) == [False] * 6


def test_notices_are_actionable_text():
    dl = L._stall_notice("nuclei_scan", 3)
    assert "BLOCKED (no-progress guard)" in dl and "nuclei_scan" in dl
    rf = L._repeated_failure_notice("sqlmap_scan", 3)
    assert "loop guard" in rf and "sqlmap_scan" in rf and "alternative" in rf
