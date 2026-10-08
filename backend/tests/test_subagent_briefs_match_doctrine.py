"""Guard against the A2 drift: the LLM-facing phase briefs must follow the same
doctrine the top-level operator does (AGENTS.md operator card point #4 — drive
the typed tools directly; ``platform_investigation_step``/``_execute`` is the
no-LLM deterministic baseline, never how an LLM-driven worker should operate).

Before this test, ``_SUBAGENT_BRIEFS["recon"]`` told a spawned worker to "Drive
platform_investigation_step -> platform_investigation_execute one bounded
decision at a time" — the exact opposite of AGENTS.md. Nothing kept the two in
sync, so they drifted. This asserts they can't drift back silently.
"""

from __future__ import annotations

import pytest

from osprey.services import phase_supervisor


@pytest.mark.parametrize("phase", ["recon", "vuln", "exploit"])
def test_brief_never_recommends_the_no_llm_baseline(phase):
    brief = phase_supervisor.subagent_brief(phase).lower()
    assert brief, f"no brief defined for phase {phase!r}"
    # The brief may mention the baseline to tell the worker NOT to use it, but it
    # must never recommend *driving* through it.
    assert "drive platform_investigation_step" not in brief
    assert "-> platform_investigation_execute" not in brief
    assert "execute one bounded decision" not in brief


@pytest.mark.parametrize("phase", ["recon", "vuln"])
def test_brief_tells_worker_to_drive_typed_tools(phase):
    brief = phase_supervisor.subagent_brief(phase).lower()
    assert "drive the typed" in brief
    # It should name at least one concrete typed tool, proving it points at the
    # real tool surface rather than the opaque capability picker.
    assert "_scan" in brief or "_probe" in brief or "_crawl" in brief
