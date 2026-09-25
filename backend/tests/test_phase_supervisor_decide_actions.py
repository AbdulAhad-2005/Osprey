"""``decide_actions`` — the phase supervisor's pure spawn decision, now driven
by precomputed priority-unlock results (plans/harness/06-prioritization-
engine.md Step 4) instead of a finding-count signals dict."""

from __future__ import annotations

from osprey.services.phase_supervisor import decide_actions


def test_spawns_unlocked_phase_with_no_active_or_prior_agent():
    actions = decide_actions(
        phase_unlock={"vuln": (True, "port priority 1.8 >= threshold 1.4"), "exploit": (False, "")},
        active_by_phase={}, spawned_by_phase={}, max_agents_per_phase=3,
    )
    assert [a.phase for a in actions] == ["vuln"]
    assert "priority" in actions[0].reason


def test_does_not_spawn_locked_phase():
    actions = decide_actions(
        phase_unlock={"vuln": (False, "best vuln priority 0.10 < threshold 1.40"), "exploit": (False, "")},
        active_by_phase={}, spawned_by_phase={}, max_agents_per_phase=3,
    )
    assert actions == []


def test_does_not_respawn_a_phase_already_active():
    actions = decide_actions(
        phase_unlock={"vuln": (True, "hot"), "exploit": (False, "")},
        active_by_phase={"vuln": 1}, spawned_by_phase={}, max_agents_per_phase=3,
    )
    assert actions == []


def test_respects_per_phase_spawn_budget():
    actions = decide_actions(
        phase_unlock={"vuln": (True, "hot"), "exploit": (False, "")},
        active_by_phase={}, spawned_by_phase={"vuln": 3}, max_agents_per_phase=3,
    )
    assert actions == []


def test_both_downstream_phases_can_unlock_concurrently():
    actions = decide_actions(
        phase_unlock={"vuln": (True, "vuln hot"), "exploit": (True, "exploit hot")},
        active_by_phase={}, spawned_by_phase={}, max_agents_per_phase=3,
    )
    assert {a.phase for a in actions} == {"vuln", "exploit"}
