"""Skills registry, implicit target binding, and scoped-agent roles."""

from __future__ import annotations

from osprey.services import knowledge_browser as kb
from osprey.services import skills_loader as sl


def test_every_skill_has_frontmatter_description():
    skills = kb.list_skills()
    assert len(skills) >= 60
    for s in skills:
        assert s["description"], f"{s['path']} missing description"
        assert s["name"], f"{s['path']} missing name"
        assert s["phase"], f"{s['path']} missing phase"


def test_parse_frontmatter_roundtrip():
    meta, body = kb.parse_frontmatter(
        '---\nname: x\ndescription: "hi: there"\nphase: recon\ntags: [a, b]\n---\n\n# Body\ntext'
    )
    assert meta["name"] == "x"
    assert meta["description"] == "hi: there"
    assert meta["phase"] == "recon"
    assert body.startswith("# Body")


def test_get_skill_by_name_and_path():
    by_path = kb.get_skill("recon/subdomain-enumeration.md")
    by_name = kb.get_skill("subdomain-enumeration")
    assert by_path and by_name
    assert by_path["path"] == by_name["path"]


def test_phase_index_is_anchored():
    idx = kb.skills_index_text(phase="vuln", limit=50)
    assert "nuclei-scanning" in idx
    # a recon-only skill should not appear in the vuln-anchored index
    assert "subdomain-enumeration" not in idx


def test_full_text_load_strips_frontmatter():
    text = sl.load_skills_for_phase("recon")
    assert not text.lstrip().startswith("---")
    assert "name:" not in text.splitlines()[0]


def test_active_phase_digest_has_index():
    digest = sl.active_phase_skill_digest("recon")
    assert "MORE SKILLS FOR THIS PHASE" in digest


def test_implicit_binding_ip_creates_engagement():
    from osprey.services.target_binding import resolve_engagement_for_target

    result = resolve_engagement_for_target("192.0.2.44")
    assert result.engagement is not None
    assert result.engagement.target == "192.0.2.44"


def test_implicit_binding_ambiguous_asks_clarification():
    from osprey.services.target_binding import resolve_engagement_for_target

    result = resolve_engagement_for_target("zong")
    assert result.engagement is None
    assert result.clarification


def test_phase_agents_only_expose_explicit_scoped_roles():
    from osprey.schemas.jobs import AGENT_ROLES
    from osprey.services.phase_agent import _AGENT_PHASES

    assert _AGENT_PHASES == frozenset(AGENT_ROLES)
    assert "commander" not in _AGENT_PHASES
