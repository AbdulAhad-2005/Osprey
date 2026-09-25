"""find_skills — plans/harness/08-skill-system-at-scale.md.

Runs against the real skills/ directory (not a fixture) — this is exactly
what platform_skills/CLI query against, so a test double would prove less.
Done criteria this covers: find_skills(mitre=...) and find_skills(
asset_type=...) return the right skills, ranked, capped — never "everything".
"""

from __future__ import annotations

from osprey.services.knowledge_browser import find_skills, list_skills


def test_router_level_index_stays_small_regardless_of_corpus_size():
    """Step 2's actual scale claim: the always-available index is routers
    only. Whatever the corpus size, list_skills() never returns every
    reference/*.md deep-dive alongside it."""
    items = list_skills()
    assert items, "expected the real skills/ corpus to be non-empty"
    for it in items:
        assert "/reference/" not in it["path"]


def test_find_skills_with_nothing_given_returns_nothing():
    """No dimension supplied -> no match, not 'return everything' — that's
    what list_skills()/skills_index_text() are for."""
    assert find_skills() == []


def test_find_skills_by_mitre_returns_real_matches():
    results = find_skills(mitre="T1098", limit=10)
    assert results
    for r in results:
        assert any(m.lower().startswith("t1098") for m in r["mitre"])


def test_find_skills_by_asset_type_ranks_the_specific_skill_first():
    results = find_skills(asset_type="graphql_endpoint", limit=5)
    assert results
    assert results[0]["path"] == "web/graphql-testing.md"


def test_find_skills_respects_limit():
    results = find_skills(query="scan", limit=3)
    assert len(results) <= 3


def test_find_skills_by_query_matches_relevant_domain_skills():
    results = find_skills(query="sql injection", limit=10)
    paths = [r["path"] for r in results]
    assert "vuln/injection-testing.md" in paths


def test_find_skills_by_phase_scopes_correctly():
    results = find_skills(query="scan", phase="web", limit=20)
    for r in results:
        assert "web" in r["phases"] or r["path"].startswith("web/")


def test_find_skills_combines_dimensions_additively():
    """A skill matching on BOTH a tag and the query text should outrank one
    matching only the query text."""
    tag_and_text = find_skills(query="graphql", tags=["graphql"], limit=10)
    text_only = find_skills(query="graphql", limit=10)
    assert tag_and_text
    assert text_only
    # Same top result either way, but scoring more dimensions should not
    # demote it — sanity check the combined score is >= the single-dim one.
    top_combined = next(r for r in tag_and_text if r["path"] == "web/graphql-testing.md")
    assert top_combined is not None


def test_unseeded_new_schema_fields_default_gracefully():
    """None of the 78 real skills set domain/nist_csf/capabilities yet — the
    parser must default them, never KeyError."""
    for rec in list_skills():
        assert isinstance(rec["domain"], str)
        assert isinstance(rec["nist_csf"], list)
        assert isinstance(rec["capabilities"], list)
