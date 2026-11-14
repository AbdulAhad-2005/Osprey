"""domain_hunter's affiliation gate + confidence (pure logic, no network).

Replaces the old static denylists: a WEAK signal (site link / search snippet)
only becomes a candidate when it shares the seed brand token or corroborates a
strong one; a self-hosted-infra host counts only when it shares the brand token
(so a provider like google.com from a seed's SPF/MX is dropped)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "mcp-servers" / "recon" / "tools"


def _load():
    for p in (ROOT / "mcp-servers", TOOLS):
        if str(p) not in sys.path:
            sys.path.insert(0, str(p))
    spec = importlib.util.spec_from_file_location("_dh_cli_test", TOOLS / "_domain_hunter_cli.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclass needs the module in sys.modules
    spec.loader.exec_module(mod)
    return mod


dh = _load()


def test_shares_brand_token():
    assert dh._shares_brand_token("geoit.tv", ["geo"])          # geo -> geoit
    assert dh._shares_brand_token("teslamotors.com", ["tesla"])
    assert not dh._shares_brand_token("google.com", ["careem"])
    assert not dh._shares_brand_token("amazonses.com", ["careem"])


def test_brand_stopwords_block_generic_words_from_becoming_tokens():
    """Live bug: a title like '... Official Site' derived the brand token
    'site', which then matched sitemaps.org (the XML sitemap protocol's own
    spec domain, present in virtually every auto-generated sitemap.xml) as a
    false-positive sister."""
    tokens = dh._brand_tokens("mojang.com", "Welcome to the Minecraft Official Site | Minecraft")
    assert "site" not in tokens and "sites" not in tokens
    assert not dh._shares_brand_token("sitemaps.org", tokens)


def test_weak_signal_without_brand_or_corroboration_is_dropped():
    h = dh.DomainHunter("careem.com")
    h._add_candidate("apple.com", method="site_scrape", evidence="outbound link")
    assert "apple.com" not in h.candidates  # weak + no brand + no strong → noise


def test_self_infra_drops_providers_keeps_brand_infra():
    h = dh.DomainHunter("geo.tv")
    h._add_candidate("google.com", method="self_infra", evidence="SPF include")  # provider
    h._add_candidate("geoit.tv", method="self_infra", evidence="MX host: mx1.geoit.tv")
    # self_infra is only CALLED for brand-shared hosts, but even if a provider
    # slips to _add_candidate it is weak-equivalent noise: brand gate keeps geoit.
    assert "geoit.tv" in h.candidates
    assert h.candidates["geoit.tv"].brand_match


def test_strong_signal_creates_candidate_without_brand():
    h = dh.DomainHunter("example.com")
    h._add_candidate("other-co.net", method="reverse_whois", evidence="same registrant")
    assert "other-co.net" in h.candidates
    assert dh.candidate_confidence(h.candidates["other-co.net"]) == "high"  # registrant → high


def test_weak_corroborates_existing_candidate():
    h = dh.DomainHunter("example.com")
    h._add_candidate("sister.net", method="reverse_whois", evidence="same registrant")
    h._add_candidate("sister.net", method="site_scrape", evidence="also linked")
    c = h.candidates["sister.net"]
    assert "site_scrape" in c.weak_methods and "reverse_whois" in c.strong_methods


def test_confidence_tiers():
    strong_pair = dh.Candidate(domain="a.com", strong_methods={"self_infra", "tracker_pivot"})
    assert dh.candidate_confidence(strong_pair) == "high"
    one_strong = dh.Candidate(domain="b.com", strong_methods={"tracker_pivot"})
    assert dh.candidate_confidence(one_strong) == "medium"
    one_weak = dh.Candidate(domain="c.com", weak_methods={"site_scrape"}, brand_match=True)
    assert dh.candidate_confidence(one_weak) == "low"


def test_wikidata_is_a_strong_method():
    assert "wikidata" in dh._STRONG_METHODS


class _FakeResp:
    def __init__(self, payload, ok=True, status_code=200):
        self._payload = payload
        self.ok = ok
        self.status_code = status_code

    def json(self):
        return self._payload


def _fake_session(search_by_query: dict, entities_by_qid: dict):
    """A requests.Session stand-in: wbsearchentities keyed by the 'search'
    param, wbgetentities keyed by the (sorted) 'ids' param."""
    class _S:
        def get(self, url, params=None, timeout=None):
            params = params or {}
            if params.get("action") == "wbsearchentities":
                hits = search_by_query.get(params["search"], [])
                return _FakeResp({"search": hits})
            if params.get("action") == "wbgetentities":
                ids = params["ids"].split("|")
                return _FakeResp({"entities": {i: entities_by_qid[i] for i in ids if i in entities_by_qid}})
            return _FakeResp({}, ok=False, status_code=404)
    return _S()


def _entity(label, p856=None, p355=None, p749=None, p127=None, instance_of=None, description=""):
    def claims_for(prop, values):
        return [{"mainsnak": {"datavalue": {"value": v}}} for v in values] if values else []

    return {
        "labels": {"en": {"value": label}},
        "descriptions": {"en": {"value": description}},
        "claims": {
            "P856": claims_for("P856", p856),
            "P355": claims_for("P355", [{"id": q} for q in p355] if p355 else None),
            "P749": claims_for("P749", [{"id": q} for q in p749] if p749 else None),
            "P127": claims_for("P127", [{"id": q} for q in p127] if p127 else None),
            "P31": claims_for("P31", [{"id": q} for q in instance_of] if instance_of else None),
        },
    }


def test_wikidata_chase_finds_subsidiary_site():
    s = _fake_session(
        search_by_query={"seed.com": [{"id": "Q1"}]},
        entities_by_qid={
            "Q1": _entity("Seed Co", p856=["https://seed.com"], p355=["Q2"]),
            "Q2": _entity("Sister Co", p856=["https://sister-brand.com"]),
        },
    )
    out = dh._wikidata_affiliated_sites(s, "seed.com", "seed")
    assert out == {"sister-brand.com": "Wikidata: Sister Co, a subsidiary/parent of the seed org"}


def test_wikidata_excludes_institutional_shareholder_p127_target():
    """P127 (owned by) is followed (fixed from an earlier blanket exclusion —
    see test_wikidata_includes_real_p127_owner below), but a target that is
    itself a financial-services/investment entity is excluded — confirmed
    live on Tesla: P127 included Capital Group Companies, Wikidata's own
    gloss for it is literally 'financial services company'."""
    s = _fake_session(
        search_by_query={"seed.com": [{"id": "Q1"}]},
        entities_by_qid={
            "Q1": _entity("Seed Co", p856=["https://seed.com"], p127=["Q9"]),
            "Q9": _entity("Some Fund", p856=["https://fund.example"], description="financial services company"),
        },
    )
    out = dh._wikidata_affiliated_sites(s, "seed.com", "seed")
    assert out == {}


def test_wikidata_excludes_human_p127_target():
    """A P127 target that is a person (instance_of human, Q5) is excluded
    even with no financial-sounding description — confirmed live on Tesla:
    P127 included a major individual shareholder whose own P856 happened to
    point to an unrelated company he separately chairs."""
    s = _fake_session(
        search_by_query={"seed.com": [{"id": "Q1"}]},
        entities_by_qid={
            "Q1": _entity("Seed Co", p856=["https://seed.com"], p127=["Q9"]),
            "Q9": _entity("Some Person", p856=["https://unrelated-employer.example"], instance_of=["Q5"]),
        },
    )
    out = dh._wikidata_affiliated_sites(s, "seed.com", "seed")
    assert out == {}


def test_wikidata_includes_real_p127_owner():
    """A genuine P127 (owned by) relationship — neither a financial
    institution nor a person — is trusted. Confirmed live: IKEA's only
    P355/P749 claims are empty, but P127 is Stichting INGKA Foundation
    (ingkafoundation.org), its real controlling entity; excluding P127
    entirely (the prior behavior) missed this real affiliate completely."""
    s = _fake_session(
        search_by_query={"seed.com": [{"id": "Q1"}]},
        entities_by_qid={
            "Q1": _entity("Seed Co", p856=["https://seed.com"], p127=["Q9"]),
            "Q9": _entity("Controlling Foundation", p856=["https://foundation.example"]),
        },
    )
    out = dh._wikidata_affiliated_sites(s, "seed.com", "seed")
    assert out == {"foundation.example": "Wikidata: Controlling Foundation, a subsidiary/parent of the seed org"}


def test_wikidata_rejects_unverified_entity():
    """A search hit whose own P856 does NOT match the seed is never trusted —
    this is what keeps an ambiguous short brand token (e.g. a one-word
    consumer brand matching an unrelated namesake entity) from contaminating
    results, even though it costs recall on names Wikidata's own search
    ranks ambiguously."""
    s = _fake_session(
        search_by_query={"seed.com": [{"id": "Q1"}]},
        entities_by_qid={"Q1": _entity("Unrelated Namesake", p856=["https://unrelated.example"], p355=["Q2"])},
    )
    out = dh._wikidata_affiliated_sites(s, "seed.com", "seed")
    assert out == {}


def test_wikidata_falls_back_through_query_tiers_to_find_verified_hit():
    """seed_root search finds the WRONG entity (no matching P856); the next
    tier (brand) finds the right one further down its own rank list — both
    must be checked, not just each tier's #1 hit."""
    s = _fake_session(
        search_by_query={
            "seed.com": [{"id": "Qwrong"}],
            "seed": [{"id": "Qwrong2"}, {"id": "Q1"}],
        },
        entities_by_qid={
            "Qwrong": _entity("Unrelated", p856=["https://unrelated.example"]),
            "Qwrong2": _entity("Also Unrelated", p856=["https://also-unrelated.example"]),
            "Q1": _entity("Seed Co", p856=["https://seed.com"], p749=["Q2"]),
            "Q2": _entity("Parent Co", p856=["https://parent-brand.com"]),
        },
    )
    out = dh._wikidata_affiliated_sites(s, "seed.com", "seed")
    assert out == {"parent-brand.com": "Wikidata: Parent Co, a subsidiary/parent of the seed org"}


def test_progress_snapshots_respect_the_confidence_floor():
    """A kill mid-run must not leave a below-floor candidate as the last
    recorded # DHJSON line — the backend parser reads only the LAST one in
    stdout (see _domain_hunter_rows), and nothing downstream re-applies
    --confidence-min to an already-printed line."""
    import io
    import contextlib
    import json

    h = dh.DomainHunter("example.com", confidence_min="medium")
    h._add_candidate("weak.net", method="site_scrape", evidence="outbound link")  # low, single weak method
    h._add_candidate("strong.net", method="reverse_whois", evidence="same registrant")  # high

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        h._emit_progress("test_stage")
    lines = [ln for ln in buf.getvalue().splitlines() if ln.startswith(dh._DHJSON_PREFIX)]
    rows = json.loads(lines[-1][len(dh._DHJSON_PREFIX):])
    domains = {r["domain"] for r in rows}
    assert "strong.net" in domains
    assert "weak.net" not in domains


def test_live_probe_sweep_emits_intermediate_progress(monkeypatch):
    """The live-probe stage is itself budgeted up to 90s — a kill partway
    through must not leave every candidate's `live` flag stuck at its
    pre-probe False default with no snapshot taken since discovery ended.
    Patch the probe itself (not time.monotonic/deadline) so the real 90s
    wall-clock deadline never triggers inside this fast, hermetic test."""
    import io
    import contextlib

    h = dh.DomainHunter("example.com", confidence_min="medium")
    for i in range(12):
        h._add_candidate(f"sister{i}.net", method="reverse_whois", evidence="same registrant")

    monkeypatch.setattr(dh, "_live_probe", lambda session, domain: (True, None))

    emitted: list[str] = []
    original_emit = dh.DomainHunter._emit_progress

    def _spy(self, stage):
        emitted.append(stage)
        original_emit(self, stage)

    monkeypatch.setattr(dh.DomainHunter, "_emit_progress", _spy)

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        h._resolve_live_status()

    assert emitted.count("live_probe") >= 2  # periodic, not just once at the very end
    assert all(c.live for c in h.candidates.values())


def test_wikidata_strips_www_before_matching_seed():
    """A real bug: an entity's P856 is frequently 'https://www.seed.com' —
    comparing the raw hostname (not its registrable apex) to the bare seed
    root always misses, silently dropping a verified real match."""
    s = _fake_session(
        search_by_query={"seed.com": [{"id": "Q1"}]},
        entities_by_qid={"Q1": _entity("Seed Co", p856=["https://www.seed.com"], p749=["Q2"])},
    )
    out = dh._wikidata_affiliated_sites(s, "seed.com", "seed")
    assert "Q2" not in out  # Q2 has no entity data fetched, but Q1 must verify
    s2 = _fake_session(
        search_by_query={"seed.com": [{"id": "Q1"}]},
        entities_by_qid={
            "Q1": _entity("Seed Co", p856=["https://www.seed.com"], p749=["Q2"]),
            "Q2": _entity("Parent Co", p856=["https://parent-brand.com"]),
        },
    )
    out2 = dh._wikidata_affiliated_sites(s2, "seed.com", "seed")
    assert "parent-brand.com" in out2
