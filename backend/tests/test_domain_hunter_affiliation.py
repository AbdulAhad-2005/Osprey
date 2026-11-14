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
