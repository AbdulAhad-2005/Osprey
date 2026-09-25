"""Regression test for the OBSERVATION noise-filter: the store itself must
keep including OBSERVATION rows by default (internal analytical callers —
report_generator, hypothesis_engine, finding_correlator, etc. — depend on
this, since that's literally what OBSERVATION is for, see
recon_network.py's _unparsed_observation/_flush_script), while an explicit
exclude_noise=True (the human-facing findings endpoint's default) must hide
them everywhere — including from a tag/keyword-filtered lookup, not just an
unfiltered browse. (A prior version of this filter exempted tag/q from the
exclusion specifically to protect asn_enum's netblock findings, which are
themselves OBSERVATION-typed — but that caller, surface_expansion.py's
subnet pivot, calls the store directly and never sets exclude_noise=True at
all, so it's protected by the store's own default, not by a tag/q exemption.
The exemption's only real effect was silently disabling the filter for any
human keyword search, e.g. /findings <domain-name>, since the target domain
matches nearly every row by construction.)
"""

from __future__ import annotations

import uuid

from osprey.schemas.finding import Finding, FindingType
from osprey.services.findings_store import get_findings_store


def _eid() -> str:
    return uuid.uuid4().hex[:12]


def _seed(eid: str) -> None:
    store = get_findings_store()
    store.add(
        Finding(
            engagement_id=eid,
            finding_type=FindingType.OBSERVATION,
            title="some_tool raw output",
            target="example.com",
            tags=["some_tool", "unparsed"],
        )
    )
    store.add(
        Finding(
            engagement_id=eid,
            finding_type=FindingType.OBSERVATION,
            title="Netblock 10.0.0.0/24 (AS12345)",
            target="example.com",
            metadata={"cidr": "10.0.0.0/24", "role": "netblock"},
            tags=["netblock", "asn", "asn_prefix"],
        )
    )
    store.add(
        Finding(
            engagement_id=eid,
            finding_type=FindingType.VULNERABILITY,
            title="Real vulnerability finding",
            target="example.com",
        )
    )


def test_store_default_includes_observation_rows():
    """Internal analytical callers never pass exclude_noise — they must keep
    seeing everything, unfiltered, exactly as before this feature existed."""
    eid = _eid()
    _seed(eid)
    findings = get_findings_store().list(engagement_id=eid, limit=100)
    titles = {f.title for f in findings}
    assert "some_tool raw output" in titles
    assert "Netblock 10.0.0.0/24 (AS12345)" in titles
    assert "Real vulnerability finding" in titles


def test_exclude_noise_hides_observation_on_unfiltered_browse():
    eid = _eid()
    _seed(eid)
    findings = get_findings_store().list(engagement_id=eid, limit=100, exclude_noise=True)
    titles = {f.title for f in findings}
    assert "some_tool raw output" not in titles
    assert "Netblock 10.0.0.0/24 (AS12345)" not in titles
    assert "Real vulnerability finding" in titles


def test_exclude_noise_also_applies_to_tag_filtered_lookup():
    """A human searching by tag still doesn't want noise mixed in — an
    explicit exclude_noise=True means exclude_noise, full stop."""
    eid = _eid()
    _seed(eid)
    findings = get_findings_store().list(
        engagement_id=eid, tag="asn_prefix", limit=100, exclude_noise=True,
    )
    titles = {f.title for f in findings}
    assert "Netblock 10.0.0.0/24 (AS12345)" not in titles


def test_exclude_noise_also_applies_to_keyword_search():
    """The regression this test guards: q="samaa.tv" (a broad substring
    matching nearly every row) must not silently disable the noise filter —
    that's exactly the case a human /findings <domain> search hits."""
    eid = _eid()
    _seed(eid)
    findings = get_findings_store().list(
        engagement_id=eid, q="raw output", limit=100, exclude_noise=True,
    )
    titles = {f.title for f in findings}
    assert "some_tool raw output" not in titles


def test_subnet_pivot_lookup_is_protected_by_the_store_default_not_a_tag_exemption():
    """surface_expansion.py calls store.list(tag="asn_prefix", ...) directly,
    never setting exclude_noise — this must keep returning netblock
    OBSERVATION rows via the store's own False default, independent of
    whatever the human-facing endpoint's exclude_noise default is."""
    eid = _eid()
    _seed(eid)
    findings = get_findings_store().list(engagement_id=eid, tag="asn_prefix", limit=200)
    titles = {f.title for f in findings}
    assert "Netblock 10.0.0.0/24 (AS12345)" in titles
