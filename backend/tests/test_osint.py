"""Passive-OSINT: catalog, entity graph, parsers, and evidence grading."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.schemas.engagement_graph import AssetType
from pentest_platform.schemas.finding import (
    EvidenceGrade,
    Finding,
    FindingType,
)
from pentest_platform.schemas.tools import ToolCategory
from pentest_platform.services.engagement_graph import get_engagement_graph
from pentest_platform.services.findings_store import get_findings_store
from pentest_platform.services.parsers.registry import ensure_parsers_loaded, parse_tool_output
from pentest_platform.services.parsers.freeform_probe import parse_freeform_probe_output
from pentest_platform.services import tool_registry as tr


# --- Catalog ---------------------------------------------------------------

def test_osint_category_and_tools_registered() -> None:
    osint = [t for t in tr.ALL_TOOL_DEFINITIONS if t.category == ToolCategory.OSINT]
    names = {t.name for t in osint}
    assert len(osint) == 10
    assert {"web_contact_harvest", "theharvester", "sherlock", "maigret",
            "holehe", "phoneinfoga", "dnstwist", "metagoofil",
            "social_analyzer", "email_permute"} <= names
    # all passive, and each resolves via get_tool_definition
    for t in osint:
        assert t.safety_level.value == "passive"
        assert tr.get_tool_definition(t.name) is not None


def test_osint_aliases_resolve() -> None:
    assert tr.resolve_tool_name("harvester") == "theharvester"
    assert tr.resolve_tool_name("typosquat") == "dnstwist"
    assert tr.resolve_tool_name("contact_harvest") == "web_contact_harvest"


# --- Evidence grading ------------------------------------------------------

def test_osint_default_grades() -> None:
    from pentest_platform.schemas.finding import default_grade_for_type

    assert default_grade_for_type(FindingType.PERSON) == EvidenceGrade.UNVERIFIED
    assert default_grade_for_type(FindingType.SOCIAL_ACCOUNT) == EvidenceGrade.UNVERIFIED
    assert default_grade_for_type(FindingType.EMAIL) == EvidenceGrade.INFERRED
    assert default_grade_for_type(FindingType.PHONE) == EvidenceGrade.INFERRED


# --- Graph entity ingest ---------------------------------------------------

def test_email_builds_domain_and_person_edges() -> None:
    with TestClient(app) as client:
        eid = client.post("/api/v1/engagements/", json={"target": "acme.test"}).json()["id"]
    f = Finding(
        engagement_id=eid,
        finding_type=FindingType.EMAIL,
        title="jane.doe@acme.test",
        source_tool="web_contact_harvest",
        target="acme.test",
        metadata={"person": "Jane Doe"},
    )
    get_findings_store().add(f)
    get_engagement_graph().ingest_finding(f)
    graph = get_engagement_graph()

    emails = graph.list_nodes(engagement_id=eid, asset_type=AssetType.EMAIL)
    assert any(n.label == "jane.doe@acme.test" for n in emails)

    has_email = graph.list_edges(engagement_id=eid, relationship="has_email")
    assert any(e.source_id == "domain:acme.test" for e in has_email)

    owns = graph.list_edges(engagement_id=eid, relationship="owns_email")
    assert any(e.source_id == "person:jane doe" for e in owns)


def test_username_social_and_person_pivot() -> None:
    with TestClient(app) as client:
        eid = client.post("/api/v1/engagements/", json={"target": "pivot.test"}).json()["id"]
    sa = Finding(
        engagement_id=eid,
        finding_type=FindingType.SOCIAL_ACCOUNT,
        title="https://twitter.com/janedoe",
        source_tool="maigret",
        target="janedoe",
        metadata={"username": "janedoe", "network": "twitter"},
    )
    get_findings_store().add(sa)
    get_engagement_graph().ingest_finding(sa)
    graph = get_engagement_graph()

    used_on = graph.list_edges(engagement_id=eid, relationship="used_on")
    assert any(e.source_id == "username:janedoe" for e in used_on)
    sacc = graph.list_nodes(engagement_id=eid, asset_type=AssetType.SOCIAL_ACCOUNT)
    assert sacc


# --- Parsers ---------------------------------------------------------------

def test_web_contact_harvest_parser() -> None:
    ensure_parsers_loaded()
    payload = json.dumps({
        "domain": "acme.test",
        "emails": ["a@acme.test"],
        "phones": ["+14155552671"],
        "names": ["Jane Doe"],
        "social": [{"network": "github", "url": "https://github.com/jd", "username": "jd"}],
    })
    fs = parse_tool_output("web_contact_harvest", payload, engagement_id="e", target="acme.test")
    types = {f.finding_type for f in fs}
    assert FindingType.EMAIL in types
    assert FindingType.PHONE in types
    assert FindingType.PERSON in types
    assert FindingType.SOCIAL_ACCOUNT in types
    assert FindingType.USERNAME in types


def test_email_permute_parser_marks_candidates_unverified() -> None:
    ensure_parsers_loaded()
    payload = json.dumps({
        "name": "Jane Doe",
        "domain": "acme.test",
        "mx": True,
        "candidates": ["jane.doe@acme.test", "jdoe@acme.test"],
    })
    fs = parse_tool_output("email_permute", payload, engagement_id="e", target="acme.test")
    assert fs and all(f.finding_type == FindingType.EMAIL for f in fs)
    assert all(f.evidence_grade == EvidenceGrade.UNVERIFIED for f in fs)
    assert all("candidate" in f.tags for f in fs)
    assert all(f.metadata.get("person") == "Jane Doe" for f in fs)


def test_dnstwist_parser_only_resolving() -> None:
    ensure_parsers_loaded()
    payload = json.dumps([
        {"domain": "acme.test", "fuzzer": "original"},
        {"domain": "acmе.test", "fuzzer": "homoglyph", "dns_a": ["1.2.3.4"]},
        {"domain": "acme-login.test", "fuzzer": "addition"},  # no DNS -> skipped
    ])
    fs = parse_tool_output("dnstwist", payload, engagement_id="e", target="acme.test")
    assert len(fs) == 1
    assert "typosquat" in fs[0].tags


def test_sherlock_parser_emits_username_and_accounts() -> None:
    ensure_parsers_loaded()
    stdout = "[*] Checking username janedoe on:\n[+] GitHub: https://github.com/janedoe\n[+] Twitter: https://twitter.com/janedoe\n"
    fs = parse_tool_output("sherlock", stdout, engagement_id="e", target="janedoe")
    assert any(f.finding_type == FindingType.USERNAME for f in fs)
    accts = [f for f in fs if f.finding_type == FindingType.SOCIAL_ACCOUNT]
    assert len(accts) == 2


# --- Freeform script contract ---------------------------------------------

def test_freeform_marker_accepts_osint_types() -> None:
    stdout = "FINDING|inferred|info|email|jane@acme.test|found on about page"
    fs = parse_freeform_probe_output(stdout, engagement_id="e", run_id="r")
    assert any(f.finding_type == FindingType.EMAIL for f in fs)
