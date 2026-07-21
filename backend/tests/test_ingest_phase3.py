"""Phase 3: richer ingest + hypothesis correlation + stdout index."""

from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.schemas.finding import (
    EvidenceGrade,
    Finding,
    FindingType,
)
from pentest_platform.services.engagement_graph import get_engagement_graph
from pentest_platform.services.finding_correlator import (
    correlate_engagement,
    reload_correlation_rules,
)
from pentest_platform.services.findings_store import get_findings_store
from pentest_platform.services.ingest_promoter import apply_ingest_rules, reload_ingest_rules
from pentest_platform.services.operator_memory import is_hypothesis_relation
from pentest_platform.services.stdout_index import clear_stdout_index, list_stdout_index, record_stdout_entry


def test_ingest_expands_http_auth_tls_and_spa_demotion() -> None:
    reload_ingest_rules()
    with TestClient(app) as client:
        eng = client.post(
            "/api/v1/engagements/",
            json={"target": "ingest-p3.test", "name": "p3-ingest"},
        ).json()
    eid = eng["id"]

    stdout = """
HTTP/1.1 200 OK
Server: nginx/1.24.0
WWW-Authenticate: Basic realm="mgmt"
Set-Cookie: SID=abc; Domain=.ingest-p3.test; Path=/
Location: https://login.ingest-p3.test/callback
Content-Type: text/html
DNS:*.ingest-p3.test
CN = portal.ingest-p3.test

https://portal.ingest-p3.test/api/users [200] [Portal Login]

<!DOCTYPE html>
<div id="root"></div>
__NEXT_DATA__={}
"""
    findings = apply_ingest_rules(
        stdout,
        engagement_id=eid,
        source_tool="httpx_probe",
        target="https://portal.ingest-p3.test/api/users",
        persist=True,
    )
    ids = {str(f.metadata.get("ingest_rule") or "") for f in findings}
    titles = " ".join(f.title for f in findings).lower()
    tags = {t for f in findings for t in (f.tags or [])}

    assert "www_authenticate" in ids or "auth challenge" in titles
    assert "set_cookie_domain" in ids or "set-cookie" in titles
    assert "spa_catchall_suspect" in tags
    # SPA on API path must not stay HIGH/CRITICAL observed API claim
    for f in findings:
        if "api_json" in (f.tags or []) or "json api" in (f.title or "").lower():
            assert f.evidence_grade != EvidenceGrade.OBSERVED or f.claim_severity.value in (
                "info",
                "none",
                "low",
                "medium",
            )
    assert any("spa" in (f.title or "").lower() or "spa_catchall_suspect" in (f.tags or []) for f in findings)


def test_correlator_shares_auth_is_hypothesis() -> None:
    reload_correlation_rules()
    with TestClient(app) as client:
        eng = client.post(
            "/api/v1/engagements/",
            json={"target": "corr-p3.test", "name": "p3-corr"},
        ).json()
    eid = eng["id"]
    store = get_findings_store()
    for host in ("erp.corr-p3.test", "ess.corr-p3.test"):
        store.add(
            Finding(
                engagement_id=eid,
                finding_type=FindingType.OBSERVATION,
                title=f"Set-Cookie: SID=x; Domain=.corr-p3.test; Path=/",
                evidence=f"Set-Cookie: SID=x; Domain=.corr-p3.test; Path=/ host={host}",
                target=host,
                source_tool="httpx_probe",
                tags=["auto_ingest", "cookie", "auth_surface"],
            )
        )
    result = correlate_engagement(eid)
    assert result["count"] >= 1
    assert result["links"], "expected shares_auth hypothesis link"
    rel = result["links"][0].get("relationship") or ""
    assert is_hypothesis_relation(rel)
    assert "shares_auth" in rel


def test_correlator_same_ip_titles() -> None:
    reload_correlation_rules()
    with TestClient(app) as client:
        eng = client.post(
            "/api/v1/engagements/",
            json={"target": "sameip-p3.test", "name": "p3-sameip"},
        ).json()
    eid = eng["id"]
    store = get_findings_store()
    graph = get_engagement_graph()

    for host in ("a.sameip-p3.test", "b.sameip-p3.test"):
        f_host = Finding(
            engagement_id=eid,
            finding_type=FindingType.SUBDOMAIN,
            title=host,
            evidence=f"{host} A 10.9.8.7",
            source_tool="dnsx_resolve",
            target=host,
            metadata={"ip": "10.9.8.7"},
        )
        store.add(f_host)
        graph.ingest_finding(f_host)
        store.add(
            Finding(
                engagement_id=eid,
                finding_type=FindingType.OBSERVATION,
                title="HTTP 200 title: Acme Portal Login",
                target=f"https://{host}/",
                source_tool="httpx_probe",
                tags=["auto_ingest", "http_title"],
            )
        )

    result = correlate_engagement(eid)
    assert result["links"], "expected likely_same_app hypothesis for co-hosted similar titles"
    rel = result["links"][0].get("relationship") or ""
    assert is_hypothesis_relation(rel)
    assert "likely_same_app" in rel


def test_stdout_index_api() -> None:
    clear_stdout_index()
    with TestClient(app) as client:
        eng = client.post(
            "/api/v1/engagements/",
            json={"target": "idx-p3.test", "name": "p3-idx"},
        ).json()
        eid = eng["id"]
        record_stdout_entry(
            engagement_id=eid,
            tool_name="httpx_probe",
            target="idx-p3.test",
            stdout_path=f"/tmp/pentest/{eid}/httpx.stdout.txt",
            snippet="https://idx-p3.test [200] [Hello]",
        )
        data = client.get(
            "/api/v1/hybrid/stdout-index",
            params={"engagement_id": eid},
        ).json()
        assert data["count"] >= 1
        assert "httpx" in (data.get("text") or "").lower()
        packet = list_stdout_index(eid, limit=3)
        assert packet["entries"][0]["snippet"]
