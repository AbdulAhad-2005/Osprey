"""Vulnerability-analysis phase: parsers, severity/grade discipline, registration,
catalog, dispatch handoff. Pure unit tests — no DB or network.
"""

from __future__ import annotations

from pentest_platform.schemas.finding import (
    ClaimSeverity,
    EvidenceGrade,
    Finding,
    FindingType,
)
from pentest_platform.services.parsers.registry import _OUTPUT_PARSERS, ensure_parsers_loaded
from pentest_platform.services.parsers.vuln import (
    parse_dalfox,
    parse_jaeles,
    parse_nikto,
    parse_nuclei,
    parse_sqlmap,
    parse_wpscan,
)
from pentest_platform.services.task_registry import get_task, list_tasks
from pentest_platform.services.tech_dispatch import _matches
from pentest_platform.services.tool_discovery import get_tools_for_llm_phase


# --------------------------------------------------------------------------- #
# parsers
# --------------------------------------------------------------------------- #

def test_nuclei_parses_cve_and_severity():
    line = ('{"template-id":"CVE-2021-44228","info":{"name":"Log4j RCE","severity":"critical",'
            '"tags":["cve","rce"],"classification":{"cve-id":["CVE-2021-44228"],"cwe-id":["CWE-502"]}},'
            '"matched-at":"https://x.com/api"}')
    fs = parse_nuclei(line, target="x.com")
    assert len(fs) == 1
    f = fs[0]
    assert f.finding_type == FindingType.VULNERABILITY
    assert f.claim_severity == ClaimSeverity.CRITICAL
    assert f.evidence_grade == EvidenceGrade.OBSERVED  # allows critical
    assert f.metadata["cve"] == "CVE-2021-44228"
    assert f.metadata["cwe"] == "CWE-502"
    assert f.phase == "vuln"


def test_nuclei_info_template_capped_low():
    line = '{"template-id":"tech","info":{"name":"nginx","severity":"info"},"matched-at":"https://x"}'
    f = parse_nuclei(line, target="x")[0]
    assert f.claim_severity == ClaimSeverity.INFO


def test_sqlmap_confirmed_injection_is_critical():
    out = ("sqlmap identified the following injection point\nParameter: id (GET)\n"
           "    Type: boolean-based blind\nback-end DBMS: MySQL")
    fs = parse_sqlmap(out, target="http://x/p?id=1")
    assert fs and fs[0].claim_severity == ClaimSeverity.CRITICAL
    assert fs[0].metadata["parameter"] == "id"
    assert fs[0].metadata["dbms"].startswith("MySQL")


def test_sqlmap_not_injectable_is_recorded_negative():
    out = "all tested parameters do not appear to be injectable"
    fs = parse_sqlmap(out, target="http://x/p?id=1")
    assert len(fs) == 1
    assert fs[0].finding_type == FindingType.OBSERVATION
    assert "no_sqli" in fs[0].tags


def test_dalfox_verified_vs_reflected_grade():
    js = ('[{"type":"V","param":"q","data":"http://x?q=<script>","severity":"High"},'
          '{"type":"R","param":"s","data":"http://x?s=1","severity":"Low"}]')
    fs = parse_dalfox(js, target="http://x")
    verified = [f for f in fs if "verified" in f.tags][0]
    reflected = [f for f in fs if "reflected" in f.tags][0]
    assert verified.evidence_grade == EvidenceGrade.OBSERVED
    assert verified.claim_severity == ClaimSeverity.HIGH
    # reflected lead is INFERRED → severity clamped to at most MEDIUM
    assert reflected.evidence_grade == EvidenceGrade.INFERRED
    assert reflected.claim_severity.value in ("low", "info")


def test_wpscan_core_and_plugin_vulns():
    js = ('{"target_url":"http://wp","version":{"vulnerabilities":[{"title":"Core XSS",'
          '"references":{"cve":["2019-1"]}}]},"plugins":{"cf7":{"vulnerabilities":['
          '{"title":"RCE","references":{"cve":["2020-2"]}}]}}}')
    fs = parse_wpscan(js, target="http://wp")
    titles = " ".join(f.title for f in fs)
    assert "core" in titles and "plugin:cf7" in titles
    assert all(f.finding_type == FindingType.VULNERABILITY for f in fs)


def test_nikto_and_jaeles_parse():
    nikto = "+ OSVDB-3092: /backup/: Backup directory found\n+ Target IP: 1.2.3.4\n"
    fn = parse_nikto(nikto, target="http://x")
    assert len(fn) == 1 and fn[0].metadata.get("osvdb") == "3092"

    jaeles = "[High][sqli/error] https://x/item?id=1\n"
    fj = parse_jaeles(jaeles, target="x")
    assert fj[0].claim_severity == ClaimSeverity.HIGH
    assert fj[0].metadata["signature"] == "sqli/error"


def test_severity_clamped_by_grade_on_inferred():
    """A vuln finding downgraded to INFERRED cannot claim CRITICAL."""
    f = Finding(
        finding_type=FindingType.VULNERABILITY,
        title="version-only CVE guess",
        evidence_grade=EvidenceGrade.INFERRED,
        claim_severity=ClaimSeverity.CRITICAL,
        source_tool="nuclei_scan",
    )
    assert f.claim_severity == ClaimSeverity.MEDIUM  # clamped


# --------------------------------------------------------------------------- #
# registration / catalog / phase wiring
# --------------------------------------------------------------------------- #

def test_all_vuln_parsers_registered():
    ensure_parsers_loaded()
    for tool in ("nuclei_scan", "nikto_scan", "wpscan_analyze", "sqlmap_scan",
                 "dalfox_xss_scan", "jaeles_vulnerability_scan"):
        assert tool in _OUTPUT_PARSERS


def test_vuln_catalog_tasks_present():
    ids = {t.id for t in list_tasks(phase="vuln")}
    assert {"vulnerability_scan", "cms_vulnerability_scan", "sql_injection_test", "xss_test"} <= ids
    assert get_task("vulnerability_scan").default_tool == "nuclei_scan"


def test_vuln_phase_exposes_scanner_tools():
    names = {t["function"]["name"] for t in get_tools_for_llm_phase("vuln")}
    assert {"nuclei_scan", "nikto_scan", "wpscan_analyze", "sqlmap_scan", "dalfox_xss_scan"} <= names


# --------------------------------------------------------------------------- #
# recon → vuln dispatch handoff
# --------------------------------------------------------------------------- #

def test_dispatch_wordpress_and_injection_handoff():
    tech = Finding(finding_type=FindingType.TECHNOLOGY, title="WordPress",
                   metadata={"technology": "WordPress"}, source_tool="whatweb_scan")
    param = Finding(finding_type=FindingType.OBSERVATION, title="param id",
                    tags=["injection_point_candidate"], source_tool="arjun_scan")
    assert _matches({"metadata_key": "technology", "metadata_contains": "wordpress"},
                    [tech], graph=None, engagement_id="e") is True
    assert _matches({"has_tag": "injection_point_candidate", "min_count": 1},
                    [param], graph=None, engagement_id="e") is True
    assert _matches({"has_tag": "injection_point_candidate", "min_count": 1},
                    [tech], graph=None, engagement_id="e") is False
