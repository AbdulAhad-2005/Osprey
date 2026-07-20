# Platform kernel smoke test — run from repo root
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$backendSrc = Join-Path $root "backend\src"

$env:PYTHONPATH = $backendSrc

Write-Host "== Import platform kernel ==" -ForegroundColor Cyan
python -c @"
from pentest_platform.platform import (
    RunAssistState,
    build_phase_handoff,
    build_situational_brief,
    enrich_tool_result,
    export_structured_findings,
)
from pentest_platform.platform.adaptation import AdaptationContext
from pentest_platform.services.parsers.registry import ensure_parsers_loaded, parse_tool_output, digest_tool_output
from pentest_platform.schemas.tools import ToolExecutionResponse

ensure_parsers_loaded()

# Situational context
brief = build_situational_brief(target='scanme.nmap.org', resolved_ip='45.33.32.156')
assert 'CURRENT SITUATION' in brief
assert 'SENSIBLE NEXT MOVES' in brief

# Parser registry
sample = 'Nmap scan report for scanme.nmap.org (45.33.32.156)\n22/tcp open ssh\n80/tcp open http'
findings = parse_tool_output('nmap_syn_scan', sample, target='scanme.nmap.org')
assert len(findings) >= 2, findings
digest = digest_tool_output('nmap_syn_scan', sample)
assert 'open port' in digest.lower(), digest

# Handoff
export = export_structured_findings(target='scanme.nmap.org', run_id='smoke')
assert export.target == 'scanme.nmap.org'

# Adaptation pipeline
state = RunAssistState()
resp = ToolExecutionResponse(
    tool_name='nmap_syn_scan',
    success=False,
    returncode=1,
    stdout='',
    stderr='timed out',
    error='timeout',
    timed_out=True,
    command='nmap -p- 45.33.32.156',
)
ctx = AdaptationContext(
    tool_response=resp,
    assist_state=state,
    signature='{\"tool\":\"nmap_syn_scan\"}',
    engagement_id='',
    run_id='smoke',
    target='45.33.32.156',
    run_phase='network',
    params={'target': '45.33.32.156'},
)
# Failure analysis
from pentest_platform.platform.failure_analysis import FailureContext, analyze_failure, format_failure_analysis

fail_ctx = FailureContext(
    tool_name='dnsenum_scan',
    command='dnsenum scanme.nmap.org',
    stdout='dnsenum VERSION:1.3.1\n',
    stderr='',
    error='',
    returncode=255,
    timed_out=False,
)
diag = analyze_failure(fail_ctx)
assert diag is not None
assert diag.category in ('incomplete_invocation', 'tool_failure'), diag.category
analysis = format_failure_analysis(fail_ctx, diagnosis=diag)
assert 'FAILURE ANALYSIS' in analysis
assert 'retry' in analysis.lower() or 'fix' in analysis.lower()

enriched = enrich_tool_result('FAILED', ctx)
assert 'FAILURE ANALYSIS' in enriched or 'HINT' in enriched, enriched[:500]
assert 'CURRENT SITUATION' in enriched

print('OK: platform kernel smoke passed')
"@

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Smoke complete." -ForegroundColor Green
